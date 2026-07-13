//! ChatGPT data-export adapter.
//!
//! Each top-level conversation is normalized independently. Mapping nodes and
//! their parent edges remain explicit so regenerated responses never become a
//! synthetic linear transcript.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::archive_source::{parse_archive_items, stable_id, string_any, timestamp, ArchiveItem};
use super::{
    AttachmentRef, AttachmentState, CandidateOutcome, ComponentVersion, ContentKind, ContentPart,
    Conversation, ConversationCandidate, ConversationSourceParser, IngestionIssue, MessageNode,
    MessageRole, NodeState, SourceProduct, SourceRecord,
};

const PARSER_NAME: &str = "tessera-chatgpt-export";
const PARSER_VERSION: &str = "1";

#[derive(Debug, Clone, Default)]
pub struct ChatgptExportParser {
    export_id: Option<String>,
}

impl ChatgptExportParser {
    pub fn new(export_id: Option<String>) -> Self {
        Self { export_id }
    }
}

impl ConversationSourceParser for ChatgptExportParser {
    fn source_product(&self) -> SourceProduct {
        SourceProduct::Chatgpt
    }

    fn parser(&self) -> ComponentVersion {
        ComponentVersion {
            name: PARSER_NAME.into(),
            version: PARSER_VERSION.into(),
        }
    }

    fn normalizer(&self) -> ComponentVersion {
        ComponentVersion {
            name: "tessera-conversation".into(),
            version: "1".into(),
        }
    }

    fn export_id(&self) -> Option<String> {
        self.export_id.clone()
    }

    fn parse(&self, source: &[u8]) -> Result<Vec<ConversationCandidate>, IngestionIssue> {
        let items = parse_archive_items(source)?;
        if items.is_empty() {
            return Err(IngestionIssue::MissingRequiredStructure);
        }
        Ok(items
            .iter()
            .map(|item| build_conversation(item, self.export_id.as_deref()))
            .collect())
    }
}

fn build_conversation(item: &ArchiveItem, export_id: Option<&str>) -> ConversationCandidate {
    let Some(object) = item.value.as_object() else {
        return ConversationCandidate::quarantined(
            format!("chatgpt-record-{}", item.index),
            IngestionIssue::ChangedFieldType,
        );
    };
    let Some(conversation_id) = string_any(object, &["id", "conversation_id", "uuid"]) else {
        return ConversationCandidate::quarantined(
            format!("chatgpt-record-{}", item.index),
            IngestionIssue::MissingRequiredStructure,
        );
    };
    let Some(mapping) = object.get("mapping").and_then(Value::as_object) else {
        return ConversationCandidate::quarantined(
            conversation_id,
            if object.contains_key("mapping") {
                IngestionIssue::ChangedFieldType
            } else {
                IngestionIssue::MissingRequiredStructure
            },
        );
    };
    if mapping.is_empty() {
        return ConversationCandidate::quarantined(
            conversation_id,
            IngestionIssue::MissingRequiredStructure,
        );
    }

    let canonical_nodes: BTreeMap<String, String> = mapping
        .keys()
        .map(|source_id| {
            (
                source_id.clone(),
                stable_id("gptnode", &[&conversation_id, source_id]),
            )
        })
        .collect();
    let tool_uses = discover_tool_uses(&conversation_id, mapping);
    let mut source_records = Vec::with_capacity(mapping.len());
    let mut nodes = Vec::with_capacity(mapping.len());
    let mut models = BTreeSet::new();

    for (ordinal, (source_node_id, raw_node)) in mapping.iter().enumerate() {
        let record_id = stable_id("gptrecord", &[&conversation_id, source_node_id]);
        let raw_object = raw_node.as_object();
        let raw_message = raw_object.and_then(|node| node.get("message"));
        let message = raw_object
            .and_then(|node| node.get("message"))
            .and_then(Value::as_object);
        let source_message_id = message.and_then(|message| string_any(message, &["id", "uuid"]));
        source_records.push(SourceRecord {
            record_id: record_id.clone(),
            record_index: ordinal as u64,
            source_id: Some(source_node_id.clone()),
            byte_start: Some(item.byte_start),
            byte_end: Some(item.byte_end),
            line_start: Some(item.line_start),
            line_end: Some(item.line_end),
        });

        let source_parent = raw_object
            .and_then(|node| node.get("parent"))
            .and_then(Value::as_str);
        let parent_node_id = source_parent.and_then(|id| canonical_nodes.get(id).cloned());
        let mut state = node_state(raw_object, message);
        if raw_message.is_some_and(|message| !message.is_null() && !message.is_object()) {
            state = NodeState::Malformed;
        }
        let mut extensions = BTreeMap::from([(
            "source_node_id".into(),
            Value::String(source_node_id.clone()),
        )]);
        if let Some(message_id) = source_message_id.as_deref() {
            extensions.insert("source_message_id".into(), Value::String(message_id.into()));
        }
        if let Some(parent) = source_parent {
            extensions.insert("source_parent_node_id".into(), Value::String(parent.into()));
            if parent_node_id.is_none() {
                state = NodeState::Partial;
                extensions.insert("missing_source_parent".into(), Value::Bool(true));
            }
        }
        if let Some(children) = raw_object
            .and_then(|node| node.get("children"))
            .and_then(Value::as_array)
        {
            extensions.insert("source_children".into(), Value::Array(children.clone()));
        }
        if let Some(author) = message
            .and_then(|message| message.get("author"))
            .and_then(Value::as_object)
        {
            extensions.insert("source_author".into(), Value::Object(author.clone()));
        }
        if let Some(metadata) = message.and_then(message_metadata) {
            extensions.insert(
                "source_message_metadata".into(),
                Value::Object(metadata.clone()),
            );
        }
        if let Some(recipient) = message
            .and_then(|message| message.get("recipient"))
            .and_then(Value::as_str)
        {
            extensions.insert("source_recipient".into(), Value::String(recipient.into()));
        }
        if raw_message.is_some_and(|message| !message.is_null() && !message.is_object()) {
            extensions.insert(
                "source_message_missing_or_invalid".into(),
                Value::Bool(true),
            );
        }

        let model = message
            .and_then(message_metadata)
            .and_then(|metadata| string_any(metadata, &["model_slug", "model"]));
        if let Some(model) = &model {
            models.insert(model.clone());
        }
        let role = message.map(message_role).unwrap_or(MessageRole::Unknown);
        let timestamp = message.and_then(|message| timestamp(message.get("create_time")));
        let content_parts = if let Some(message) = message {
            message_parts(&conversation_id, source_node_id, message, role, &tool_uses)
        } else if raw_message.is_none_or(Value::is_null) && raw_object.is_some() {
            Vec::new()
        } else {
            vec![unsupported_part(
                stable_id("gptpart", &[&conversation_id, source_node_id, "malformed"]),
                raw_node.clone(),
                "missing_or_invalid_message",
            )]
        };
        nodes.push(MessageNode {
            node_id: canonical_nodes[source_node_id].clone(),
            parent_node_id,
            role,
            state,
            timestamp,
            model,
            source_record_ids: vec![record_id],
            content_parts,
            extensions,
        });
    }

    let source_endpoint = string_any(object, &["current_node", "current_node_id"]);
    if source_endpoint
        .as_ref()
        .is_some_and(|id| !canonical_nodes.contains_key(id))
    {
        return ConversationCandidate::quarantined(conversation_id, IngestionIssue::OrphanNode);
    }
    let endpoint = source_endpoint
        .as_ref()
        .and_then(|id| canonical_nodes.get(id).cloned())
        .or_else(|| select_leaf(&nodes));
    let selected_path = endpoint
        .and_then(|endpoint| trace_path(&endpoint, &nodes))
        .unwrap_or_default();
    if selected_path.is_empty() {
        return ConversationCandidate::quarantined(conversation_id, IngestionIssue::Cycle);
    }

    let project = string_any(
        object,
        &[
            "project_id",
            "project_uuid",
            "conversation_template_id",
            "gizmo_id",
        ],
    );
    let mut extensions = BTreeMap::from([
        ("session_id".into(), Value::String(conversation_id.clone())),
        (
            "source_format".into(),
            Value::String("chatgpt_export".into()),
        ),
    ]);
    if let Some(project) = &project {
        extensions.insert("project".into(), Value::String(project.clone()));
    }
    if let Some(export_id) = export_id {
        extensions.insert(
            "source_file_identity".into(),
            Value::String(export_id.into()),
        );
    }
    if !models.is_empty() {
        extensions.insert(
            "models".into(),
            Value::Array(models.into_iter().map(Value::String).collect()),
        );
    }
    if let Some(current) = string_any(object, &["current_node", "current_node_id"]) {
        extensions.insert("selected_source_node_id".into(), Value::String(current));
    }
    let associations = source_associations(object);
    if !associations.is_empty() {
        extensions.insert("source_associations".into(), Value::Object(associations));
    }

    let conversation = Conversation {
        conversation_id: conversation_id.clone(),
        title: string_any(object, &["title", "name"]),
        project,
        created_at: timestamp(
            object
                .get("create_time")
                .or_else(|| object.get("created_at")),
        ),
        updated_at: timestamp(
            object
                .get("update_time")
                .or_else(|| object.get("updated_at")),
        ),
        sensitivity: "restricted".into(),
        source_records,
        nodes,
        selected_path,
        extensions,
    };
    validate_candidate(conversation_id, conversation)
}

fn validate_candidate(id: String, conversation: Conversation) -> ConversationCandidate {
    match conversation.validate() {
        Ok(()) => ConversationCandidate::conversation(conversation),
        Err(error) => {
            let text = error.to_string();
            let issue = if text.contains("cycle") {
                IngestionIssue::Cycle
            } else if text.contains("unknown parent") {
                IngestionIssue::OrphanNode
            } else {
                IngestionIssue::NormalFormInvariant
            };
            ConversationCandidate {
                source_conversation_id: id,
                outcome: CandidateOutcome::Quarantined(issue),
            }
        }
    }
}

fn message_metadata(message: &Map<String, Value>) -> Option<&Map<String, Value>> {
    message.get("metadata").and_then(Value::as_object)
}

fn source_associations(object: &Map<String, Value>) -> Map<String, Value> {
    let mut associations = Map::new();
    for key in [
        "project_id",
        "project_uuid",
        "conversation_template_id",
        "gizmo_id",
        "gizmo_type",
    ] {
        if let Some(value) = object.get(key) {
            associations.insert(key.into(), value.clone());
        }
    }
    associations
}

fn node_state(
    node: Option<&Map<String, Value>>,
    message: Option<&Map<String, Value>>,
) -> NodeState {
    let Some(message) = message else {
        return if node.is_some() {
            NodeState::Hidden
        } else {
            NodeState::Malformed
        };
    };
    let metadata = message_metadata(message);
    if metadata.is_some_and(|metadata| {
        bool_any(
            metadata,
            &[
                "is_visually_hidden_from_conversation",
                "is_hidden",
                "hidden",
            ],
        )
    }) {
        return NodeState::Hidden;
    }
    if bool_any(message, &["is_deleted", "deleted"])
        || metadata.is_some_and(|metadata| {
            bool_any(
                metadata,
                &["is_deleted", "is_deleted_from_citation", "deleted"],
            )
        })
        || message.get("status").and_then(Value::as_str) == Some("deleted")
    {
        return NodeState::Deleted;
    }
    match message.get("status").and_then(Value::as_str) {
        Some("finished_successfully") | None => NodeState::Visible,
        Some(_) => NodeState::Partial,
    }
}

fn bool_any(object: &Map<String, Value>, keys: &[&str]) -> bool {
    keys.iter()
        .any(|key| object.get(*key).and_then(Value::as_bool).unwrap_or(false))
}

fn message_role(message: &Map<String, Value>) -> MessageRole {
    match message
        .get("author")
        .and_then(Value::as_object)
        .and_then(|author| author.get("role"))
        .and_then(Value::as_str)
    {
        Some("user") | Some("human") => MessageRole::User,
        Some("assistant") => MessageRole::Assistant,
        Some("system") => MessageRole::System,
        Some("tool") => MessageRole::Tool,
        _ => MessageRole::Unknown,
    }
}

fn discover_tool_uses(
    conversation_id: &str,
    mapping: &Map<String, Value>,
) -> BTreeMap<String, String> {
    let mut uses = BTreeMap::new();
    for (node_id, node) in mapping {
        let Some(message) = node
            .as_object()
            .and_then(|node| node.get("message"))
            .and_then(Value::as_object)
        else {
            continue;
        };
        let recipient = message.get("recipient").and_then(Value::as_str);
        let content_type = message
            .get("content")
            .and_then(Value::as_object)
            .and_then(|content| content.get("content_type"))
            .and_then(Value::as_str);
        let tool_name = recipient
            .filter(|recipient| *recipient != "all")
            .map(str::to_owned)
            .or_else(|| message_metadata(message).and_then(|m| string_any(m, &["tool_name"])));
        if (recipient.is_some_and(|recipient| recipient != "all")
            || matches!(content_type, Some("tool_use" | "tool_call")))
            && tool_name.is_some()
        {
            let source_message_id =
                string_any(message, &["id", "uuid"]).unwrap_or_else(|| node_id.clone());
            let call_id = message_metadata(message)
                .and_then(|metadata| {
                    string_any(metadata, &["tool_call_id", "call_id", "tool_use_id"])
                })
                .unwrap_or_else(|| source_message_id.clone());
            uses.insert(
                call_id,
                stable_id("gptpart", &[conversation_id, node_id, "tool_use"]),
            );
        }
    }
    uses
}

fn message_parts(
    conversation_id: &str,
    source_node_id: &str,
    message: &Map<String, Value>,
    role: MessageRole,
    tool_uses: &BTreeMap<String, String>,
) -> Vec<ContentPart> {
    let recipient = message.get("recipient").and_then(Value::as_str);
    let content = message.get("content");
    let content_type = content
        .and_then(Value::as_object)
        .and_then(|content| content.get("content_type"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let mut parts = if recipient.is_some_and(|recipient| recipient != "all")
        || matches!(content_type, "tool_use" | "tool_call")
    {
        let source_message_id =
            string_any(message, &["id", "uuid"]).unwrap_or_else(|| source_node_id.into());
        let call_id = message_metadata(message)
            .and_then(|metadata| string_any(metadata, &["tool_call_id", "call_id", "tool_use_id"]))
            .unwrap_or(source_message_id);
        let tool_name = recipient
            .filter(|recipient| *recipient != "all")
            .map(str::to_owned)
            .or_else(|| message_metadata(message).and_then(|m| string_any(m, &["tool_name"])));
        vec![ContentPart {
            part_id: tool_uses.get(&call_id).cloned().unwrap_or_else(|| {
                stable_id("gptpart", &[conversation_id, source_node_id, "tool_use"])
            }),
            kind: if tool_name.is_some() {
                ContentKind::ToolUse
            } else {
                ContentKind::Unsupported
            },
            text: None,
            language: None,
            tool_name,
            tool_use_id: None,
            data: content.cloned().or_else(|| Some(Value::Object(Map::new()))),
            attachment: None,
            extensions: BTreeMap::from([("source_tool_call_id".into(), Value::String(call_id))]),
        }]
    } else if role == MessageRole::Tool || matches!(content_type, "tool_result" | "computer_output")
    {
        tool_result_part(conversation_id, source_node_id, message, tool_uses)
    } else {
        normal_content_parts(conversation_id, source_node_id, content)
    };
    append_metadata_attachments(conversation_id, source_node_id, message, &mut parts);
    parts
}

fn tool_result_part(
    conversation_id: &str,
    source_node_id: &str,
    message: &Map<String, Value>,
    tool_uses: &BTreeMap<String, String>,
) -> Vec<ContentPart> {
    let call_id = message_metadata(message)
        .and_then(|metadata| string_any(metadata, &["tool_call_id", "call_id", "tool_use_id"]));
    let matched = call_id.as_ref().and_then(|id| tool_uses.get(id)).cloned();
    let mut extensions = BTreeMap::new();
    if let Some(call_id) = call_id {
        extensions.insert("source_tool_call_id".into(), Value::String(call_id));
    }
    if matched.is_none() {
        extensions.insert("unmatched_tool_result".into(), Value::Bool(true));
    }
    vec![ContentPart {
        part_id: stable_id("gptpart", &[conversation_id, source_node_id, "tool_result"]),
        kind: if matched.is_some() {
            ContentKind::ToolResult
        } else {
            ContentKind::Unsupported
        },
        text: None,
        language: None,
        tool_name: None,
        tool_use_id: matched,
        data: message.get("content").cloned(),
        attachment: None,
        extensions,
    }]
}

fn normal_content_parts(
    conversation_id: &str,
    source_node_id: &str,
    content: Option<&Value>,
) -> Vec<ContentPart> {
    let Some(content) = content else {
        return Vec::new();
    };
    let Some(object) = content.as_object() else {
        return vec![unsupported_part(
            stable_id("gptpart", &[conversation_id, source_node_id, "0"]),
            content.clone(),
            "content_not_object",
        )];
    };
    let content_type = object
        .get("content_type")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if content_type == "code" {
        return vec![ContentPart {
            part_id: stable_id("gptpart", &[conversation_id, source_node_id, "0"]),
            kind: ContentKind::Code,
            text: extract_text(object),
            language: object
                .get("language")
                .and_then(Value::as_str)
                .map(str::to_owned),
            tool_name: None,
            tool_use_id: None,
            data: None,
            attachment: None,
            extensions: BTreeMap::new(),
        }];
    }
    let Some(values) = object.get("parts").and_then(Value::as_array) else {
        return extract_text(object)
            .map(|text| {
                vec![text_part(
                    stable_id("gptpart", &[conversation_id, source_node_id, "0"]),
                    text,
                )]
            })
            .unwrap_or_else(|| {
                vec![unsupported_part(
                    stable_id("gptpart", &[conversation_id, source_node_id, "0"]),
                    content.clone(),
                    "unsupported_content_object",
                )]
            });
    };
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let id = stable_id(
                "gptpart",
                &[conversation_id, source_node_id, &index.to_string()],
            );
            let mut part = match value {
                Value::String(text) => text_part(id, text.clone()),
                Value::Object(object) => structured_part(id, object),
                other => unsupported_part(id, other.clone(), "unsupported_part_type"),
            };
            part.extensions.insert(
                "source_content_part_index".into(),
                Value::Number(index.into()),
            );
            part
        })
        .collect()
}

fn extract_text(object: &Map<String, Value>) -> Option<String> {
    object
        .get("text")
        .or_else(|| object.get("content"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            object.get("parts").and_then(Value::as_array).map(|parts| {
                parts
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
        })
}

fn structured_part(id: String, object: &Map<String, Value>) -> ContentPart {
    let source_type = object
        .get("content_type")
        .or_else(|| object.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    match source_type {
        "text" => text_part(
            id,
            object
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .into(),
        ),
        "code" => ContentPart {
            part_id: id,
            kind: ContentKind::Code,
            text: Some(
                object
                    .get("text")
                    .or_else(|| object.get("code"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .into(),
            ),
            language: object
                .get("language")
                .and_then(Value::as_str)
                .map(str::to_owned),
            tool_name: None,
            tool_use_id: None,
            data: None,
            attachment: None,
            extensions: BTreeMap::new(),
        },
        "image_asset_pointer" | "image" => attachment_part(id, ContentKind::Image, object),
        "file" | "file_attachment" | "audio_asset_pointer" => {
            attachment_part(id, ContentKind::File, object)
        }
        _ => unsupported_part(id, Value::Object(object.clone()), source_type),
    }
}

fn append_metadata_attachments(
    conversation_id: &str,
    source_node_id: &str,
    message: &Map<String, Value>,
    parts: &mut Vec<ContentPart>,
) {
    let Some(attachments) = message_metadata(message)
        .and_then(|metadata| metadata.get("attachments"))
        .and_then(Value::as_array)
    else {
        return;
    };
    for (index, attachment) in attachments.iter().enumerate() {
        let id = stable_id(
            "gptpart",
            &[
                conversation_id,
                source_node_id,
                "attachment",
                &index.to_string(),
            ],
        );
        if let Some(object) = attachment.as_object() {
            parts.push(attachment_part(id, ContentKind::File, object));
        } else {
            parts.push(unsupported_part(
                id,
                attachment.clone(),
                "invalid_attachment",
            ));
        }
    }
}

fn attachment_part(id: String, kind: ContentKind, object: &Map<String, Value>) -> ContentPart {
    let source_id = string_any(object, &["asset_pointer", "file_id", "id", "attachment_id"])
        .unwrap_or_else(|| stable_id("gptattachment", &[&id]));
    let inline = object.contains_key("data") || object.contains_key("base64");
    let external = object.contains_key("asset_pointer") || object.contains_key("url");
    ContentPart {
        part_id: id,
        kind,
        text: None,
        language: None,
        tool_name: None,
        tool_use_id: None,
        data: None,
        attachment: Some(AttachmentRef {
            attachment_id: source_id,
            filename: string_any(object, &["name", "filename"]),
            media_type: string_any(object, &["mime_type", "media_type", "content_type"]),
            preservation: if inline {
                AttachmentState::Preserved
            } else if external {
                AttachmentState::ExternalUnfetched
            } else {
                AttachmentState::Missing
            },
            content_hash: string_any(object, &["content_hash", "hash"])
                .filter(|hash| hash.len() == 64),
        }),
        extensions: BTreeMap::from([("source_attachment".into(), Value::Object(object.clone()))]),
    }
}

fn text_part(id: String, text: String) -> ContentPart {
    ContentPart {
        part_id: id,
        kind: ContentKind::Text,
        text: Some(text),
        language: None,
        tool_name: None,
        tool_use_id: None,
        data: None,
        attachment: None,
        extensions: BTreeMap::new(),
    }
}

fn unsupported_part(id: String, value: Value, reason: &str) -> ContentPart {
    ContentPart {
        part_id: id,
        kind: ContentKind::Unsupported,
        text: None,
        language: None,
        tool_name: None,
        tool_use_id: None,
        data: Some(value),
        attachment: None,
        extensions: BTreeMap::from([("source_type".into(), Value::String(reason.into()))]),
    }
}

fn select_leaf(nodes: &[MessageNode]) -> Option<String> {
    let parents: BTreeSet<&str> = nodes
        .iter()
        .filter_map(|node| node.parent_node_id.as_deref())
        .collect();
    nodes
        .iter()
        .rev()
        .find(|node| !parents.contains(node.node_id.as_str()))
        .map(|node| node.node_id.clone())
}

fn trace_path(endpoint: &str, nodes: &[MessageNode]) -> Option<Vec<String>> {
    let by_id: BTreeMap<&str, &MessageNode> = nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect();
    let mut current = endpoint;
    let mut reverse = Vec::new();
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(current) {
            return None;
        }
        let node = by_id.get(current)?;
        reverse.push(current.to_owned());
        let Some(parent) = node.parent_node_id.as_deref() else {
            break;
        };
        current = parent;
    }
    reverse.reverse();
    Some(reverse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{self, Sensitivity};
    use crate::conversation::{
        citation_for_chunk, ingest, load_conversation, reconstruct_cited_nodes,
        reconstruct_cited_source_records, IngestionOptions,
    };
    use crate::crypto::KdfParams;
    use crate::{space, Vault};

    const FIXTURE: &[u8] = include_bytes!("../../../../tests/fixtures/chatgpt-export.json");

    #[test]
    fn preserves_mapping_branches_selected_path_and_source_ids() {
        let candidates = ChatgptExportParser::new(Some("chatgpt-export.json".into()))
            .parse(FIXTURE)
            .expect("parse");
        assert_eq!(candidates.len(), 2);
        let CandidateOutcome::Conversation(conversation) = &candidates[0].outcome else {
            panic!("conversation");
        };
        assert_eq!(conversation.conversation_id, "chatgpt-fixture-1");
        assert_eq!(conversation.nodes.len(), 7);
        assert!(conversation
            .nodes
            .iter()
            .any(|node| node.state == NodeState::Deleted));
        assert!(conversation
            .nodes
            .iter()
            .any(|node| node.state == NodeState::Malformed));
        assert!(conversation
            .nodes
            .iter()
            .any(|node| node.role == MessageRole::User));
        assert!(conversation
            .nodes
            .iter()
            .any(|node| node.role == MessageRole::Assistant));
        assert!(conversation
            .nodes
            .iter()
            .flat_map(|node| &node.content_parts)
            .any(|part| part.kind == ContentKind::Image));
        let rendered = conversation.render_selected_transcript().expect("render");
        assert!(rendered.contains("selected archive answer"));
        assert!(!rendered.contains("alternate archive answer"));
        assert!(conversation.nodes.iter().all(|node| {
            node.extensions.contains_key("source_node_id") && !node.source_record_ids.is_empty()
        }));
        assert_eq!(conversation.source_records[0].byte_start, Some(4));
        assert!(conversation.source_records[0].byte_end.unwrap() > 4);
    }

    #[test]
    fn quarantines_only_the_structurally_invalid_conversation() {
        let candidates = ChatgptExportParser::default()
            .parse(FIXTURE)
            .expect("parse");
        assert!(matches!(
            candidates[1].outcome,
            CandidateOutcome::Quarantined(IngestionIssue::ChangedFieldType)
        ));
        assert!(matches!(
            candidates[0].outcome,
            CandidateOutcome::Conversation(_)
        ));
    }

    #[test]
    fn persisted_citations_reconstruct_exact_conversation_bytes_and_changes_are_versions() {
        let directory = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(
            &directory.path().join("Chatgpt.tessera"),
            "test",
            &KdfParams {
                m_cost_kib: 1024,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .expect("vault");
        let space_id = space::create(&vault, "ChatGPT", None).expect("space");
        let (source_artifact, source_version) = artifact::register_encrypted_bytes(
            &vault,
            &space_id,
            "chatgpt-export.json",
            "application/json",
            Sensitivity::Restricted,
            FIXTURE,
        )
        .expect("source");
        let source_metadata = artifact::get(&vault, &source_artifact).expect("source metadata");
        assert_eq!(source_metadata.sensitivity, Sensitivity::Restricted);
        assert_eq!(source_metadata.state, artifact::ArtifactState::Pending);

        let parser = ChatgptExportParser::new(Some("chatgpt-export.json".into()));
        let first = ingest(
            &vault,
            &space_id,
            &source_version.id,
            &parser,
            &IngestionOptions::default(),
        )
        .expect("ingest");
        assert_eq!((first.imported, first.quarantined), (1, 1));
        assert_eq!(first.parser.name, PARSER_NAME);
        assert_eq!(first.parser.version, PARSER_VERSION);
        let item = first
            .items
            .iter()
            .find(|item| item.source_conversation_id == "chatgpt-fixture-1")
            .expect("valid item");
        let persisted = load_conversation(
            &vault,
            item.persisted_conversation_id
                .as_deref()
                .expect("persisted conversation"),
        )
        .expect("round trip");
        assert_eq!(persisted.nodes.len(), 7);
        let rendered = persisted.render_selected_transcript().expect("render");
        assert!(rendered.contains("selected archive answer"));
        assert!(!rendered.contains("alternate archive answer"));
        let derived_id = item.derived_text_id.as_deref().expect("derived text");
        let chunks = crate::chunk::chunks_of(&vault, derived_id).expect("chunks");
        assert!(!chunks.is_empty());
        for chunk in chunks {
            let citation = citation_for_chunk(&vault, &chunk.id).expect("citation");
            let nodes = reconstruct_cited_nodes(&vault, &citation).expect("source identities");
            assert!(nodes
                .iter()
                .all(|node| node.extensions.contains_key("source_node_id")));
            assert!(nodes
                .iter()
                .flat_map(|node| &node.content_parts)
                .all(|part| {
                    part.extensions.contains_key("source_content_part_index")
                        || part.attachment.is_some()
                        || part.kind == ContentKind::Unsupported
                }));
            let records =
                reconstruct_cited_source_records(&vault, &citation).expect("source records");
            assert!(!records.is_empty());
            for record in records {
                let value: Value =
                    serde_json::from_slice(&record.bytes).expect("conversation JSON");
                assert_eq!(value["id"], "chatgpt-fixture-1");
                assert_eq!(
                    record.bytes,
                    FIXTURE[record.byte_range.0 as usize..record.byte_range.1 as usize]
                );
            }
        }

        let changed = String::from_utf8(FIXTURE.to_vec()).expect("utf8").replace(
            "selected archive answer",
            "selected archive answer version two",
        );
        let (_, changed_version) = artifact::register_encrypted_bytes(
            &vault,
            &space_id,
            "chatgpt-export.json",
            "application/json",
            Sensitivity::Restricted,
            changed.as_bytes(),
        )
        .expect("changed source");
        let second = ingest(
            &vault,
            &space_id,
            &changed_version.id,
            &parser,
            &IngestionOptions::default(),
        )
        .expect("changed ingest");
        assert_eq!((second.updated, second.quarantined), (1, 1));
        let updated = second
            .items
            .iter()
            .find(|item| item.source_conversation_id == "chatgpt-fixture-1")
            .expect("updated item");
        assert_eq!(
            updated.previous_persisted_conversation_id.as_deref(),
            item.persisted_conversation_id.as_deref()
        );
        assert_ne!(
            updated.persisted_conversation_id,
            item.persisted_conversation_id
        );
    }
}
