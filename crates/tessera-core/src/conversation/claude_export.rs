//! Claude account data-export adapter.
//!
//! The parser accepts the documented archive-style conversation/message shape
//! without sharing assumptions with the line-oriented Claude Code adapter.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::archive_source::{parse_archive_items, stable_id, string_any, timestamp, ArchiveItem};
use super::{
    AttachmentRef, AttachmentState, CandidateOutcome, ComponentVersion, ContentKind, ContentPart,
    Conversation, ConversationCandidate, ConversationSourceParser, IngestionIssue, MessageNode,
    MessageRole, NodeState, SourceProduct, SourceRecord,
};

const PARSER_NAME: &str = "tessera-claude-export";
const PARSER_VERSION: &str = "1";

#[derive(Debug, Clone, Default)]
pub struct ClaudeExportParser {
    export_id: Option<String>,
}

impl ClaudeExportParser {
    pub fn new(export_id: Option<String>) -> Self {
        Self { export_id }
    }
}

impl ConversationSourceParser for ClaudeExportParser {
    fn source_product(&self) -> SourceProduct {
        SourceProduct::Claude
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
            format!("claude-record-{}", item.index),
            IngestionIssue::ChangedFieldType,
        );
    };
    let Some(conversation_id) = string_any(object, &["uuid", "id", "conversation_id"]) else {
        return ConversationCandidate::quarantined(
            format!("claude-record-{}", item.index),
            IngestionIssue::MissingRequiredStructure,
        );
    };
    let messages_value = object
        .get("chat_messages")
        .or_else(|| object.get("messages"));
    let Some(messages) = messages_value.and_then(Value::as_array) else {
        return ConversationCandidate::quarantined(
            conversation_id,
            if messages_value.is_some() {
                IngestionIssue::ChangedFieldType
            } else {
                IngestionIssue::MissingRequiredStructure
            },
        );
    };
    if messages.is_empty() {
        return ConversationCandidate::quarantined(
            conversation_id,
            IngestionIssue::MissingRequiredStructure,
        );
    }

    let source_ids: Vec<String> = messages
        .iter()
        .enumerate()
        .map(|(index, message)| {
            message
                .as_object()
                .and_then(|message| string_any(message, &["uuid", "id", "message_id"]))
                .unwrap_or_else(|| format!("message-{index}"))
        })
        .collect();
    let canonical_nodes: BTreeMap<String, String> = source_ids
        .iter()
        .map(|source_id| {
            (
                source_id.clone(),
                stable_id("claudenode", &[&conversation_id, source_id]),
            )
        })
        .collect();
    if canonical_nodes.len() != source_ids.len() {
        return ConversationCandidate::quarantined(
            conversation_id,
            IngestionIssue::NormalFormInvariant,
        );
    }
    let tool_uses = discover_tool_uses(&conversation_id, messages, &source_ids);
    let mut source_records = Vec::with_capacity(messages.len());
    let mut nodes = Vec::with_capacity(messages.len());
    let mut models = BTreeSet::new();

    for (index, message_value) in messages.iter().enumerate() {
        let source_id = &source_ids[index];
        let message = message_value.as_object();
        let record_id = stable_id("clauderecord", &[&conversation_id, source_id]);
        source_records.push(SourceRecord {
            record_id: record_id.clone(),
            record_index: index as u64,
            source_id: Some(source_id.clone()),
            byte_start: Some(item.byte_start),
            byte_end: Some(item.byte_end),
            line_start: Some(item.line_start),
            line_end: Some(item.line_end),
        });

        let explicit_parent = message.and_then(|message| {
            string_any(
                message,
                &["parent_uuid", "parent_message_uuid", "parent_id"],
            )
        });
        let inferred_parent = index.checked_sub(1).map(|prior| source_ids[prior].as_str());
        let source_parent = explicit_parent.as_deref().or(inferred_parent);
        let parent_node_id = source_parent.and_then(|id| canonical_nodes.get(id).cloned());
        let mut state = message.map(message_state).unwrap_or(NodeState::Malformed);
        let mut extensions =
            BTreeMap::from([("source_message_id".into(), Value::String(source_id.clone()))]);
        if let Some(parent) = explicit_parent {
            extensions.insert(
                "source_parent_message_id".into(),
                Value::String(parent.clone()),
            );
            if !canonical_nodes.contains_key(&parent) {
                state = NodeState::Partial;
                extensions.insert("missing_source_parent".into(), Value::Bool(true));
            }
        }
        if message.is_none() {
            extensions.insert("source_message_invalid".into(), Value::Bool(true));
        }
        if let Some(metadata) = message
            .and_then(|message| message.get("metadata"))
            .and_then(Value::as_object)
        {
            extensions.insert(
                "source_message_metadata".into(),
                Value::Object(metadata.clone()),
            );
        }
        let model = message.and_then(|message| string_any(message, &["model", "model_name"]));
        if let Some(model) = &model {
            models.insert(model.clone());
        }
        nodes.push(MessageNode {
            node_id: canonical_nodes[source_id].clone(),
            parent_node_id,
            role: message.map(message_role).unwrap_or(MessageRole::Unknown),
            state,
            timestamp: message.and_then(|message| {
                timestamp(
                    message
                        .get("created_at")
                        .or_else(|| message.get("create_time")),
                )
            }),
            model,
            source_record_ids: vec![record_id],
            content_parts: message
                .map(|message| message_parts(&conversation_id, source_id, message, &tool_uses))
                .unwrap_or_else(|| {
                    vec![unsupported_part(
                        stable_id("claudepart", &[&conversation_id, source_id, "malformed"]),
                        message_value.clone(),
                        "invalid_message",
                    )]
                }),
            extensions,
        });
    }

    let endpoint = string_any(object, &["current_node", "current_message_uuid"])
        .and_then(|id| canonical_nodes.get(&id).cloned())
        .or_else(|| nodes.last().map(|node| node.node_id.clone()));
    let selected_path = endpoint
        .and_then(|endpoint| trace_path(&endpoint, &nodes))
        .unwrap_or_default();
    if selected_path.is_empty() {
        return ConversationCandidate::quarantined(conversation_id, IngestionIssue::Cycle);
    }

    let project = project_identity(object);
    let mut extensions = BTreeMap::from([
        ("session_id".into(), Value::String(conversation_id.clone())),
        (
            "source_format".into(),
            Value::String("claude_export".into()),
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
    let associations = source_associations(object);
    if !associations.is_empty() {
        extensions.insert("source_associations".into(), Value::Object(associations));
    }

    let conversation = Conversation {
        conversation_id: conversation_id.clone(),
        title: string_any(object, &["name", "title", "summary"]),
        project,
        created_at: timestamp(
            object
                .get("created_at")
                .or_else(|| object.get("create_time")),
        ),
        updated_at: timestamp(
            object
                .get("updated_at")
                .or_else(|| object.get("update_time")),
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

fn project_identity(object: &Map<String, Value>) -> Option<String> {
    string_any(
        object,
        &[
            "project_uuid",
            "project_id",
            "workspace_uuid",
            "workspace_id",
        ],
    )
    .or_else(|| {
        object
            .get("project")
            .and_then(Value::as_object)
            .and_then(|project| string_any(project, &["uuid", "id", "name"]))
    })
}

fn source_associations(object: &Map<String, Value>) -> Map<String, Value> {
    let mut associations = Map::new();
    for key in [
        "project_uuid",
        "project_id",
        "workspace_uuid",
        "workspace_id",
        "project",
        "workspace",
    ] {
        if let Some(value) = object.get(key) {
            associations.insert(key.into(), value.clone());
        }
    }
    associations
}

fn message_role(message: &Map<String, Value>) -> MessageRole {
    match string_any(message, &["sender", "role", "author"]).as_deref() {
        Some("human") | Some("user") => MessageRole::User,
        Some("assistant") => MessageRole::Assistant,
        Some("system") => MessageRole::System,
        Some("tool") | Some("tool_result") => MessageRole::Tool,
        _ => MessageRole::Unknown,
    }
}

fn message_state(message: &Map<String, Value>) -> NodeState {
    if bool_any(message, &["is_deleted", "deleted"]) {
        NodeState::Deleted
    } else if bool_any(message, &["is_hidden", "hidden"]) {
        NodeState::Hidden
    } else if bool_any(message, &["is_partial", "partial"])
        || matches!(
            message.get("status").and_then(Value::as_str),
            Some("pending" | "in_progress" | "partial")
        )
    {
        NodeState::Partial
    } else {
        NodeState::Visible
    }
}

fn bool_any(object: &Map<String, Value>, keys: &[&str]) -> bool {
    keys.iter()
        .any(|key| object.get(*key).and_then(Value::as_bool).unwrap_or(false))
}

fn discover_tool_uses(
    conversation_id: &str,
    messages: &[Value],
    source_ids: &[String],
) -> BTreeMap<String, String> {
    let mut uses = BTreeMap::new();
    for (message, source_id) in messages.iter().zip(source_ids) {
        let Some(blocks) = message
            .as_object()
            .and_then(|message| message.get("content"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for (index, block) in blocks.iter().enumerate() {
            if block.get("type").and_then(Value::as_str) == Some("tool_use")
                && block.get("name").and_then(Value::as_str).is_some()
            {
                if let Some(id) = block.get("id").and_then(Value::as_str) {
                    uses.insert(
                        id.into(),
                        stable_id(
                            "claudepart",
                            &[conversation_id, source_id, &index.to_string()],
                        ),
                    );
                }
            }
        }
    }
    uses
}

fn message_parts(
    conversation_id: &str,
    source_id: &str,
    message: &Map<String, Value>,
    tool_uses: &BTreeMap<String, String>,
) -> Vec<ContentPart> {
    let mut parts = match message.get("content") {
        Some(Value::String(text)) => vec![text_part(
            stable_id("claudepart", &[conversation_id, source_id, "0"]),
            ContentKind::Text,
            text.clone(),
        )],
        Some(Value::Array(blocks)) => blocks
            .iter()
            .enumerate()
            .map(|(index, block)| {
                content_block(conversation_id, source_id, index, block, tool_uses)
            })
            .collect(),
        Some(other) => vec![unsupported_part(
            stable_id("claudepart", &[conversation_id, source_id, "0"]),
            other.clone(),
            "content_not_string_or_array",
        )],
        None => message
            .get("text")
            .and_then(Value::as_str)
            .map(|text| {
                vec![text_part(
                    stable_id("claudepart", &[conversation_id, source_id, "0"]),
                    ContentKind::Text,
                    text.into(),
                )]
            })
            .unwrap_or_default(),
    };
    append_attachments(conversation_id, source_id, message, &mut parts);
    parts
}

fn content_block(
    conversation_id: &str,
    source_id: &str,
    index: usize,
    block: &Value,
    tool_uses: &BTreeMap<String, String>,
) -> ContentPart {
    let id = stable_id(
        "claudepart",
        &[conversation_id, source_id, &index.to_string()],
    );
    let Some(object) = block.as_object() else {
        return unsupported_part(id, block.clone(), "block_not_object");
    };
    let source_type = object
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let mut extensions = BTreeMap::from([
        ("source_block_index".into(), Value::Number(index.into())),
        ("source_type".into(), Value::String(source_type.into())),
    ]);
    if let Some(source_block_id) = string_any(object, &["id", "uuid"]) {
        extensions.insert("source_content_id".into(), Value::String(source_block_id));
    }
    match source_type {
        "text" => ContentPart {
            extensions,
            ..text_part(
                id,
                ContentKind::Text,
                object
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .into(),
            )
        },
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
            extensions,
        },
        "tool_use" => {
            let source_tool_id = object.get("id").and_then(Value::as_str);
            let tool_name = object
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned);
            ContentPart {
                part_id: source_tool_id
                    .and_then(|id| tool_uses.get(id).cloned())
                    .unwrap_or(id),
                kind: if tool_name.is_some() {
                    ContentKind::ToolUse
                } else {
                    ContentKind::Unsupported
                },
                text: None,
                language: None,
                tool_name,
                tool_use_id: None,
                data: object
                    .get("input")
                    .cloned()
                    .or_else(|| Some(Value::Object(Map::new()))),
                attachment: None,
                extensions,
            }
        }
        "tool_result" => {
            let source_tool_id = object.get("tool_use_id").and_then(Value::as_str);
            let canonical_tool_id = source_tool_id.and_then(|id| tool_uses.get(id)).cloned();
            if canonical_tool_id.is_none() {
                extensions.insert("unmatched_tool_result".into(), Value::Bool(true));
            }
            ContentPart {
                part_id: id,
                kind: if canonical_tool_id.is_some() {
                    ContentKind::ToolResult
                } else {
                    ContentKind::Unsupported
                },
                text: object
                    .get("content")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                language: None,
                tool_name: None,
                tool_use_id: canonical_tool_id,
                data: object
                    .get("content")
                    .filter(|value| !value.is_string())
                    .cloned(),
                attachment: None,
                extensions,
            }
        }
        "image" => attachment_part(id, ContentKind::Image, object, extensions),
        "file" | "document" => attachment_part(id, ContentKind::File, object, extensions),
        "thinking" | "redacted_thinking" => {
            extensions.insert("withheld_from_retrieval".into(), Value::Bool(true));
            ContentPart {
                part_id: id,
                kind: ContentKind::Unsupported,
                text: None,
                language: None,
                tool_name: None,
                tool_use_id: None,
                data: None,
                attachment: None,
                extensions,
            }
        }
        "error" => ContentPart {
            extensions,
            ..text_part(
                id,
                ContentKind::Error,
                object
                    .get("message")
                    .or_else(|| object.get("text"))
                    .and_then(Value::as_str)
                    .unwrap_or("Structured source error")
                    .into(),
            )
        },
        _ => ContentPart {
            extensions,
            ..unsupported_part(id, block.clone(), source_type)
        },
    }
}

fn append_attachments(
    conversation_id: &str,
    source_id: &str,
    message: &Map<String, Value>,
    parts: &mut Vec<ContentPart>,
) {
    for key in ["attachments", "files"] {
        let Some(attachments) = message.get(key).and_then(Value::as_array) else {
            continue;
        };
        for (index, attachment) in attachments.iter().enumerate() {
            let id = stable_id(
                "claudepart",
                &[conversation_id, source_id, key, &index.to_string()],
            );
            if let Some(object) = attachment.as_object() {
                parts.push(attachment_part(
                    id,
                    ContentKind::File,
                    object,
                    BTreeMap::from([("source_collection".into(), Value::String(key.into()))]),
                ));
            } else {
                parts.push(unsupported_part(
                    id,
                    attachment.clone(),
                    "invalid_attachment",
                ));
            }
        }
    }
}

fn attachment_part(
    id: String,
    kind: ContentKind,
    object: &Map<String, Value>,
    extensions: BTreeMap<String, Value>,
) -> ContentPart {
    let source = object
        .get("source")
        .and_then(Value::as_object)
        .unwrap_or(object);
    let attachment_id = string_any(source, &["id", "uuid", "file_id", "attachment_id", "url"])
        .unwrap_or_else(|| stable_id("claudeattachment", &[&id]));
    let inline = source.contains_key("data") || source.contains_key("base64");
    let external = source.contains_key("url");
    ContentPart {
        part_id: id,
        kind,
        text: None,
        language: None,
        tool_name: None,
        tool_use_id: None,
        data: None,
        attachment: Some(AttachmentRef {
            attachment_id,
            filename: string_any(source, &["file_name", "filename", "name"]),
            media_type: string_any(source, &["mime_type", "media_type", "content_type"]),
            preservation: if inline {
                AttachmentState::Preserved
            } else if external {
                AttachmentState::ExternalUnfetched
            } else {
                AttachmentState::Missing
            },
            content_hash: string_any(source, &["content_hash", "hash"])
                .filter(|hash| hash.len() == 64),
        }),
        extensions,
    }
}

fn text_part(id: String, kind: ContentKind, text: String) -> ContentPart {
    ContentPart {
        part_id: id,
        kind,
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

    const FIXTURE: &[u8] = include_bytes!("../../../../tests/fixtures/claude-export.json");

    #[test]
    fn preserves_block_order_tool_pairing_attachments_and_partial_state() {
        let candidates = ClaudeExportParser::new(Some("claude-export.json".into()))
            .parse(FIXTURE)
            .expect("parse");
        assert_eq!(candidates.len(), 2);
        let CandidateOutcome::Conversation(conversation) = &candidates[0].outcome else {
            panic!("conversation");
        };
        assert_eq!(conversation.conversation_id, "claude-fixture-1");
        assert_eq!(conversation.nodes[0].role, MessageRole::User);
        assert_eq!(conversation.nodes[1].role, MessageRole::Assistant);
        let kinds: Vec<ContentKind> = conversation
            .nodes
            .iter()
            .flat_map(|node| node.content_parts.iter().map(|part| part.kind))
            .collect();
        assert_eq!(
            &kinds[..5],
            &[
                ContentKind::Text,
                ContentKind::File,
                ContentKind::Text,
                ContentKind::ToolUse,
                ContentKind::ToolResult,
            ]
        );
        let result = conversation
            .nodes
            .iter()
            .flat_map(|node| &node.content_parts)
            .find(|part| part.kind == ContentKind::ToolResult)
            .expect("result");
        assert!(result.tool_use_id.is_some());
        let tool_use = conversation
            .nodes
            .iter()
            .flat_map(|node| &node.content_parts)
            .find(|part| part.kind == ContentKind::ToolUse)
            .expect("tool use");
        assert_eq!(
            tool_use.extensions["source_content_id"],
            Value::String("tool-fixture-1".into())
        );
        assert!(conversation
            .nodes
            .iter()
            .any(|node| node.state == NodeState::Partial));
        assert_eq!(conversation.project.as_deref(), Some("project-fixture"));
    }

    #[test]
    fn quarantines_only_invalid_message_collection() {
        let candidates = ClaudeExportParser::default().parse(FIXTURE).expect("parse");
        assert!(matches!(
            candidates[0].outcome,
            CandidateOutcome::Conversation(_)
        ));
        assert!(matches!(
            candidates[1].outcome,
            CandidateOutcome::Quarantined(IngestionIssue::ChangedFieldType)
        ));
    }
}
