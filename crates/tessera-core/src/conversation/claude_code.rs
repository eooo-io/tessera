//! Claude Code JSONL/session adapter.
//!
//! The adapter treats every source line as untrusted evidence. Recognized
//! message and tool structures become canonical nodes/content parts; unknown,
//! partial, and malformed records remain explicitly represented and the exact
//! original bytes stay authoritative in the encrypted source artifact.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::{
    AttachmentRef, AttachmentState, CandidateOutcome, ComponentVersion, ContentKind, ContentPart,
    Conversation, ConversationCandidate, ConversationSourceParser, IngestionIssue, MessageNode,
    MessageRole, NodeState, SourceProduct, SourceRecord,
};

const PARSER_NAME: &str = "tessera-claude-code-jsonl";
const PARSER_VERSION: &str = "1";
const NORMALIZER_NAME: &str = "tessera-conversation";
const NORMALIZER_VERSION: &str = "1";

#[derive(Debug, Clone, Default)]
pub struct ClaudeCodeParser {
    source_file_identity: Option<String>,
}

impl ClaudeCodeParser {
    pub fn new(source_file_identity: Option<String>) -> Self {
        Self {
            source_file_identity,
        }
    }
}

impl ConversationSourceParser for ClaudeCodeParser {
    fn source_product(&self) -> SourceProduct {
        SourceProduct::ClaudeCode
    }

    fn parser(&self) -> ComponentVersion {
        ComponentVersion {
            name: PARSER_NAME.into(),
            version: PARSER_VERSION.into(),
        }
    }

    fn normalizer(&self) -> ComponentVersion {
        ComponentVersion {
            name: NORMALIZER_NAME.into(),
            version: NORMALIZER_VERSION.into(),
        }
    }

    fn export_id(&self) -> Option<String> {
        self.source_file_identity.clone()
    }

    fn parse(&self, source: &[u8]) -> Result<Vec<ConversationCandidate>, IngestionIssue> {
        let records = parse_records(source)?;
        if records.is_empty() {
            return Err(IngestionIssue::MissingRequiredStructure);
        }

        let explicit_sessions: BTreeSet<String> = records
            .iter()
            .filter_map(|record| record.session_id())
            .collect();
        let fallback = format!("partial-{}", &blake3::hash(source).to_hex()[..24]);
        let sole_session = (explicit_sessions.len() == 1)
            .then(|| explicit_sessions.iter().next().cloned())
            .flatten();
        let mut grouped = BTreeMap::<String, Vec<RawRecord>>::new();
        for record in records {
            let session = record
                .session_id()
                .or_else(|| sole_session.clone())
                .unwrap_or_else(|| fallback.clone());
            grouped.entry(session).or_default().push(record);
        }

        Ok(grouped
            .into_iter()
            .map(|(session_id, records)| {
                build_conversation(&session_id, &records, self.source_file_identity.as_deref())
            })
            .collect())
    }
}

#[derive(Debug, Clone)]
struct RawRecord {
    record_index: u64,
    line: u64,
    byte_start: u64,
    byte_end: u64,
    raw: Vec<u8>,
    value: Option<Value>,
}

impl RawRecord {
    fn object(&self) -> Option<&Map<String, Value>> {
        self.value.as_ref()?.as_object()
    }

    fn string(&self, key: &str) -> Option<&str> {
        self.object()?.get(key)?.as_str()
    }

    fn session_id(&self) -> Option<String> {
        self.string("sessionId")
            .or_else(|| self.string("session_id"))
            .map(str::to_owned)
    }

    fn source_uuid(&self) -> Option<&str> {
        self.string("uuid").or_else(|| self.string("id"))
    }
}

fn parse_records(source: &[u8]) -> Result<Vec<RawRecord>, IngestionIssue> {
    if std::str::from_utf8(source).is_err() {
        return Err(IngestionIssue::ParserFailure);
    }
    let mut records = Vec::new();
    let mut line_start = 0usize;
    let mut line_number = 1u64;
    for cursor in 0..=source.len() {
        if cursor != source.len() && source[cursor] != b'\n' {
            continue;
        }
        let mut end = cursor;
        if end > line_start && source[end - 1] == b'\r' {
            end -= 1;
        }
        if source[line_start..end]
            .iter()
            .any(|byte| !byte.is_ascii_whitespace())
        {
            let raw = source[line_start..end].to_vec();
            records.push(RawRecord {
                record_index: records.len() as u64,
                line: line_number,
                byte_start: line_start as u64,
                byte_end: end as u64,
                value: serde_json::from_slice(&raw).ok(),
                raw,
            });
        }
        line_start = cursor.saturating_add(1);
        line_number += 1;
    }
    Ok(records)
}

fn build_conversation(
    session_id: &str,
    records: &[RawRecord],
    source_file_identity: Option<&str>,
) -> ConversationCandidate {
    let mut source_records = Vec::with_capacity(records.len());
    let mut node_ids = BTreeMap::<String, String>::new();
    let mut seen_node_ids = BTreeSet::new();
    for record in records {
        let source_key = record
            .source_uuid()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("record-{}", record.record_index));
        let node_id = stable_id("ccnode", &[session_id, &source_key]);
        if !seen_node_ids.insert(node_id.clone()) {
            return ConversationCandidate {
                source_conversation_id: session_id.to_owned(),
                outcome: CandidateOutcome::Quarantined(IngestionIssue::NormalFormInvariant),
            };
        }
        node_ids.insert(source_key, node_id);
    }

    let tool_parts = discover_tool_parts(session_id, records);
    let mut nodes = Vec::with_capacity(records.len());
    let mut timestamps = Vec::new();
    let mut metadata = SessionMetadata::default();
    for record in records {
        let record_id = stable_id(
            "ccrecord",
            &[
                session_id,
                &record.record_index.to_string(),
                blake3::hash(&record.raw).to_hex().as_str(),
            ],
        );
        source_records.push(SourceRecord {
            record_id: record_id.clone(),
            record_index: record.record_index,
            source_id: record.source_uuid().map(str::to_owned),
            byte_start: Some(record.byte_start),
            byte_end: Some(record.byte_end),
            line_start: Some(record.line),
            line_end: Some(record.line),
        });
        metadata.observe(record);
        let source_key = record
            .source_uuid()
            .map(str::to_owned)
            .unwrap_or_else(|| format!("record-{}", record.record_index));
        let node_id = node_ids[&source_key].clone();
        let mut state = record_state(record);
        let timestamp = record
            .string("timestamp")
            .and_then(valid_timestamp)
            .map(str::to_owned);
        if record.string("timestamp").is_some() && timestamp.is_none() {
            state = NodeState::Malformed;
        }
        if let Some(timestamp) = &timestamp {
            timestamps.push(timestamp.clone());
        }
        let source_parent = record
            .string("parentUuid")
            .or_else(|| record.string("parent_uuid"))
            .or_else(|| record.string("leafUuid"));
        let parent_node_id = source_parent.and_then(|parent| node_ids.get(parent).cloned());
        let mut extensions = BTreeMap::new();
        if let Some(parent) = source_parent.filter(|parent| !node_ids.contains_key(*parent)) {
            state = NodeState::Partial;
            extensions.insert("source_parent_uuid".into(), Value::String(parent.into()));
            extensions.insert("missing_source_parent".into(), Value::Bool(true));
        }
        if let Some(kind) = record.string("type") {
            extensions.insert("source_record_type".into(), Value::String(kind.into()));
        }
        if let Some(subtype) = record.string("subtype") {
            extensions.insert(
                "source_record_subtype".into(),
                Value::String(subtype.into()),
            );
        }
        if record.value.is_none() {
            extensions.insert("malformed_jsonl".into(), Value::Bool(true));
        }
        let role = record_role(record);
        let model = record
            .object()
            .and_then(|object| object.get("message"))
            .and_then(Value::as_object)
            .and_then(|message| message.get("model"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(model) = &model {
            metadata.models.insert(model.clone());
        }
        nodes.push(MessageNode {
            node_id,
            parent_node_id,
            role,
            state,
            timestamp,
            model,
            source_record_ids: vec![record_id],
            content_parts: record_parts(session_id, record, &tool_parts),
            extensions,
        });
    }

    let selected_path = select_path(records, &nodes, &node_ids);
    if selected_path.is_empty() {
        return ConversationCandidate::quarantined(
            session_id,
            IngestionIssue::MissingRequiredStructure,
        );
    }
    timestamps.sort();
    let mut extensions = metadata.into_extensions(session_id, source_file_identity);
    extensions.insert(
        "source_format".into(),
        Value::String("claude_code_jsonl".into()),
    );
    let conversation = Conversation {
        conversation_id: session_id.to_owned(),
        title: metadata_title(records),
        project: extensions
            .get("project")
            .and_then(Value::as_str)
            .map(str::to_owned),
        created_at: timestamps.first().cloned(),
        updated_at: timestamps.last().cloned(),
        sensitivity: "restricted".into(),
        source_records,
        nodes,
        selected_path,
        extensions,
    };
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
            ConversationCandidate::quarantined(session_id, issue)
        }
    }
}

#[derive(Default)]
struct SessionMetadata {
    cwd: Option<String>,
    project: Option<String>,
    repository: Option<String>,
    git_branch: Option<String>,
    git_commit: Option<String>,
    client_version: Option<String>,
    models: BTreeSet<String>,
}

impl SessionMetadata {
    fn observe(&mut self, record: &RawRecord) {
        self.cwd = self.cwd.take().or_else(|| string_any(record, &["cwd"]));
        self.project = self
            .project
            .take()
            .or_else(|| string_any(record, &["project", "projectName"]));
        self.repository = self
            .repository
            .take()
            .or_else(|| string_any(record, &["repository", "repo", "gitRepository"]));
        self.git_branch = self
            .git_branch
            .take()
            .or_else(|| string_any(record, &["gitBranch", "git_branch"]));
        self.git_commit = self
            .git_commit
            .take()
            .or_else(|| string_any(record, &["gitCommit", "git_commit"]));
        self.client_version = self
            .client_version
            .take()
            .or_else(|| string_any(record, &["version"]));
    }

    fn into_extensions(
        mut self,
        session_id: &str,
        source_file_identity: Option<&str>,
    ) -> BTreeMap<String, Value> {
        if self.project.is_none() {
            self.project = self
                .cwd
                .as_deref()
                .and_then(|cwd| cwd.trim_end_matches('/').rsplit('/').next())
                .filter(|name| !name.is_empty())
                .map(str::to_owned);
        }
        let mut values = BTreeMap::new();
        values.insert("session_id".into(), Value::String(session_id.into()));
        insert_string(&mut values, "cwd", self.cwd);
        insert_string(&mut values, "project", self.project);
        insert_string(&mut values, "repository", self.repository);
        insert_string(&mut values, "git_branch", self.git_branch);
        insert_string(&mut values, "git_commit", self.git_commit);
        insert_string(&mut values, "client_version", self.client_version);
        if let Some(identity) = source_file_identity {
            values.insert(
                "source_file_identity".into(),
                Value::String(identity.into()),
            );
        }
        if !self.models.is_empty() {
            values.insert(
                "models".into(),
                Value::Array(self.models.into_iter().map(Value::String).collect()),
            );
        }
        values
    }
}

fn insert_string(values: &mut BTreeMap<String, Value>, key: &str, value: Option<String>) {
    if let Some(value) = value {
        values.insert(key.into(), Value::String(value));
    }
}

fn string_any(record: &RawRecord, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| record.string(key).map(str::to_owned))
}

fn metadata_title(records: &[RawRecord]) -> Option<String> {
    records.iter().find_map(|record| {
        string_any(record, &["title", "summary"])
            .filter(|title| !title.is_empty() && title.len() <= 512)
    })
}

fn valid_timestamp(value: &str) -> Option<&str> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|_| value)
}

fn record_role(record: &RawRecord) -> MessageRole {
    let message_role = record
        .object()
        .and_then(|object| object.get("message"))
        .and_then(Value::as_object)
        .and_then(|message| message.get("role"))
        .and_then(Value::as_str);
    match message_role.or_else(|| record.string("type")) {
        Some("user") | Some("human") => MessageRole::User,
        Some("assistant") => MessageRole::Assistant,
        Some("system") | Some("summary") => MessageRole::System,
        Some("tool") | Some("tool_result") => MessageRole::Tool,
        _ => MessageRole::Unknown,
    }
}

fn record_state(record: &RawRecord) -> NodeState {
    if record.value.is_none() {
        return NodeState::Malformed;
    }
    if bool_any(record, &["isCompactSummary", "is_compact_summary"])
        || matches!(record.string("type"), Some("summary"))
        || matches!(record.string("subtype"), Some("compact_boundary"))
    {
        return NodeState::Compacted;
    }
    if bool_any(
        record,
        &["isSidechain", "is_sidechain", "isMeta", "is_meta"],
    ) || matches!(
        record.string("type"),
        Some("progress" | "file-history-snapshot")
    ) {
        return NodeState::Hidden;
    }
    if bool_any(record, &["isDeleted", "is_deleted"]) {
        return NodeState::Deleted;
    }
    if bool_any(record, &["isPartial", "is_partial"]) {
        return NodeState::Partial;
    }
    if matches!(record.string("type"), Some("user" | "assistant" | "system")) {
        NodeState::Visible
    } else {
        NodeState::Unsupported
    }
}

fn bool_any(record: &RawRecord, keys: &[&str]) -> bool {
    keys.iter().any(|key| {
        record
            .object()
            .and_then(|object| object.get(*key))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    })
}

fn discover_tool_parts(session_id: &str, records: &[RawRecord]) -> BTreeMap<String, String> {
    let mut parts = BTreeMap::new();
    for record in records {
        let Some(content) = message_content(record).and_then(Value::as_array) else {
            continue;
        };
        for block in content {
            if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                if let Some(id) = block.get("id").and_then(Value::as_str) {
                    parts.insert(id.into(), stable_id("ccpart", &[session_id, "tool", id]));
                }
            }
        }
    }
    parts
}

fn record_parts(
    session_id: &str,
    record: &RawRecord,
    tool_parts: &BTreeMap<String, String>,
) -> Vec<ContentPart> {
    if record.value.is_none() {
        return vec![text_part(
            stable_id(
                "ccpart",
                &[session_id, &record.record_index.to_string(), "malformed"],
            ),
            ContentKind::Error,
            "Malformed JSONL record preserved only in the encrypted source",
        )];
    }
    let compacted = record_state(record) == NodeState::Compacted;
    let mut parts = if let Some(content) = message_content(record) {
        content_parts(session_id, record, content, compacted, tool_parts)
    } else if compacted {
        if let Some(text) = record
            .string("summary")
            .or_else(|| record.string("content"))
        {
            vec![text_part(
                stable_id(
                    "ccpart",
                    &[session_id, &record.record_index.to_string(), "summary"],
                ),
                ContentKind::Compaction,
                text,
            )]
        } else {
            Vec::new()
        }
    } else if let Some(error) = record.string("error") {
        vec![text_part(
            stable_id(
                "ccpart",
                &[session_id, &record.record_index.to_string(), "error"],
            ),
            ContentKind::Error,
            error,
        )]
    } else {
        vec![ContentPart {
            part_id: stable_id(
                "ccpart",
                &[session_id, &record.record_index.to_string(), "unsupported"],
            ),
            kind: ContentKind::Unsupported,
            text: None,
            language: None,
            tool_name: None,
            tool_use_id: None,
            data: record.value.clone(),
            attachment: None,
            extensions: BTreeMap::from([(
                "source_type".into(),
                Value::String(record.string("type").unwrap_or("unknown").into()),
            )]),
        }]
    };
    let metadata = source_metadata_block(record);
    if !metadata.is_empty() {
        parts.push(ContentPart {
            part_id: stable_id(
                "ccpart",
                &[session_id, &record.record_index.to_string(), "metadata"],
            ),
            kind: ContentKind::Unsupported,
            text: None,
            language: None,
            tool_name: None,
            tool_use_id: None,
            data: Some(Value::Object(metadata)),
            attachment: None,
            extensions: BTreeMap::from([(
                "source_type".into(),
                Value::String("session_metadata".into()),
            )]),
        });
    }
    parts
}

fn source_metadata_block(record: &RawRecord) -> Map<String, Value> {
    const KEYS: &[&str] = &[
        "sessionId",
        "session_id",
        "cwd",
        "project",
        "projectName",
        "repository",
        "repo",
        "gitRepository",
        "gitBranch",
        "git_branch",
        "gitCommit",
        "git_commit",
        "version",
    ];
    let mut metadata = Map::new();
    if let Some(object) = record.object() {
        for key in KEYS {
            if let Some(value @ Value::String(_)) = object.get(*key) {
                metadata.insert((*key).into(), value.clone());
            }
        }
    }
    metadata
}

fn message_content(record: &RawRecord) -> Option<&Value> {
    record.object()?.get("message")?.as_object()?.get("content")
}

fn content_parts(
    session_id: &str,
    record: &RawRecord,
    content: &Value,
    compacted: bool,
    tool_parts: &BTreeMap<String, String>,
) -> Vec<ContentPart> {
    match content {
        Value::String(text) => vec![text_part(
            stable_id(
                "ccpart",
                &[session_id, &record.record_index.to_string(), "0"],
            ),
            if compacted {
                ContentKind::Compaction
            } else {
                ContentKind::Text
            },
            text,
        )],
        Value::Array(blocks) => blocks
            .iter()
            .enumerate()
            .map(|(index, block)| {
                content_block(session_id, record, index, block, compacted, tool_parts)
            })
            .collect(),
        other => vec![ContentPart {
            part_id: stable_id(
                "ccpart",
                &[session_id, &record.record_index.to_string(), "0"],
            ),
            kind: ContentKind::Unsupported,
            text: None,
            language: None,
            tool_name: None,
            tool_use_id: None,
            data: Some(other.clone()),
            attachment: None,
            extensions: BTreeMap::from([(
                "reason".into(),
                Value::String("message_content_not_string_or_array".into()),
            )]),
        }],
    }
}

fn content_block(
    session_id: &str,
    record: &RawRecord,
    index: usize,
    block: &Value,
    compacted: bool,
    tool_parts: &BTreeMap<String, String>,
) -> ContentPart {
    let source_type = block
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let default_id = stable_id(
        "ccpart",
        &[
            session_id,
            &record.record_index.to_string(),
            &index.to_string(),
        ],
    );
    match source_type {
        "text" => text_part(
            default_id,
            if compacted {
                ContentKind::Compaction
            } else {
                ContentKind::Text
            },
            block.get("text").and_then(Value::as_str).unwrap_or(""),
        ),
        "code" => ContentPart {
            part_id: default_id,
            kind: ContentKind::Code,
            text: Some(
                block
                    .get("text")
                    .or_else(|| block.get("code"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .into(),
            ),
            language: block
                .get("language")
                .and_then(Value::as_str)
                .map(str::to_owned),
            tool_name: None,
            tool_use_id: None,
            data: None,
            attachment: None,
            extensions: BTreeMap::new(),
        },
        "tool_use" => {
            let source_id = block.get("id").and_then(Value::as_str);
            ContentPart {
                part_id: source_id
                    .and_then(|id| tool_parts.get(id).cloned())
                    .unwrap_or(default_id),
                kind: ContentKind::ToolUse,
                text: None,
                language: None,
                tool_name: block.get("name").and_then(Value::as_str).map(str::to_owned),
                tool_use_id: None,
                data: block
                    .get("input")
                    .cloned()
                    .or(Some(Value::Object(Map::new()))),
                attachment: None,
                extensions: source_id
                    .map(|id| {
                        BTreeMap::from([("source_tool_use_id".into(), Value::String(id.into()))])
                    })
                    .unwrap_or_default(),
            }
        }
        "tool_result" => {
            let source_use = block.get("tool_use_id").and_then(Value::as_str);
            let canonical_use = source_use.and_then(|id| tool_parts.get(id)).cloned();
            let content = block.get("content").cloned();
            let mut extensions = BTreeMap::new();
            if block.get("is_error").and_then(Value::as_bool) == Some(true) {
                extensions.insert("is_error".into(), Value::Bool(true));
            }
            if let Some(source_use) = source_use {
                extensions.insert(
                    "source_tool_use_id".into(),
                    Value::String(source_use.into()),
                );
            }
            if canonical_use.is_none() {
                extensions.insert("unmatched_tool_result".into(), Value::Bool(true));
            }
            ContentPart {
                part_id: default_id,
                kind: if canonical_use.is_some() {
                    ContentKind::ToolResult
                } else {
                    ContentKind::Unsupported
                },
                text: content.as_ref().and_then(Value::as_str).map(str::to_owned),
                language: None,
                tool_name: None,
                tool_use_id: canonical_use,
                data: content.filter(|value| !value.is_string()),
                attachment: None,
                extensions,
            }
        }
        "image" | "file" | "document" => attachment_part(default_id, source_type, block),
        "error" => text_part(
            default_id,
            ContentKind::Error,
            block
                .get("text")
                .or_else(|| block.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("Structured source error"),
        ),
        "thinking" | "redacted_thinking" => ContentPart {
            part_id: default_id,
            kind: ContentKind::Unsupported,
            text: None,
            language: None,
            tool_name: None,
            tool_use_id: None,
            data: None,
            attachment: None,
            extensions: BTreeMap::from([
                ("source_type".into(), Value::String(source_type.into())),
                ("withheld_from_retrieval".into(), Value::Bool(true)),
            ]),
        },
        _ => ContentPart {
            part_id: default_id,
            kind: ContentKind::Unsupported,
            text: None,
            language: None,
            tool_name: None,
            tool_use_id: None,
            data: Some(block.clone()),
            attachment: None,
            extensions: BTreeMap::from([("source_type".into(), Value::String(source_type.into()))]),
        },
    }
}

fn text_part(id: String, kind: ContentKind, text: &str) -> ContentPart {
    ContentPart {
        part_id: id,
        kind,
        text: Some(text.into()),
        language: None,
        tool_name: None,
        tool_use_id: None,
        data: None,
        attachment: None,
        extensions: BTreeMap::new(),
    }
}

fn attachment_part(id: String, source_type: &str, block: &Value) -> ContentPart {
    let source = block.get("source").unwrap_or(block);
    let attachment_id = source
        .get("id")
        .or_else(|| block.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| stable_id("ccattachment", &[&id]));
    let has_inline_data = source.get("data").is_some();
    ContentPart {
        part_id: id,
        kind: match source_type {
            "image" => ContentKind::Image,
            "file" | "document" => ContentKind::File,
            _ => ContentKind::Attachment,
        },
        text: None,
        language: None,
        tool_name: None,
        tool_use_id: None,
        data: None,
        attachment: Some(AttachmentRef {
            attachment_id,
            filename: source
                .get("filename")
                .or_else(|| source.get("name"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            media_type: source
                .get("media_type")
                .or_else(|| source.get("mediaType"))
                .or_else(|| source.get("type"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            preservation: if has_inline_data {
                AttachmentState::Preserved
            } else if source.get("url").is_some() {
                AttachmentState::ExternalUnfetched
            } else {
                AttachmentState::Missing
            },
            content_hash: source
                .get("content_hash")
                .or_else(|| source.get("hash"))
                .and_then(Value::as_str)
                .filter(|hash| hash.len() == 64)
                .map(str::to_owned),
        }),
        extensions: BTreeMap::from([("source_type".into(), Value::String(source_type.into()))]),
    }
}

fn select_path(
    records: &[RawRecord],
    nodes: &[MessageNode],
    node_ids: &BTreeMap<String, String>,
) -> Vec<String> {
    let by_id: BTreeMap<&str, &MessageNode> = nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect();
    let explicit_leaf = records
        .iter()
        .rev()
        .find_map(|record| record.string("leafUuid"))
        .and_then(|leaf| node_ids.get(leaf));
    let endpoint = explicit_leaf.cloned().or_else(|| {
        nodes
            .iter()
            .rev()
            .find(|node| {
                matches!(
                    node.state,
                    NodeState::Visible | NodeState::Compacted | NodeState::Partial
                )
            })
            .or_else(|| nodes.last())
            .map(|node| node.node_id.clone())
    });
    let Some(mut current) = endpoint else {
        return Vec::new();
    };
    let mut reverse = Vec::new();
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(current.clone()) {
            return Vec::new();
        }
        reverse.push(current.clone());
        let Some(parent) = by_id
            .get(current.as_str())
            .and_then(|node| node.parent_node_id.clone())
        else {
            break;
        };
        current = parent;
    }
    reverse.reverse();
    reverse
}

fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    format!("{prefix}_{}", &hasher.finalize().to_hex()[..32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{self, Sensitivity};
    use crate::blob::BlobHash;
    use crate::conversation::{
        citation_for_chunk, ingest, list_conversation_metadata, reconstruct_cited_source_records,
        ConversationMetadataFilter, IngestionOptions,
    };
    use crate::crypto::KdfParams;
    use crate::embed::{EmbedError, EmbeddingProvider};
    use crate::index::RetrievalConstraints;
    use crate::{space, Vault};

    const FIXTURE: &[u8] = include_bytes!("../../../../tests/fixtures/claude-code-session.jsonl");

    struct TestEmbedder;

    impl EmbeddingProvider for TestEmbedder {
        fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
            let mut vector = vec![0.0f32; 384];
            let lower = text.to_lowercase();
            for window in lower.as_bytes().windows(3) {
                let index =
                    (window[0] as usize * 31 * 31 + window[1] as usize * 31 + window[2] as usize)
                        % 384;
                vector[index] += 1.0;
            }
            let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
            if norm > 0.0 {
                for value in &mut vector {
                    *value /= norm;
                }
            }
            Ok(vector)
        }

        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
            texts.iter().map(|text| self.embed(text)).collect()
        }

        fn model_version(&self) -> &str {
            "claude-code-test-trigram@1"
        }

        fn dimensions(&self) -> usize {
            384
        }

        fn calibrated_relevance_floor(&self) -> Option<f32> {
            Some(0.0)
        }
    }

    fn conversation() -> Conversation {
        let candidates = ClaudeCodeParser::new(Some("sanitized-session.jsonl".into()))
            .parse(FIXTURE)
            .expect("parse fixture");
        assert_eq!(candidates.len(), 1);
        match candidates.into_iter().next().expect("candidate").outcome {
            CandidateOutcome::Conversation(conversation) => *conversation,
            other => panic!("expected conversation, got {other:?}"),
        }
    }

    #[test]
    fn preserves_tool_pairing_compaction_partial_records_and_metadata() {
        let conversation = conversation();
        assert_eq!(conversation.conversation_id, "session-sanitized-1");
        assert_eq!(conversation.project.as_deref(), Some("tessera-fixture"));
        assert_eq!(
            conversation.extensions["git_branch"],
            Value::String("feature/import".into())
        );
        assert!(conversation
            .nodes
            .iter()
            .any(|node| node.state == NodeState::Compacted));
        assert!(conversation
            .nodes
            .iter()
            .any(|node| node.state == NodeState::Malformed));
        assert!(conversation
            .nodes
            .iter()
            .any(|node| node.state == NodeState::Partial));
        let tool_use = conversation
            .nodes
            .iter()
            .flat_map(|node| &node.content_parts)
            .find(|part| part.kind == ContentKind::ToolUse)
            .expect("tool use");
        let tool_result = conversation
            .nodes
            .iter()
            .flat_map(|node| &node.content_parts)
            .find(|part| part.kind == ContentKind::ToolResult)
            .expect("tool result");
        assert_eq!(
            tool_result.tool_use_id.as_deref(),
            Some(tool_use.part_id.as_str())
        );
        assert!(conversation
            .nodes
            .iter()
            .flat_map(|node| &node.content_parts)
            .filter(|part| part.kind == ContentKind::ToolUse)
            .any(
                |part| part.data.as_ref().and_then(|data| data.get("file_path"))
                    == Some(&Value::String("src/importer.rs".into()))
            ));
        assert!(conversation
            .render_selected_transcript()
            .expect("render")
            .contains("cargo test"));
    }

    #[test]
    fn records_retain_exact_line_and_byte_coordinates() {
        let conversation = conversation();
        for record in &conversation.source_records {
            let start = record.byte_start.expect("start") as usize;
            let end = record.byte_end.expect("end") as usize;
            let exact = std::str::from_utf8(&FIXTURE[start..end]).expect("fixture UTF-8");
            assert!(!exact.contains('\n'));
            assert!(serde_json::from_str::<Value>(exact).is_ok() || exact == "{malformed-json");
            assert_eq!(record.line_start, record.line_end);
        }
    }

    #[test]
    fn persisted_chunks_reconstruct_exact_jsonl_records_and_never_split_turns() {
        let directory = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(
            &directory.path().join("ClaudeCode.tessera"),
            "test",
            &KdfParams {
                m_cost_kib: 1024,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .expect("vault");
        let space_id = space::create(&vault, "Claude Code", None).expect("space");
        let source_artifact = artifact::register(
            &vault,
            &space_id,
            "sanitized-session.jsonl",
            "application/x-ndjson",
            Sensitivity::Restricted,
        )
        .expect("source artifact");
        let source_hash = vault
            .blobs()
            .put(vault.dek().expect("dek"), FIXTURE)
            .expect("encrypted source");
        let source_version =
            artifact::record_version(&vault, &source_artifact, &source_hash, FIXTURE.len() as u64)
                .expect("source version");
        let report = ingest(
            &vault,
            &space_id,
            &source_version.id,
            &ClaudeCodeParser::new(Some("sanitized-session.jsonl".into())),
            &IngestionOptions::default(),
        )
        .expect("ingest");
        let item = &report.items[0];
        let metadata = list_conversation_metadata(
            &vault,
            &ConversationMetadataFilter {
                source_product: Some(SourceProduct::ClaudeCode),
                project: Some("tessera-fixture".into()),
                git_branch: Some("feature/import".into()),
                ..ConversationMetadataFilter::default()
            },
        )
        .expect("filter metadata");
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].session_id, "session-sanitized-1");
        let metadata_text: String = vault
            .conn()
            .query_row(
                "SELECT session_id || ' ' || COALESCE(project, '') || ' ' ||
                        COALESCE(repository, '') || ' ' || COALESCE(git_branch, '') || ' ' ||
                        COALESCE(models_json, '')
                 FROM conversation_source_metadata",
                [],
                |row| row.get(0),
            )
            .expect("metadata text");
        assert!(!metadata_text.contains("cargo test"));
        assert!(!metadata_text.contains("test result: ok"));
        let derived_id = item.derived_text_id.as_deref().expect("derived text");
        let artifact_id: String = vault
            .conn()
            .query_row(
                "SELECT av.artifact_id FROM conversations c
                 JOIN artifact_versions av ON av.id = c.artifact_version_id
                 WHERE c.id = ?1",
                [item
                    .persisted_conversation_id
                    .as_deref()
                    .expect("conversation id")],
                |row| row.get(0),
            )
            .expect("conversation artifact");
        artifact::set_state(
            &vault,
            &artifact::ArtifactId(artifact_id.clone()),
            artifact::ArtifactState::Live,
        )
        .expect("promote fixture conversation");
        crate::search::embed_missing(&vault, &TestEmbedder).expect("embed conversation");
        let constraints = RetrievalConstraints {
            sensitivity_ceiling: Sensitivity::Restricted,
            ..RetrievalConstraints::default()
        };
        for query in [
            "cargo test tessera core claude code",
            "sanitized structured error",
            "what happened in the tessera fixture project",
        ] {
            let hits = crate::search::query(&vault, &TestEmbedder, query, &constraints, 3)
                .expect("query conversation");
            assert!(!hits.is_empty(), "no retrieval hit for {query}");
            assert_eq!(hits[0].artifact_id.0, artifact_id);
        }
        let turns = crate::transcript::turns_for_derived(&vault, derived_id).expect("turns");
        let boundaries: BTreeSet<u64> = turns
            .iter()
            .flat_map(|turn| [turn.byte_offset_start, turn.byte_offset_end])
            .collect();
        let chunks = crate::chunk::chunks_of(&vault, derived_id).expect("chunks");
        assert!(!chunks.is_empty());
        for chunk in chunks {
            assert!(boundaries.contains(&chunk.byte_offset_start));
            assert!(boundaries.contains(&chunk.byte_offset_end));
            let citation = citation_for_chunk(&vault, &chunk.id).expect("citation");
            let records =
                reconstruct_cited_source_records(&vault, &citation).expect("exact source records");
            assert!(!records.is_empty());
            for record in records {
                assert_eq!(
                    record.bytes,
                    FIXTURE[record.byte_range.0 as usize..record.byte_range.1 as usize]
                );
            }
        }
        assert_eq!(
            vault
                .blobs()
                .get(vault.dek().expect("dek"), &BlobHash(source_hash.0))
                .expect("raw source"),
            FIXTURE
        );
    }
}
