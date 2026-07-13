//! Source-neutral, branch-preserving conversation normal form.
//!
//! Source parsers must map into this model without flattening alternate
//! branches, executing tool events, or inventing missing content. Persistence
//! and encrypted derivations are layered on this validated in-memory form.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

mod archive_source;
mod chatgpt_export;
mod claude_code;
mod claude_export;
mod ingestion;
mod persistence;

pub use chatgpt_export::ChatgptExportParser;
pub use claude_code::ClaudeCodeParser;
pub use claude_export::ClaudeExportParser;

pub use ingestion::{
    get_ingestion_run, ingest, list_ingestion_runs, CandidateOutcome, ConversationCandidate,
    ConversationSourceParser, IngestionError, IngestionIssue, IngestionItemReport,
    IngestionItemStatus, IngestionOptions, IngestionRunReport, IngestionRunStatus,
};

pub use persistence::{
    citation_for_chunk, citation_for_disclosed_range, list_conversation_metadata,
    load_conversation, persist_archive, persist_archive_selection, rechunk_conversation,
    reconstruct_cited_nodes, reconstruct_cited_source_records, ConversationCitation,
    ConversationMetadata, ConversationMetadataFilter, ConversationPersistenceConfig,
    ConversationPersistenceError, PersistedConversation, ProcessingLocality,
    ReconstructedSourceRecord,
};

pub const SCHEMA_VERSION: &str = "tessera.conversation.v1";
const SCHEMA_SRC: &str = include_str!("../../../spec/conversation-normal-form.schema.json");

#[derive(Debug, Error)]
pub enum ConversationError {
    #[error("conversation JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("conversation schema is invalid: {0}")]
    Schema(String),
    #[error("conversation invariant failed: {0}")]
    Invariant(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConversationArchive {
    pub schema_version: String,
    pub source: SourceIdentity,
    pub conversations: Vec<Conversation>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceIdentity {
    pub product: SourceProduct,
    pub source_hash: String,
    pub parser: ComponentVersion,
    pub normalizer: ComponentVersion,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceProduct {
    ClaudeCode,
    Claude,
    Chatgpt,
}

impl SourceProduct {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude_code",
            Self::Claude => "claude",
            Self::Chatgpt => "chatgpt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentVersion {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Conversation {
    pub conversation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    pub sensitivity: String,
    pub source_records: Vec<SourceRecord>,
    pub nodes: Vec<MessageNode>,
    pub selected_path: Vec<String>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRecord {
    pub record_id: String,
    pub record_index: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_start: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_end: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_start: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_end: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageNode {
    pub node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_node_id: Option<String>,
    pub role: MessageRole,
    pub state: NodeState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub source_record_ids: Vec<String>,
    pub content_parts: Vec<ContentPart>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    User,
    Assistant,
    System,
    Tool,
    Unknown,
}

impl MessageRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::System => "system",
            Self::Tool => "tool",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    Visible,
    Hidden,
    Deleted,
    Partial,
    Compacted,
    Malformed,
    Unsupported,
}

impl NodeState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Visible => "visible",
            Self::Hidden => "hidden",
            Self::Deleted => "deleted",
            Self::Partial => "partial",
            Self::Compacted => "compacted",
            Self::Malformed => "malformed",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentPart {
    pub part_id: String,
    pub kind: ContentKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_use_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment: Option<AttachmentRef>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    Text,
    Code,
    ToolUse,
    ToolResult,
    Attachment,
    File,
    Image,
    Compaction,
    Error,
    Unsupported,
}

impl ContentKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Code => "code",
            Self::ToolUse => "tool_use",
            Self::ToolResult => "tool_result",
            Self::Attachment => "attachment",
            Self::File => "file",
            Self::Image => "image",
            Self::Compaction => "compaction",
            Self::Error => "error",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub attachment_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub preservation: AttachmentState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentState {
    Preserved,
    Missing,
    ExternalUnfetched,
    Unsupported,
}

impl ConversationArchive {
    pub fn from_json(input: &str) -> Result<Self, ConversationError> {
        let value: Value = serde_json::from_str(input)?;
        let schema: Value = serde_json::from_str(SCHEMA_SRC)
            .map_err(|e| ConversationError::Schema(e.to_string()))?;
        let validator = jsonschema::validator_for(&schema)
            .map_err(|e| ConversationError::Schema(e.to_string()))?;
        validator
            .validate(&value)
            .map_err(|e| ConversationError::Schema(e.to_string()))?;
        let archive: Self = serde_json::from_value(value)?;
        archive.validate()?;
        Ok(archive)
    }

    pub fn validate(&self) -> Result<(), ConversationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ConversationError::Invariant(format!(
                "unsupported schema version {}",
                self.schema_version
            )));
        }
        if self.source.source_hash.len() != 64
            || !self
                .source
                .source_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ConversationError::Invariant(
                "source_hash must be 64 hexadecimal characters".into(),
            ));
        }
        let mut ids = BTreeSet::new();
        for conversation in &self.conversations {
            if !ids.insert(&conversation.conversation_id) {
                return Err(ConversationError::Invariant(format!(
                    "duplicate conversation id {}",
                    conversation.conversation_id
                )));
            }
            conversation.validate()?;
        }
        Ok(())
    }
}

impl Conversation {
    pub fn validate(&self) -> Result<(), ConversationError> {
        let record_ids: BTreeSet<&str> = self
            .source_records
            .iter()
            .map(|record| record.record_id.as_str())
            .collect();
        if record_ids.len() != self.source_records.len() {
            return Err(ConversationError::Invariant(format!(
                "{} has duplicate source record ids",
                self.conversation_id
            )));
        }
        let record_indices: BTreeSet<u64> = self
            .source_records
            .iter()
            .map(|record| record.record_index)
            .collect();
        if record_indices.len() != self.source_records.len() {
            return Err(ConversationError::Invariant(format!(
                "{} has duplicate source record indices",
                self.conversation_id
            )));
        }
        for record in &self.source_records {
            if record
                .byte_start
                .zip(record.byte_end)
                .is_some_and(|(a, b)| a > b)
                || record
                    .line_start
                    .zip(record.line_end)
                    .is_some_and(|(a, b)| a > b)
            {
                return Err(ConversationError::Invariant(format!(
                    "source record {} has a reversed range",
                    record.record_id
                )));
            }
        }

        let nodes: BTreeMap<&str, &MessageNode> = self
            .nodes
            .iter()
            .map(|node| (node.node_id.as_str(), node))
            .collect();
        if nodes.len() != self.nodes.len() {
            return Err(ConversationError::Invariant(format!(
                "{} has duplicate node ids",
                self.conversation_id
            )));
        }
        let mut part_ids = BTreeSet::new();
        let mut part_locations = BTreeMap::new();
        for node in &self.nodes {
            if node.parent_node_id.as_deref() == Some(node.node_id.as_str()) {
                return Err(ConversationError::Invariant(format!(
                    "node {} is its own parent",
                    node.node_id
                )));
            }
            if node
                .parent_node_id
                .as_deref()
                .is_some_and(|parent| !nodes.contains_key(parent))
            {
                return Err(ConversationError::Invariant(format!(
                    "node {} has an unknown parent",
                    node.node_id
                )));
            }
            if node.source_record_ids.is_empty()
                || node
                    .source_record_ids
                    .iter()
                    .any(|id| !record_ids.contains(id.as_str()))
            {
                return Err(ConversationError::Invariant(format!(
                    "node {} has missing or unknown source records",
                    node.node_id
                )));
            }
            for (part_index, part) in node.content_parts.iter().enumerate() {
                if !part_ids.insert(part.part_id.as_str()) {
                    return Err(ConversationError::Invariant(format!(
                        "duplicate content part id {}",
                        part.part_id
                    )));
                }
                part_locations.insert(
                    part.part_id.as_str(),
                    (node.node_id.as_str(), part_index, part.kind),
                );
                part.validate()?;
            }
        }
        for node in &self.nodes {
            for (part_index, part) in node.content_parts.iter().enumerate() {
                if part.kind == ContentKind::ToolResult {
                    let use_id = part.tool_use_id.as_deref().ok_or_else(|| {
                        ConversationError::Invariant(format!(
                            "tool result {} has no matching tool use",
                            part.part_id
                        ))
                    })?;
                    let (use_node, use_index, use_kind) =
                        part_locations.get(use_id).copied().ok_or_else(|| {
                            ConversationError::Invariant(format!(
                                "tool result {} has no matching tool use",
                                part.part_id
                            ))
                        })?;
                    if use_kind != ContentKind::ToolUse
                        || (use_node == node.node_id && use_index >= part_index)
                        || (use_node != node.node_id
                            && !is_ancestor(use_node, &node.node_id, &nodes))
                    {
                        return Err(ConversationError::Invariant(format!(
                            "tool result {} references a tool use outside its prior branch",
                            part.part_id
                        )));
                    }
                }
            }
            let mut seen = BTreeSet::new();
            let mut current = Some(node.node_id.as_str());
            while let Some(id) = current {
                if !seen.insert(id) {
                    return Err(ConversationError::Invariant(format!(
                        "cycle reaches node {}",
                        node.node_id
                    )));
                }
                current = nodes
                    .get(id)
                    .and_then(|item| item.parent_node_id.as_deref());
            }
        }
        if self.selected_path.is_empty() {
            return Err(ConversationError::Invariant(
                "selected_path must identify one explicit branch".into(),
            ));
        }
        for (index, id) in self.selected_path.iter().enumerate() {
            let node = nodes.get(id.as_str()).ok_or_else(|| {
                ConversationError::Invariant(format!("selected path contains unknown node {id}"))
            })?;
            let expected_parent = index
                .checked_sub(1)
                .map(|prior| self.selected_path[prior].as_str());
            if node.parent_node_id.as_deref() != expected_parent {
                return Err(ConversationError::Invariant(format!(
                    "selected path is not contiguous at node {id}"
                )));
            }
        }
        Ok(())
    }

    /// Deterministically render only the explicitly selected branch.
    pub fn render_selected_transcript(&self) -> Result<String, ConversationError> {
        Ok(self.render_with_spans()?.text)
    }

    fn render_with_spans(&self) -> Result<RenderedConversation, ConversationError> {
        self.validate()?;
        let nodes: BTreeMap<&str, &MessageNode> = self
            .nodes
            .iter()
            .map(|node| (node.node_id.as_str(), node))
            .collect();
        let mut output = String::new();
        let mut node_spans = Vec::with_capacity(self.selected_path.len());
        let mut part_spans = Vec::new();
        for id in &self.selected_path {
            let node = nodes[id.as_str()];
            let node_start = output.len();
            output.push_str(&format!(
                "[{} {} {}]\n",
                node.role.as_str(),
                node.node_id,
                node.state.as_str()
            ));
            for part in &node.content_parts {
                let part_start = output.len();
                output.push_str(&format!("<{}:{}>\n", part.kind.as_str(), part.part_id));
                if let Some(text) = &part.text {
                    output.push_str(text);
                    output.push('\n');
                } else if let Some(data) = &part.data {
                    output.push_str(&serde_json::to_string(data)?);
                    output.push('\n');
                } else if let Some(attachment) = &part.attachment {
                    output.push_str(&format!(
                        "[attachment {} {:?}]\n",
                        attachment.attachment_id, attachment.preservation
                    ));
                }
                part_spans.push(RenderedPartSpan {
                    node_id: node.node_id.clone(),
                    part_id: part.part_id.clone(),
                    start: part_start as u64,
                    end: output.len() as u64,
                });
            }
            node_spans.push(RenderedNodeSpan {
                node_id: node.node_id.clone(),
                start: node_start as u64,
                end: output.len() as u64,
            });
        }
        Ok(RenderedConversation {
            text: output,
            node_spans,
            part_spans,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RenderedConversation {
    text: String,
    node_spans: Vec<RenderedNodeSpan>,
    part_spans: Vec<RenderedPartSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RenderedNodeSpan {
    node_id: String,
    start: u64,
    end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RenderedPartSpan {
    node_id: String,
    part_id: String,
    start: u64,
    end: u64,
}

fn is_ancestor(candidate: &str, node_id: &str, nodes: &BTreeMap<&str, &MessageNode>) -> bool {
    let mut current = nodes
        .get(node_id)
        .and_then(|node| node.parent_node_id.as_deref());
    while let Some(id) = current {
        if id == candidate {
            return true;
        }
        current = nodes
            .get(id)
            .and_then(|node| node.parent_node_id.as_deref());
    }
    false
}

impl ContentPart {
    fn validate(&self) -> Result<(), ConversationError> {
        match self.kind {
            ContentKind::Text
            | ContentKind::Code
            | ContentKind::Compaction
            | ContentKind::Error
                if self.text.is_none() =>
            {
                Err(ConversationError::Invariant(format!(
                    "content part {} requires text",
                    self.part_id
                )))
            }
            ContentKind::ToolUse if self.tool_name.is_none() || self.data.is_none() => {
                Err(ConversationError::Invariant(format!(
                    "tool use {} requires tool_name and data",
                    self.part_id
                )))
            }
            ContentKind::ToolResult if self.tool_use_id.is_none() => {
                Err(ConversationError::Invariant(format!(
                    "tool result {} requires tool_use_id",
                    self.part_id
                )))
            }
            ContentKind::Attachment | ContentKind::File | ContentKind::Image
                if self.attachment.is_none() =>
            {
                Err(ConversationError::Invariant(format!(
                    "attachment part {} requires attachment metadata",
                    self.part_id
                )))
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../../tests/fixtures/conversation-tree.json");

    #[test]
    fn structural_fixture_validates_and_selected_render_excludes_alternate_branch() {
        let archive = ConversationArchive::from_json(FIXTURE).expect("fixture");
        let rendered = archive.conversations[0]
            .render_selected_transcript()
            .expect("render");
        assert!(rendered.contains("selected answer"));
        assert!(rendered.contains("tool_result"));
        assert!(rendered.contains("compacted context"));
        assert!(!rendered.contains("alternate answer must stay separate"));
    }

    #[test]
    fn orphan_cycle_bad_tool_pair_and_noncontiguous_selection_fail_closed() {
        let archive = ConversationArchive::from_json(FIXTURE).expect("fixture");
        let mut orphan = archive.clone();
        orphan.conversations[0].nodes[1].parent_node_id = Some("node_missing".into());
        assert!(orphan.validate().is_err());

        let mut cycle = archive.clone();
        cycle.conversations[0].nodes[0].parent_node_id = Some("node_selected".into());
        assert!(cycle.validate().is_err());

        let mut bad_tool = archive.clone();
        let result = bad_tool.conversations[0]
            .nodes
            .iter_mut()
            .flat_map(|node| node.content_parts.iter_mut())
            .find(|part| part.kind == ContentKind::ToolResult)
            .expect("tool result");
        result.tool_use_id = Some("part_missing".into());
        assert!(bad_tool.validate().is_err());

        let mut cross_branch = ConversationArchive::from_json(FIXTURE).expect("fixture");
        let alternate = cross_branch.conversations[0]
            .nodes
            .iter_mut()
            .find(|node| node.node_id == "node_alternate")
            .expect("alternate");
        alternate.content_parts.push(ContentPart {
            part_id: "part_alternate_tool".into(),
            kind: ContentKind::ToolUse,
            text: None,
            language: None,
            tool_name: Some("read_file".into()),
            tool_use_id: None,
            data: Some(serde_json::json!({"path":"alternate"})),
            attachment: None,
            extensions: BTreeMap::new(),
        });
        let result = cross_branch.conversations[0]
            .nodes
            .iter_mut()
            .flat_map(|node| node.content_parts.iter_mut())
            .find(|part| part.kind == ContentKind::ToolResult)
            .expect("tool result");
        result.tool_use_id = Some("part_alternate_tool".into());
        assert!(cross_branch.validate().is_err());

        let mut duplicate_record = ConversationArchive::from_json(FIXTURE).expect("fixture");
        duplicate_record.conversations[0].source_records[1].record_index = 0;
        assert!(duplicate_record.validate().is_err());

        let mut branch_jump = archive;
        branch_jump.conversations[0].selected_path =
            vec!["node_root".into(), "node_alternate".into()];
        assert!(branch_jump.validate().is_err());
    }
}
