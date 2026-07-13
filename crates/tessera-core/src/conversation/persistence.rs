//! Encrypted persistence and exact chunk citations for conversation archives.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    AttachmentState, ComponentVersion, Conversation, ConversationArchive, ConversationError,
    MessageNode, RenderedConversation, SourceIdentity, SourceProduct,
};
use crate::artifact::ArtifactId;
use crate::blob::{BlobError, BlobHash};
use crate::chunk::{Chunk, ChunkError, ChunkParams};
use crate::space::SpaceId;
use crate::vault::{Vault, VaultError};

const MEDIA_TYPE: &str = "application/vnd.tessera.conversation+json";

#[derive(Debug, Error)]
pub enum ConversationPersistenceError {
    #[error("conversation error: {0}")]
    Conversation(#[from] ConversationError),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("blob error: {0}")]
    Blob(#[from] BlobError),
    #[error("chunk error: {0}")]
    Chunk(#[from] ChunkError),
    #[error("transcript error: {0}")]
    Transcript(#[from] crate::transcript::TranscriptError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("conversation persistence JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("source artifact version not found: {0}")]
    SourceArtifactVersionNotFound(String),
    #[error("target space not found: {0}")]
    SpaceNotFound(String),
    #[error("source hash {declared} does not match encrypted artifact blob {actual}")]
    SourceHashMismatch { declared: String, actual: String },
    #[error("conversation archive was already persisted: {0}")]
    AlreadyPersisted(String),
    #[error("conversation not found: {0}")]
    ConversationNotFound(String),
    #[error("conversation chunk mapping not found or range invalid: {0}")]
    CitationNotFound(String),
    #[error("conversation persistence invariant failed: {0}")]
    Invariant(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingLocality {
    Local,
    Cloud,
}

impl ProcessingLocality {
    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Cloud => "cloud",
        }
    }

    fn parse(value: &str) -> Result<Self, ConversationPersistenceError> {
        match value {
            "local" => Ok(Self::Local),
            "cloud" => Ok(Self::Cloud),
            other => Err(ConversationPersistenceError::Invariant(format!(
                "unknown processing locality {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConversationPersistenceConfig {
    pub renderer: ComponentVersion,
    pub chunker: ComponentVersion,
    pub chunk_params: ChunkParams,
    pub locality: ProcessingLocality,
}

impl Default for ConversationPersistenceConfig {
    fn default() -> Self {
        Self {
            renderer: ComponentVersion {
                name: "tessera-conversation-renderer".into(),
                version: "1".into(),
            },
            chunker: ComponentVersion {
                name: "tessera-turn-chunker".into(),
                version: "1".into(),
            },
            chunk_params: ChunkParams::default(),
            locality: ProcessingLocality::Local,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedConversation {
    pub id: String,
    pub source_conversation_id: String,
    pub artifact_id: ArtifactId,
    pub artifact_version_id: String,
    pub derived_text_id: String,
    pub chunk_ids: Vec<String>,
    pub canonical_hash: String,
    pub normalized_hash: String,
    pub derivation_hash: String,
}

/// Content-free citation metadata suitable for attaching to a retrieval hit.
/// Exact messages are available only through [`reconstruct_cited_nodes`], so
/// the disclosure layer cannot accidentally smuggle an entire message through
/// an excerpt citation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConversationCitation {
    pub chunk_id: String,
    pub persisted_conversation_id: String,
    pub source_product: SourceProduct,
    pub source_hash: String,
    pub source_export_id: Option<String>,
    pub source_artifact_version_id: String,
    pub source_conversation_id: String,
    pub branch_path: Vec<String>,
    pub branch_endpoint_node_id: String,
    pub first_node_id: String,
    pub last_node_id: String,
    pub node_ids: Vec<String>,
    pub content_part_ids: Vec<String>,
    pub source_record_ids: Vec<String>,
    pub normalized_byte_range: (u64, u64),
    pub source_timestamp_range: Option<(String, String)>,
    pub artifact_version_id: String,
    pub canonical_hash: String,
    pub normalized_hash: String,
    pub derivation_hash: String,
    pub parser: ComponentVersion,
    pub normalizer: ComponentVersion,
    pub renderer: ComponentVersion,
    pub chunker: ComponentVersion,
    pub locality: ProcessingLocality,
    pub processed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConversationEnvelope {
    schema_version: String,
    source: SourceIdentity,
    conversation: Conversation,
}

struct PreparedConversation {
    id: String,
    artifact_id: ArtifactId,
    artifact_version_id: String,
    canonical_hash: String,
    envelope: ConversationEnvelope,
    rendered: RenderedConversation,
    normalized_hash: String,
}

/// Persist a validated archive against its immutable encrypted source export.
/// Each conversation becomes a separate pending artifact, which makes the
/// existing quarantine and lens sensitivity checks apply without exceptions.
pub fn persist_archive(
    vault: &Vault,
    space_id: &SpaceId,
    source_artifact_version_id: &str,
    archive: &ConversationArchive,
    config: &ConversationPersistenceConfig,
) -> Result<Vec<PersistedConversation>, ConversationPersistenceError> {
    archive.validate()?;
    validate_config(config)?;

    let space_exists: bool = vault.conn().query_row(
        "SELECT EXISTS(SELECT 1 FROM spaces WHERE id = ?1)",
        [&space_id.0],
        |row| row.get(0),
    )?;
    if !space_exists {
        return Err(ConversationPersistenceError::SpaceNotFound(
            space_id.0.clone(),
        ));
    }

    let source_blob_hash = vault
        .conn()
        .query_row(
            "SELECT blob_hash FROM artifact_versions WHERE id = ?1",
            [source_artifact_version_id],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                ConversationPersistenceError::SourceArtifactVersionNotFound(
                    source_artifact_version_id.to_owned(),
                )
            }
            other => ConversationPersistenceError::Database(other),
        })?;
    if source_blob_hash != archive.source.source_hash {
        return Err(ConversationPersistenceError::SourceHashMismatch {
            declared: archive.source.source_hash.clone(),
            actual: source_blob_hash,
        });
    }
    // The row/hash match is not enough: authenticate the immutable source
    // ciphertext before committing any provenance derived from it.
    vault
        .blobs()
        .get(vault.dek()?, &BlobHash(source_blob_hash))?;

    let archive_id = stable_id(
        "carch",
        &[
            &archive.source.source_hash,
            &archive.schema_version,
            &archive.source.parser.name,
            &archive.source.parser.version,
            &archive.source.normalizer.name,
            &archive.source.normalizer.version,
        ],
    );
    let exists: bool = vault.conn().query_row(
        "SELECT EXISTS(SELECT 1 FROM conversation_archives WHERE id = ?1)",
        [&archive_id],
        |row| row.get(0),
    )?;
    if exists {
        return Err(ConversationPersistenceError::AlreadyPersisted(archive_id));
    }

    let archive_bytes = serde_json::to_vec(archive)?;
    let normal_form_hash = vault.blobs().put(vault.dek()?, &archive_bytes)?.0;
    let mut prepared = Vec::with_capacity(archive.conversations.len());
    for conversation in &archive.conversations {
        let id = stable_id("conv", &[&archive_id, &conversation.conversation_id]);
        let artifact_id = ArtifactId(stable_id("art", &[&id]));
        let envelope = ConversationEnvelope {
            schema_version: archive.schema_version.clone(),
            source: archive.source.clone(),
            conversation: conversation.clone(),
        };
        let canonical_bytes = serde_json::to_vec(&envelope)?;
        let canonical_hash = vault.blobs().put(vault.dek()?, &canonical_bytes)?.0;
        let artifact_version_id = stable_id("artv", &[&artifact_id.0, &canonical_hash]);
        let rendered = conversation.render_with_spans()?;
        let normalized_hash = vault.blobs().put(vault.dek()?, rendered.text.as_bytes())?.0;
        prepared.push(PreparedConversation {
            id,
            artifact_id,
            artifact_version_id,
            canonical_hash,
            envelope,
            rendered,
            normalized_hash,
        });
    }

    vault.conn().execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| {
        let now = chrono::Utc::now().to_rfc3339();
        vault.conn().execute(
            "INSERT INTO conversation_archives
             (id, source_artifact_version_id, schema_version, source_product, source_hash,
              normal_form_blob_hash, parser_name, parser_version, normalizer_name,
              normalizer_version, locality, processed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                archive_id,
                source_artifact_version_id,
                archive.schema_version,
                source_product_str(archive.source.product),
                archive.source.source_hash,
                normal_form_hash,
                archive.source.parser.name,
                archive.source.parser.version,
                archive.source.normalizer.name,
                archive.source.normalizer.version,
                config.locality.as_str(),
                now,
            ],
        )?;

        let mut persisted = Vec::with_capacity(prepared.len());
        for item in &prepared {
            let conversation = &item.envelope.conversation;
            let filename = format!("conversation-{}.json", &item.canonical_hash[..16]);
            vault.conn().execute(
                "INSERT INTO artifacts
                 (id, space_id, filename, media_type, sensitivity, state, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?6)",
                rusqlite::params![
                    item.artifact_id.0,
                    space_id.0,
                    filename,
                    MEDIA_TYPE,
                    conversation.sensitivity,
                    now,
                ],
            )?;
            vault.conn().execute(
                "INSERT INTO artifact_versions
                 (id, artifact_id, version, blob_hash, size_bytes, created_at)
                 VALUES (?1, ?2, 1, ?3, ?4, ?5)",
                rusqlite::params![
                    item.artifact_version_id,
                    item.artifact_id.0,
                    item.canonical_hash,
                    serde_json::to_vec(&item.envelope)?.len() as i64,
                    now,
                ],
            )?;
            vault.conn().execute(
                "INSERT INTO conversations
                 (id, archive_id, artifact_version_id, source_conversation_id,
                  source_created_at, source_updated_at, selected_branch_endpoint_id,
                  canonical_hash, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    item.id,
                    archive_id,
                    item.artifact_version_id,
                    conversation.conversation_id,
                    conversation.created_at,
                    conversation.updated_at,
                    conversation.selected_path.last().expect("validated path"),
                    item.canonical_hash,
                    now,
                ],
            )?;
            persist_source_graph(vault, &item.id, conversation)?;
            let derivation = create_derivation(vault, item, config, &now)?;
            persisted.push(derivation);
        }
        Ok::<_, ConversationPersistenceError>(persisted)
    })();

    match result {
        Ok(persisted) => {
            if let Err(error) = vault.conn().execute_batch("COMMIT") {
                let _ = vault.conn().execute_batch("ROLLBACK");
                Err(error.into())
            } else {
                Ok(persisted)
            }
        }
        Err(error) => {
            let _ = vault.conn().execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

/// Produce another rendering/chunk derivation for an already-persisted
/// conversation. A changed chunker/config creates new derived and chunk ids;
/// source conversation/node/part/record ids remain untouched.
pub fn rechunk_conversation(
    vault: &Vault,
    conversation_id: &str,
    config: &ConversationPersistenceConfig,
) -> Result<PersistedConversation, ConversationPersistenceError> {
    validate_config(config)?;
    let (artifact_id, artifact_version_id, canonical_hash): (String, String, String) = vault
        .conn()
        .query_row(
            "SELECT av.artifact_id, c.artifact_version_id, c.canonical_hash
             FROM conversations c JOIN artifact_versions av ON av.id = c.artifact_version_id
             WHERE c.id = ?1",
            [conversation_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                ConversationPersistenceError::ConversationNotFound(conversation_id.to_owned())
            }
            other => ConversationPersistenceError::Database(other),
        })?;
    let envelope = load_envelope(vault, conversation_id)?;
    let rendered = envelope.conversation.render_with_spans()?;
    let normalized_hash = vault.blobs().put(vault.dek()?, rendered.text.as_bytes())?.0;
    let prepared = PreparedConversation {
        id: conversation_id.to_owned(),
        artifact_id: ArtifactId(artifact_id),
        artifact_version_id,
        canonical_hash,
        envelope,
        rendered,
        normalized_hash,
    };

    vault.conn().execute_batch("BEGIN IMMEDIATE")?;
    let now = chrono::Utc::now().to_rfc3339();
    let result = create_derivation(vault, &prepared, config, &now);
    match result {
        Ok(persisted) => {
            if let Err(error) = vault.conn().execute_batch("COMMIT") {
                let _ = vault.conn().execute_batch("ROLLBACK");
                Err(error.into())
            } else {
                Ok(persisted)
            }
        }
        Err(error) => {
            let _ = vault.conn().execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

pub fn load_conversation(
    vault: &Vault,
    conversation_id: &str,
) -> Result<Conversation, ConversationPersistenceError> {
    Ok(load_envelope(vault, conversation_id)?.conversation)
}

pub fn citation_for_chunk(
    vault: &Vault,
    chunk_id: &str,
) -> Result<ConversationCitation, ConversationPersistenceError> {
    let range = vault
        .conn()
        .query_row(
            "SELECT byte_offset_start, byte_offset_end FROM chunks WHERE id = ?1",
            [chunk_id],
            |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                ConversationPersistenceError::CitationNotFound(chunk_id.to_owned())
            }
            other => ConversationPersistenceError::Database(other),
        })?;
    citation_for_disclosed_range(vault, chunk_id, range.0, range.1)
}

/// Resolve exact provenance for an absolute `[start, end)` range inside one
/// conversation chunk. The returned citation is metadata-only.
pub fn citation_for_disclosed_range(
    vault: &Vault,
    chunk_id: &str,
    start: u64,
    end: u64,
) -> Result<ConversationCitation, ConversationPersistenceError> {
    let meta = citation_meta(vault, chunk_id)?;
    if start >= end || start < meta.chunk_start || end > meta.chunk_end {
        return Err(ConversationPersistenceError::CitationNotFound(format!(
            "{chunk_id}:{start}..{end}"
        )));
    }
    let node_ids = overlapping_source_ids(vault, &meta.derivation_id, start, end, false)?;
    if node_ids.is_empty() {
        return Err(ConversationPersistenceError::Invariant(format!(
            "range {start}..{end} maps to no conversation node"
        )));
    }
    let content_part_ids = overlapping_source_ids(vault, &meta.derivation_id, start, end, true)?;
    let envelope = load_envelope(vault, &meta.conversation_id)?;
    let wanted: BTreeSet<&str> = node_ids.iter().map(String::as_str).collect();
    let referenced_record_ids: BTreeSet<&str> = envelope
        .conversation
        .nodes
        .iter()
        .filter(|node| wanted.contains(node.node_id.as_str()))
        .flat_map(|node| node.source_record_ids.iter().map(String::as_str))
        .collect();
    let source_record_ids = envelope
        .conversation
        .source_records
        .iter()
        .filter(|record| referenced_record_ids.contains(record.record_id.as_str()))
        .map(|record| record.record_id.clone())
        .collect();
    let timestamp_range = source_timestamp_range(&envelope.conversation, &wanted);

    Ok(ConversationCitation {
        chunk_id: chunk_id.to_owned(),
        persisted_conversation_id: meta.conversation_id,
        source_product: envelope.source.product,
        source_hash: envelope.source.source_hash,
        source_export_id: envelope.source.export_id,
        source_artifact_version_id: meta.source_artifact_version_id,
        source_conversation_id: envelope.conversation.conversation_id,
        branch_path: envelope.conversation.selected_path,
        branch_endpoint_node_id: meta.branch_endpoint_node_id,
        first_node_id: node_ids.first().expect("non-empty").clone(),
        last_node_id: node_ids.last().expect("non-empty").clone(),
        node_ids,
        content_part_ids,
        source_record_ids,
        normalized_byte_range: (start, end),
        source_timestamp_range: timestamp_range,
        artifact_version_id: meta.artifact_version_id,
        canonical_hash: meta.canonical_hash,
        normalized_hash: meta.normalized_hash,
        derivation_hash: meta.derivation_hash,
        parser: meta.parser,
        normalizer: meta.normalizer,
        renderer: meta.renderer,
        chunker: meta.chunker,
        locality: meta.locality,
        processed_at: meta.processed_at,
    })
}

/// Owner/unlocked-vault reconstruction path for the exact messages named by a
/// citation. This is deliberately separate from content-free retrieval
/// metadata and does not bypass the disclosure layer on its own.
pub fn reconstruct_cited_nodes(
    vault: &Vault,
    citation: &ConversationCitation,
) -> Result<Vec<MessageNode>, ConversationPersistenceError> {
    let conversation = load_conversation(vault, &citation.persisted_conversation_id)?;
    let by_id: BTreeMap<&str, &MessageNode> = conversation
        .nodes
        .iter()
        .map(|node| (node.node_id.as_str(), node))
        .collect();
    citation
        .node_ids
        .iter()
        .map(|id| {
            by_id.get(id.as_str()).cloned().cloned().ok_or_else(|| {
                ConversationPersistenceError::Invariant(format!(
                    "citation references missing node {id}"
                ))
            })
        })
        .collect()
}

fn persist_source_graph(
    vault: &Vault,
    conversation_id: &str,
    conversation: &Conversation,
) -> Result<(), ConversationPersistenceError> {
    let selected: BTreeMap<&str, usize> = conversation
        .selected_path
        .iter()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index))
        .collect();
    let record_ids: BTreeMap<&str, String> = conversation
        .source_records
        .iter()
        .map(|record| {
            (
                record.record_id.as_str(),
                stable_id("crec", &[conversation_id, &record.record_id]),
            )
        })
        .collect();
    let node_ids: BTreeMap<&str, String> = conversation
        .nodes
        .iter()
        .map(|node| {
            (
                node.node_id.as_str(),
                stable_id("cnode", &[conversation_id, &node.node_id]),
            )
        })
        .collect();
    let part_ids: BTreeMap<&str, String> = conversation
        .nodes
        .iter()
        .flat_map(|node| &node.content_parts)
        .map(|part| {
            (
                part.part_id.as_str(),
                stable_id("cpart", &[conversation_id, &part.part_id]),
            )
        })
        .collect();

    for record in &conversation.source_records {
        vault.conn().execute(
            "INSERT INTO conversation_source_records
             (id, conversation_id, source_record_id, record_index, source_id,
              byte_start, byte_end, line_start, line_end)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                record_ids[record.record_id.as_str()],
                conversation_id,
                record.record_id,
                record.record_index as i64,
                record.source_id,
                record.byte_start.map(|value| value as i64),
                record.byte_end.map(|value| value as i64),
                record.line_start.map(|value| value as i64),
                record.line_end.map(|value| value as i64),
            ],
        )?;
    }
    for node in &conversation.nodes {
        vault.conn().execute(
            "INSERT INTO conversation_nodes
             (id, conversation_id, source_node_id, parent_id, role, source_state,
              source_timestamp, selected_order)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                node_ids[node.node_id.as_str()],
                conversation_id,
                node.node_id,
                node.parent_node_id
                    .as_deref()
                    .map(|parent| node_ids[parent].as_str()),
                node.role.as_str(),
                node.state.as_str(),
                node.timestamp,
                selected
                    .get(node.node_id.as_str())
                    .map(|index| *index as i64),
            ],
        )?;
        for record_id in &node.source_record_ids {
            vault.conn().execute(
                "INSERT INTO conversation_node_source_records (node_id, source_record_id)
                 VALUES (?1, ?2)",
                rusqlite::params![
                    node_ids[node.node_id.as_str()],
                    record_ids[record_id.as_str()],
                ],
            )?;
        }
    }
    for node in &conversation.nodes {
        for (index, part) in node.content_parts.iter().enumerate() {
            let (attachment_id, attachment_state, attachment_hash) = part
                .attachment
                .as_ref()
                .map(|attachment| {
                    (
                        Some(attachment.attachment_id.as_str()),
                        Some(attachment_state_str(attachment.preservation)),
                        attachment.content_hash.as_deref(),
                    )
                })
                .unwrap_or((None, None, None));
            vault.conn().execute(
                "INSERT INTO conversation_content_parts
                 (id, node_id, source_part_id, part_index, kind, tool_use_part_id,
                  attachment_id, attachment_state, attachment_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    part_ids[part.part_id.as_str()],
                    node_ids[node.node_id.as_str()],
                    part.part_id,
                    index as i64,
                    part.kind.as_str(),
                    part.tool_use_id
                        .as_deref()
                        .map(|source_id| part_ids[source_id].as_str()),
                    attachment_id,
                    attachment_state,
                    attachment_hash,
                ],
            )?;
        }
    }
    Ok(())
}

fn create_derivation(
    vault: &Vault,
    item: &PreparedConversation,
    config: &ConversationPersistenceConfig,
    now: &str,
) -> Result<PersistedConversation, ConversationPersistenceError> {
    let derivation_hash = stable_digest(&[
        &item.id,
        &item.normalized_hash,
        &config.renderer.name,
        &config.renderer.version,
        &config.chunker.name,
        &config.chunker.version,
        &config.chunk_params.target_tokens.to_string(),
        &config.chunk_params.overlap_tokens.to_string(),
        config.locality.as_str(),
    ]);
    let derivation_id = stable_id("cder", &[&item.id, &derivation_hash]);
    let derived_text_id = stable_id("dt", &[&item.artifact_version_id, &derivation_hash]);
    let extractor_version = format!(
        "{};chunker={}:{};target={};overlap={}",
        config.renderer.version,
        config.chunker.name,
        config.chunker.version,
        config.chunk_params.target_tokens,
        config.chunk_params.overlap_tokens
    );
    vault.conn().execute(
        "INSERT INTO derived_text
         (id, artifact_version_id, blob_hash, extractor, extractor_version, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            derived_text_id,
            item.artifact_version_id,
            item.normalized_hash,
            config.renderer.name,
            extractor_version,
            now,
        ],
    )?;
    vault.conn().execute(
        "INSERT OR IGNORE INTO provenance
         (id, derived_blob_hash, source_artifact_version_id, tool, tool_version,
          locality, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            stable_id("prov", &[&derivation_hash]),
            item.normalized_hash,
            item.artifact_version_id,
            config.renderer.name,
            config.renderer.version,
            config.locality.as_str(),
            now,
        ],
    )?;
    vault.conn().execute(
        "INSERT INTO conversation_derivations
         (id, conversation_id, derived_text_id, normalized_blob_hash, derivation_hash,
          renderer_name, renderer_version, chunker_name, chunker_version,
          target_tokens, overlap_tokens, locality, processed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        rusqlite::params![
            derivation_id,
            item.id,
            derived_text_id,
            item.normalized_hash,
            derivation_hash,
            config.renderer.name,
            config.renderer.version,
            config.chunker.name,
            config.chunker.version,
            config.chunk_params.target_tokens as i64,
            config.chunk_params.overlap_tokens as i64,
            config.locality.as_str(),
            now,
        ],
    )?;

    let node_ids = persisted_node_ids(vault, &item.id)?;
    let part_ids = persisted_part_ids(vault, &item.id)?;
    for span in &item.rendered.node_spans {
        vault.conn().execute(
            "INSERT INTO conversation_spans
             (id, derivation_id, node_id, part_id, byte_offset_start, byte_offset_end)
             VALUES (?1, ?2, ?3, NULL, ?4, ?5)",
            rusqlite::params![
                stable_id("cspan", &[&derivation_id, &span.node_id, "node"]),
                derivation_id,
                node_ids[span.node_id.as_str()],
                span.start as i64,
                span.end as i64,
            ],
        )?;
    }
    for span in &item.rendered.part_spans {
        vault.conn().execute(
            "INSERT INTO conversation_spans
             (id, derivation_id, node_id, part_id, byte_offset_start, byte_offset_end)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                stable_id("cspan", &[&derivation_id, &span.part_id, "part"]),
                derivation_id,
                node_ids[span.node_id.as_str()],
                part_ids[span.part_id.as_str()],
                span.start as i64,
                span.end as i64,
            ],
        )?;
    }
    let turns: Vec<crate::transcript::TranscriptTurn> = item
        .rendered
        .node_spans
        .iter()
        .enumerate()
        .map(|(index, span)| crate::transcript::TranscriptTurn {
            turn_index: index as u32,
            byte_offset_start: span.start,
            byte_offset_end: span.end,
            speaker: None,
            timestamp: None,
        })
        .collect();
    crate::transcript::persist_turns(vault, &derived_text_id, &turns)?;
    let derived = crate::extract::DerivedText {
        id: derived_text_id.clone(),
        artifact_version_id: item.artifact_version_id.clone(),
        blob_hash: item.normalized_hash.clone(),
        extractor: config.renderer.name.clone(),
        extractor_version,
    };
    let chunks = crate::chunk::chunk_derived_text(vault, &derived, &config.chunk_params)?;
    map_chunks(
        vault,
        &derivation_id,
        &item.envelope.conversation,
        &item.rendered,
        &node_ids,
        &chunks,
        now,
    )?;

    Ok(PersistedConversation {
        id: item.id.clone(),
        source_conversation_id: item.envelope.conversation.conversation_id.clone(),
        artifact_id: item.artifact_id.clone(),
        artifact_version_id: item.artifact_version_id.clone(),
        derived_text_id,
        chunk_ids: chunks.into_iter().map(|chunk| chunk.id).collect(),
        canonical_hash: item.canonical_hash.clone(),
        normalized_hash: item.normalized_hash.clone(),
        derivation_hash,
    })
}

fn map_chunks(
    vault: &Vault,
    derivation_id: &str,
    conversation: &Conversation,
    rendered: &RenderedConversation,
    node_ids: &BTreeMap<String, String>,
    chunks: &[Chunk],
    now: &str,
) -> Result<(), ConversationPersistenceError> {
    let endpoint = conversation.selected_path.last().expect("validated path");
    for chunk in chunks {
        let overlaps: Vec<_> = rendered
            .node_spans
            .iter()
            .filter(|span| span.end > chunk.byte_offset_start && span.start < chunk.byte_offset_end)
            .collect();
        let first = overlaps.first().ok_or_else(|| {
            ConversationPersistenceError::Invariant(format!(
                "chunk {} overlaps no conversation node",
                chunk.id
            ))
        })?;
        let last = overlaps.last().expect("non-empty");
        vault.conn().execute(
            "INSERT INTO conversation_chunk_map
             (chunk_id, derivation_id, first_node_id, last_node_id,
              branch_endpoint_node_id, mapped_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                chunk.id,
                derivation_id,
                node_ids[first.node_id.as_str()],
                node_ids[last.node_id.as_str()],
                node_ids[endpoint.as_str()],
                now,
            ],
        )?;
    }
    Ok(())
}

fn load_envelope(
    vault: &Vault,
    conversation_id: &str,
) -> Result<ConversationEnvelope, ConversationPersistenceError> {
    let (blob_hash, canonical_hash): (String, String) = vault
        .conn()
        .query_row(
            "SELECT av.blob_hash, c.canonical_hash FROM conversations c
             JOIN artifact_versions av ON av.id = c.artifact_version_id
             WHERE c.id = ?1",
            [conversation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                ConversationPersistenceError::ConversationNotFound(conversation_id.to_owned())
            }
            other => ConversationPersistenceError::Database(other),
        })?;
    if blob_hash != canonical_hash {
        return Err(ConversationPersistenceError::Invariant(format!(
            "conversation {conversation_id} canonical hash does not match its artifact version"
        )));
    }
    let bytes = vault.blobs().get(vault.dek()?, &BlobHash(blob_hash))?;
    let envelope: ConversationEnvelope = serde_json::from_slice(&bytes)?;
    ConversationArchive {
        schema_version: envelope.schema_version.clone(),
        source: envelope.source.clone(),
        conversations: vec![envelope.conversation.clone()],
        extensions: BTreeMap::new(),
    }
    .validate()?;
    Ok(envelope)
}

struct CitationMeta {
    conversation_id: String,
    derivation_id: String,
    chunk_start: u64,
    chunk_end: u64,
    branch_endpoint_node_id: String,
    source_artifact_version_id: String,
    artifact_version_id: String,
    canonical_hash: String,
    normalized_hash: String,
    derivation_hash: String,
    parser: ComponentVersion,
    normalizer: ComponentVersion,
    renderer: ComponentVersion,
    chunker: ComponentVersion,
    locality: ProcessingLocality,
    processed_at: String,
}

fn citation_meta(
    vault: &Vault,
    chunk_id: &str,
) -> Result<CitationMeta, ConversationPersistenceError> {
    let row = vault
        .conn()
        .query_row(
            "SELECT cd.conversation_id, cd.id, ch.byte_offset_start, ch.byte_offset_end,
                    endpoint.source_node_id, ca.source_artifact_version_id,
                    c.artifact_version_id, c.canonical_hash, cd.normalized_blob_hash,
                    cd.derivation_hash, ca.parser_name, ca.parser_version,
                    ca.normalizer_name, ca.normalizer_version,
                    cd.renderer_name, cd.renderer_version, cd.chunker_name,
                    cd.chunker_version, cd.locality, cd.processed_at
             FROM conversation_chunk_map cm
             JOIN chunks ch ON ch.id = cm.chunk_id
             JOIN conversation_derivations cd ON cd.id = cm.derivation_id
             JOIN conversations c ON c.id = cd.conversation_id
             JOIN conversation_archives ca ON ca.id = c.archive_id
             JOIN conversation_nodes endpoint ON endpoint.id = cm.branch_endpoint_node_id
             WHERE cm.chunk_id = ?1",
            [chunk_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, String>(17)?,
                    row.get::<_, String>(18)?,
                    row.get::<_, String>(19)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                ConversationPersistenceError::CitationNotFound(chunk_id.to_owned())
            }
            other => ConversationPersistenceError::Database(other),
        })?;
    Ok(CitationMeta {
        conversation_id: row.0,
        derivation_id: row.1,
        chunk_start: row.2 as u64,
        chunk_end: row.3 as u64,
        branch_endpoint_node_id: row.4,
        source_artifact_version_id: row.5,
        artifact_version_id: row.6,
        canonical_hash: row.7,
        normalized_hash: row.8,
        derivation_hash: row.9,
        parser: ComponentVersion {
            name: row.10,
            version: row.11,
        },
        normalizer: ComponentVersion {
            name: row.12,
            version: row.13,
        },
        renderer: ComponentVersion {
            name: row.14,
            version: row.15,
        },
        chunker: ComponentVersion {
            name: row.16,
            version: row.17,
        },
        locality: ProcessingLocality::parse(&row.18)?,
        processed_at: row.19,
    })
}

fn overlapping_source_ids(
    vault: &Vault,
    derivation_id: &str,
    start: u64,
    end: u64,
    parts: bool,
) -> Result<Vec<String>, ConversationPersistenceError> {
    let sql = if parts {
        "SELECT cp.source_part_id FROM conversation_spans cs
         JOIN conversation_content_parts cp ON cp.id = cs.part_id
         WHERE cs.derivation_id = ?1 AND cs.part_id IS NOT NULL
           AND cs.byte_offset_end > ?2 AND cs.byte_offset_start < ?3
         ORDER BY cs.byte_offset_start, cs.byte_offset_end"
    } else {
        "SELECT cn.source_node_id FROM conversation_spans cs
         JOIN conversation_nodes cn ON cn.id = cs.node_id
         WHERE cs.derivation_id = ?1 AND cs.part_id IS NULL
           AND cs.byte_offset_end > ?2 AND cs.byte_offset_start < ?3
         ORDER BY cs.byte_offset_start, cs.byte_offset_end"
    };
    let mut statement = vault.conn().prepare(sql)?;
    let ids = statement
        .query_map(
            rusqlite::params![derivation_id, start as i64, end as i64],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ids)
}

fn source_timestamp_range(
    conversation: &Conversation,
    wanted: &BTreeSet<&str>,
) -> Option<(String, String)> {
    let mut timestamps: Vec<_> = conversation
        .nodes
        .iter()
        .filter(|node| wanted.contains(node.node_id.as_str()))
        .filter_map(|node| {
            node.timestamp.as_ref().and_then(|timestamp| {
                timestamp
                    .parse::<chrono::DateTime<chrono::FixedOffset>>()
                    .ok()
                    .map(|parsed| (parsed, timestamp.clone()))
            })
        })
        .collect();
    timestamps.sort_by_key(|(parsed, _)| *parsed);
    timestamps
        .first()
        .zip(timestamps.last())
        .map(|(first, last)| (first.1.clone(), last.1.clone()))
}

fn persisted_node_ids(
    vault: &Vault,
    conversation_id: &str,
) -> Result<BTreeMap<String, String>, ConversationPersistenceError> {
    let mut statement = vault
        .conn()
        .prepare("SELECT source_node_id, id FROM conversation_nodes WHERE conversation_id = ?1")?;
    let rows = statement
        .query_map([conversation_id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

fn persisted_part_ids(
    vault: &Vault,
    conversation_id: &str,
) -> Result<BTreeMap<String, String>, ConversationPersistenceError> {
    let mut statement = vault.conn().prepare(
        "SELECT cp.source_part_id, cp.id FROM conversation_content_parts cp
         JOIN conversation_nodes cn ON cn.id = cp.node_id
         WHERE cn.conversation_id = ?1",
    )?;
    let rows = statement
        .query_map([conversation_id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

fn validate_config(
    config: &ConversationPersistenceConfig,
) -> Result<(), ConversationPersistenceError> {
    if config.renderer.name.is_empty()
        || config.renderer.version.is_empty()
        || config.chunker.name.is_empty()
        || config.chunker.version.is_empty()
        || config.chunk_params.target_tokens == 0
    {
        return Err(ConversationPersistenceError::Invariant(
            "renderer/chunker names and versions must be non-empty and target_tokens must be positive"
                .into(),
        ));
    }
    Ok(())
}

fn source_product_str(product: SourceProduct) -> &'static str {
    match product {
        SourceProduct::ClaudeCode => "claude_code",
        SourceProduct::Claude => "claude",
        SourceProduct::Chatgpt => "chatgpt",
    }
}

fn attachment_state_str(state: AttachmentState) -> &'static str {
    match state {
        AttachmentState::Preserved => "preserved",
        AttachmentState::Missing => "missing",
        AttachmentState::ExternalUnfetched => "external_unfetched",
        AttachmentState::Unsupported => "unsupported",
    }
}

fn stable_id(prefix: &str, parts: &[&str]) -> String {
    format!("{prefix}_{}", &stable_digest(parts)[..32])
}

fn stable_digest(parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::super::SourceRecord;
    use super::*;
    use crate::artifact::{self, ArtifactState, Sensitivity};
    use crate::crypto::KdfParams;
    use crate::lens::{DisclosureMode, LensPolicy};
    use crate::space;
    use proptest::prelude::*;

    const FIXTURE: &str = include_str!("../../../../tests/fixtures/conversation-tree.json");
    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    fn setup() -> (
        tempfile::TempDir,
        Vault,
        SpaceId,
        String,
        ConversationArchive,
    ) {
        let directory = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(
            &directory.path().join("Conversation.tessera"),
            "test",
            &TEST_PARAMS,
        )
        .expect("vault");
        let space_id = space::create(&vault, "Conversations", None).expect("space");
        let source_artifact = artifact::register(
            &vault,
            &space_id,
            "opaque-export.json",
            "application/json",
            Sensitivity::Restricted,
        )
        .expect("source artifact");
        let source_bytes = b"synthetic immutable source export";
        let source_hash = vault
            .blobs()
            .put(vault.dek().expect("unlocked"), source_bytes)
            .expect("source blob");
        let source_version = artifact::record_version(
            &vault,
            &source_artifact,
            &source_hash,
            source_bytes.len() as u64,
        )
        .expect("source version");
        let mut archive = ConversationArchive::from_json(FIXTURE).expect("fixture");
        archive.source.source_hash = source_hash.0;
        archive.validate().expect("updated fixture");
        (directory, vault, space_id, source_version.id, archive)
    }

    #[test]
    fn persists_exact_graph_and_reconstructs_every_chunk_citation() {
        let (_directory, vault, space_id, source_version_id, archive) = setup();
        let persisted = persist_archive(
            &vault,
            &space_id,
            &source_version_id,
            &archive,
            &ConversationPersistenceConfig::default(),
        )
        .expect("persist");
        assert_eq!(persisted.len(), 1);
        let persisted = &persisted[0];
        assert_eq!(
            load_conversation(&vault, &persisted.id).expect("load"),
            archive.conversations[0]
        );

        let conversation_artifact =
            artifact::get(&vault, &persisted.artifact_id).expect("artifact");
        assert_eq!(conversation_artifact.state, ArtifactState::Pending);
        assert_eq!(conversation_artifact.sensitivity, Sensitivity::Confidential);
        assert_eq!(
            conversation_artifact.filename,
            format!("conversation-{}.json", &persisted.canonical_hash[..16])
        );
        assert!(!conversation_artifact
            .filename
            .contains("Branch preservation"));

        let hidden: i64 = vault
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM conversation_nodes WHERE conversation_id = ?1 AND source_state = 'hidden'",
                [&persisted.id],
                |row| row.get(0),
            )
            .expect("hidden count");
        let deleted: i64 = vault
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM conversation_nodes WHERE conversation_id = ?1 AND source_state = 'deleted'",
                [&persisted.id],
                |row| row.get(0),
            )
            .expect("deleted count");
        let missing_attachment: i64 = vault
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM conversation_content_parts cp
                 JOIN conversation_nodes cn ON cn.id = cp.node_id
                 WHERE cn.conversation_id = ?1 AND cp.attachment_state = 'missing'",
                [&persisted.id],
                |row| row.get(0),
            )
            .expect("attachment count");
        assert_eq!((hidden, deleted, missing_attachment), (1, 1, 1));
        let integrity = crate::recovery::diagnose(&vault).expect("integrity diagnostics");
        let orphan_blobs = integrity
            .checks
            .iter()
            .find(|check| check.component == "orphan_blobs")
            .expect("orphan blob check");
        assert_eq!(
            orphan_blobs.affected, 0,
            "encrypted normal-form blob was misclassified as orphaned"
        );

        let mut cited_nodes = BTreeSet::new();
        for chunk_id in &persisted.chunk_ids {
            let citation = citation_for_chunk(&vault, chunk_id).expect("citation");
            assert_eq!(citation.source_product, SourceProduct::Chatgpt);
            assert_eq!(citation.source_artifact_version_id, source_version_id);
            assert_eq!(citation.branch_path, archive.conversations[0].selected_path);
            assert_eq!(citation.canonical_hash, persisted.canonical_hash);
            assert_eq!(citation.normalized_hash, persisted.normalized_hash);
            assert_eq!(citation.derivation_hash, persisted.derivation_hash);
            assert!(!citation.source_record_ids.is_empty());
            assert!(!citation.node_ids.contains(&"node_alternate".to_owned()));
            let nodes = reconstruct_cited_nodes(&vault, &citation).expect("reconstruct");
            assert_eq!(
                nodes.iter().map(|node| &node.node_id).collect::<Vec<_>>(),
                citation.node_ids.iter().collect::<Vec<_>>()
            );
            cited_nodes.extend(citation.node_ids);
        }
        assert_eq!(
            cited_nodes,
            archive.conversations[0]
                .selected_path
                .iter()
                .cloned()
                .collect()
        );

        let lens = LensPolicy::new("Conversation access", vec![space_id.clone()]);
        assert!(
            !crate::disclosure::permits(&vault, &lens, &persisted.artifact_id)
                .expect("pending permit check"),
            "pending conversation escaped quarantine"
        );
        artifact::set_state(&vault, &persisted.artifact_id, ArtifactState::Live).expect("promote");
        let mut restricted_lens = lens.clone();
        restricted_lens.sensitivity_ceiling = Sensitivity::Restricted;
        restricted_lens.disclosure_mode = DisclosureMode::Excerpt;
        assert!(
            crate::disclosure::permits(&vault, &restricted_lens, &persisted.artifact_id)
                .expect("restricted permit")
        );
        let first_citation = citation_for_chunk(&vault, &persisted.chunk_ids[0]).expect("citation");
        let search_result = crate::search::SearchResult {
            artifact_id: persisted.artifact_id.clone(),
            artifact_title: conversation_artifact.filename,
            chunk_id: persisted.chunk_ids[0].clone(),
            relevance_score: 1.0,
            byte_range: first_citation.normalized_byte_range,
            timestamp_range: None,
            source_url: None,
        };
        let disclosed = crate::disclosure::render(&vault, &search_result, &restricted_lens, false)
            .expect("disclose conversation excerpt");
        let disclosed_range = disclosed.disclosed_range.expect("excerpt range");
        let disclosed_citation = citation_for_disclosed_range(
            &vault,
            &persisted.chunk_ids[0],
            disclosed_range.0,
            disclosed_range.1,
        )
        .expect("disclosed citation");
        assert!(!reconstruct_cited_nodes(&vault, &disclosed_citation)
            .expect("reconstruct disclosed")
            .is_empty());
        let mut internal_lens = lens;
        internal_lens.sensitivity_ceiling = Sensitivity::Internal;
        assert!(
            !crate::disclosure::permits(&vault, &internal_lens, &persisted.artifact_id)
                .expect("internal permit"),
            "conversation exceeded the lens sensitivity ceiling"
        );
    }

    #[test]
    fn rechunking_changes_derived_ids_but_not_source_identities() {
        let (_directory, vault, space_id, source_version_id, archive) = setup();
        let small = ConversationPersistenceConfig {
            chunk_params: ChunkParams {
                target_tokens: 1,
                overlap_tokens: 0,
            },
            ..ConversationPersistenceConfig::default()
        };
        let first = persist_archive(&vault, &space_id, &source_version_id, &archive, &small)
            .expect("persist")
            .remove(0);
        let source_ids_before: Vec<String> = {
            let mut statement = vault
                .conn()
                .prepare(
                    "SELECT source_node_id FROM conversation_nodes
                     WHERE conversation_id = ?1 ORDER BY source_node_id",
                )
                .expect("prepare");
            statement
                .query_map([&first.id], |row| row.get(0))
                .expect("query")
                .collect::<Result<_, _>>()
                .expect("collect")
        };
        let large = ConversationPersistenceConfig {
            chunk_params: ChunkParams {
                target_tokens: 10_000,
                overlap_tokens: 0,
            },
            ..ConversationPersistenceConfig::default()
        };
        let second = rechunk_conversation(&vault, &first.id, &large).expect("rechunk");
        let source_ids_after: Vec<String> = {
            let mut statement = vault
                .conn()
                .prepare(
                    "SELECT source_node_id FROM conversation_nodes
                     WHERE conversation_id = ?1 ORDER BY source_node_id",
                )
                .expect("prepare");
            statement
                .query_map([&first.id], |row| row.get(0))
                .expect("query")
                .collect::<Result<_, _>>()
                .expect("collect")
        };
        assert_eq!(source_ids_before, source_ids_after);
        assert_ne!(first.derived_text_id, second.derived_text_id);
        assert_ne!(first.derivation_hash, second.derivation_hash);
        assert!(first
            .chunk_ids
            .iter()
            .all(|id| !second.chunk_ids.contains(id)));
        assert_eq!(
            load_conversation(&vault, &first.id).expect("load"),
            archive.conversations[0]
        );
    }

    #[test]
    fn owner_recovery_rebuild_restores_conversation_derivations() {
        let (_directory, vault, space_id, source_version_id, archive) = setup();
        let persisted = persist_archive(
            &vault,
            &space_id,
            &source_version_id,
            &archive,
            &ConversationPersistenceConfig::default(),
        )
        .expect("persist")
        .remove(0);
        artifact::set_state(&vault, &persisted.artifact_id, ArtifactState::Live).expect("live");

        let rebuilt = crate::recovery::rebuild_derived(&vault).expect("rebuild derived");
        assert_eq!(rebuilt.artifacts_moved_to_pending, 1);
        assert_eq!(rebuilt.failed, 0);
        assert!(rebuilt.chunked >= 1);
        assert_eq!(
            artifact::get(&vault, &persisted.artifact_id)
                .expect("artifact")
                .state,
            ArtifactState::Pending
        );
        assert_eq!(
            load_conversation(&vault, &persisted.id).expect("load rebuilt"),
            archive.conversations[0]
        );
        let mapped_chunks: i64 = vault
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM conversation_chunk_map cm
                 JOIN conversation_derivations cd ON cd.id = cm.derivation_id
                 WHERE cd.conversation_id = ?1",
                [&persisted.id],
                |row| row.get(0),
            )
            .expect("mapped chunks");
        assert!(mapped_chunks > 0);
    }

    #[test]
    fn unauthenticated_source_cannot_acquire_conversation_provenance() {
        let (_directory, vault, space_id, source_version_id, archive) = setup();
        vault
            .blobs()
            .delete(&BlobHash(archive.source.source_hash.clone()))
            .expect("remove source fixture");
        assert!(matches!(
            persist_archive(
                &vault,
                &space_id,
                &source_version_id,
                &archive,
                &ConversationPersistenceConfig::default(),
            ),
            Err(ConversationPersistenceError::Blob(BlobError::NotFound(_)))
        ));
        let archives: i64 = vault
            .conn()
            .query_row("SELECT COUNT(*) FROM conversation_archives", [], |row| {
                row.get(0)
            })
            .expect("archive count");
        assert_eq!(archives, 0);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn arbitrary_small_branch_trees_have_exact_selected_spans(
            selected_len in 1usize..8,
            alternate_flags in prop::collection::vec(any::<bool>(), 1..8),
        ) {
            let mut source_records = Vec::new();
            let mut nodes = Vec::new();
            let mut selected_path = Vec::new();
            for index in 0..selected_len {
                let node_id = format!("selected_{index}");
                let record_id = format!("record_{index}");
                let part_id = format!("part_{index}");
                source_records.push(SourceRecord {
                    record_id: record_id.clone(),
                    record_index: source_records.len() as u64,
                    source_id: None,
                    byte_start: None,
                    byte_end: None,
                    line_start: None,
                    line_end: None,
                });
                nodes.push(MessageNode {
                    node_id: node_id.clone(),
                    parent_node_id: index.checked_sub(1).map(|prior| format!("selected_{prior}")),
                    role: super::super::MessageRole::User,
                    state: super::super::NodeState::Visible,
                    timestamp: None,
                    model: None,
                    source_record_ids: vec![record_id],
                    content_parts: vec![super::super::ContentPart {
                        part_id,
                        kind: super::super::ContentKind::Text,
                        text: Some(format!("selected text {index}")),
                        language: None,
                        tool_name: None,
                        tool_use_id: None,
                        data: None,
                        attachment: None,
                        extensions: BTreeMap::new(),
                    }],
                    extensions: BTreeMap::new(),
                });
                selected_path.push(node_id.clone());
                if alternate_flags[index % alternate_flags.len()] {
                    let alt_index = nodes.len();
                    let alt_node_id = format!("alternate_{index}");
                    let alt_record_id = format!("alternate_record_{index}");
                    source_records.push(SourceRecord {
                        record_id: alt_record_id.clone(),
                        record_index: source_records.len() as u64,
                        source_id: None,
                        byte_start: None,
                        byte_end: None,
                        line_start: None,
                        line_end: None,
                    });
                    nodes.push(MessageNode {
                        node_id: alt_node_id,
                        parent_node_id: Some(node_id),
                        role: super::super::MessageRole::Assistant,
                        state: super::super::NodeState::Visible,
                        timestamp: None,
                        model: None,
                        source_record_ids: vec![alt_record_id],
                        content_parts: vec![super::super::ContentPart {
                            part_id: format!("alternate_part_{alt_index}"),
                            kind: super::super::ContentKind::Text,
                            text: Some(format!("alternate text {index}")),
                            language: None,
                            tool_name: None,
                            tool_use_id: None,
                            data: None,
                            attachment: None,
                            extensions: BTreeMap::new(),
                        }],
                        extensions: BTreeMap::new(),
                    });
                }
            }
            let conversation = Conversation {
                conversation_id: "property".into(),
                title: None,
                project: None,
                created_at: None,
                updated_at: None,
                sensitivity: "internal".into(),
                source_records,
                nodes,
                selected_path: selected_path.clone(),
                extensions: BTreeMap::new(),
            };
            conversation.validate().expect("valid generated tree");
            let rendered = conversation.render_with_spans().expect("render");
            prop_assert_eq!(
                rendered.node_spans.iter().map(|span| span.node_id.clone()).collect::<Vec<_>>(),
                selected_path
            );
            prop_assert_eq!(rendered.node_spans.first().map(|span| span.start), Some(0));
            prop_assert_eq!(rendered.node_spans.last().map(|span| span.end), Some(rendered.text.len() as u64));
            for pair in rendered.node_spans.windows(2) {
                prop_assert_eq!(pair[0].end, pair[1].start);
            }
            for part in &rendered.part_spans {
                let node = rendered.node_spans.iter().find(|node| node.node_id == part.node_id).expect("part node");
                prop_assert!(part.start >= node.start && part.end <= node.end);
                prop_assert!(part.start < part.end);
            }
            prop_assert!(!rendered.text.contains("alternate text"));
        }
    }
}
