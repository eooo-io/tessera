//! Source-neutral, idempotent conversation ingestion runs.
//!
//! Parsers discover source-native conversations and return either a validated
//! candidate or a bounded structural issue. This runner owns immutable-source
//! authentication, delta/update decisions, checkpoints, persistence, and the
//! plaintext-safe operational ledger.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    persist_archive_selection, ComponentVersion, Conversation, ConversationArchive,
    ConversationPersistenceConfig, ConversationPersistenceError, SourceIdentity, SourceProduct,
    SCHEMA_VERSION,
};
use crate::blob::{BlobError, BlobHash};
use crate::space::SpaceId;
use crate::vault::{Vault, VaultError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestionIssue {
    MissingRequiredStructure,
    ChangedFieldType,
    OrphanNode,
    Cycle,
    InvalidTimestamp,
    UnsupportedContentPart,
    DuplicateConversationId,
    TargetSpaceConflict,
    NormalFormInvariant,
    ParserFailure,
    NormalizerFailure,
}

impl IngestionIssue {
    pub fn code(self) -> &'static str {
        match self {
            Self::MissingRequiredStructure => "missing_required_structure",
            Self::ChangedFieldType => "changed_field_type",
            Self::OrphanNode => "orphan_node",
            Self::Cycle => "cycle",
            Self::InvalidTimestamp => "invalid_timestamp",
            Self::UnsupportedContentPart => "unsupported_content_part",
            Self::DuplicateConversationId => "duplicate_conversation_id",
            Self::TargetSpaceConflict => "target_space_conflict",
            Self::NormalFormInvariant => "normal_form_invariant",
            Self::ParserFailure => "parser_failure",
            Self::NormalizerFailure => "normalizer_failure",
        }
    }

    pub fn safe_summary(self) -> &'static str {
        match self {
            Self::MissingRequiredStructure => "required conversation structure is missing",
            Self::ChangedFieldType => "a required source field changed type",
            Self::OrphanNode => "a conversation node references an unknown parent",
            Self::Cycle => "a conversation branch contains a cycle",
            Self::InvalidTimestamp => "a source timestamp is invalid",
            Self::UnsupportedContentPart => "a content part cannot be represented safely",
            Self::DuplicateConversationId => "the source emitted a duplicate conversation id",
            Self::TargetSpaceConflict => {
                "the current conversation identity belongs to a different target space"
            }
            Self::NormalFormInvariant => "the normalized conversation violates the v1 contract",
            Self::ParserFailure => "the source parser could not enumerate the archive safely",
            Self::NormalizerFailure => "the source record could not be normalized safely",
        }
    }
}

#[derive(Debug, Clone)]
pub enum CandidateOutcome {
    Conversation(Box<Conversation>),
    Quarantined(IngestionIssue),
    Failed(IngestionIssue),
}

#[derive(Debug, Clone)]
pub struct ConversationCandidate {
    pub source_conversation_id: String,
    pub outcome: CandidateOutcome,
}

impl ConversationCandidate {
    pub fn conversation(conversation: Conversation) -> Self {
        Self {
            source_conversation_id: conversation.conversation_id.clone(),
            outcome: CandidateOutcome::Conversation(Box::new(conversation)),
        }
    }

    pub fn quarantined(source_conversation_id: impl Into<String>, issue: IngestionIssue) -> Self {
        Self {
            source_conversation_id: source_conversation_id.into(),
            outcome: CandidateOutcome::Quarantined(issue),
        }
    }

    pub fn failed(source_conversation_id: impl Into<String>, issue: IngestionIssue) -> Self {
        Self {
            source_conversation_id: source_conversation_id.into(),
            outcome: CandidateOutcome::Failed(issue),
        }
    }
}

/// Source adapters implement only discovery and normalization. They never
/// write the vault or decide dedupe/replacement semantics.
pub trait ConversationSourceParser {
    fn source_product(&self) -> SourceProduct;
    fn parser(&self) -> ComponentVersion;
    fn normalizer(&self) -> ComponentVersion;
    fn export_id(&self) -> Option<String> {
        None
    }
    fn parse(&self, source: &[u8]) -> Result<Vec<ConversationCandidate>, IngestionIssue>;
}

#[derive(Debug, Clone, Default)]
pub struct IngestionOptions {
    /// Operational checkpoint hook. Processing stops cleanly after this many
    /// pending items and the same run can be resumed deterministically.
    pub max_items: Option<usize>,
    pub resume_run_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestionRunStatus {
    Running,
    Interrupted,
    Completed,
    Failed,
}

impl IngestionRunStatus {
    fn parse(value: &str) -> Self {
        match value {
            "running" => Self::Running,
            "interrupted" => Self::Interrupted,
            "completed" => Self::Completed,
            _ => Self::Failed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestionItemStatus {
    Pending,
    Imported,
    Unchanged,
    Updated,
    Quarantined,
    Failed,
}

impl IngestionItemStatus {
    fn parse(value: &str) -> Self {
        match value {
            "pending" => Self::Pending,
            "imported" => Self::Imported,
            "unchanged" => Self::Unchanged,
            "updated" => Self::Updated,
            "quarantined" => Self::Quarantined,
            _ => Self::Failed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestionItemReport {
    pub id: String,
    pub ordinal: u64,
    pub source_conversation_id: String,
    pub source_digest: Option<String>,
    pub status: IngestionItemStatus,
    pub persisted_conversation_id: Option<String>,
    pub previous_persisted_conversation_id: Option<String>,
    pub derived_text_id: Option<String>,
    pub derivation_hash: Option<String>,
    pub embedding_model_version: Option<String>,
    pub error_code: Option<String>,
    pub safe_error_summary: Option<String>,
    pub retry_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestionRunReport {
    pub id: String,
    pub source_artifact_version_id: String,
    pub target_space_id: String,
    pub source_product: SourceProduct,
    pub source_hash: String,
    pub parser: ComponentVersion,
    pub normalizer: ComponentVersion,
    pub status: IngestionRunStatus,
    pub discovered: u64,
    pub imported: u64,
    pub unchanged: u64,
    pub updated: u64,
    pub quarantined: u64,
    pub failed: u64,
    pub checkpoint_ordinal: u64,
    pub retry_count: u64,
    pub error_code: Option<String>,
    pub safe_error_summary: Option<String>,
    pub started_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
    pub items: Vec<IngestionItemReport>,
}

#[derive(Debug, Error)]
pub enum IngestionError {
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("blob error: {0}")]
    Blob(#[from] BlobError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("conversation persistence error: {0}")]
    Persistence(#[from] ConversationPersistenceError),
    #[error("conversation JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("source artifact version not found: {0}")]
    SourceArtifactVersionNotFound(String),
    #[error("target space not found: {0}")]
    TargetSpaceNotFound(String),
    #[error("ingestion run not found: {0}")]
    RunNotFound(String),
    #[error("ingestion run is already complete: {0}")]
    AlreadyComplete(String),
    #[error("failed ingestion run cannot be resumed; start a new run: {0}")]
    FailedRunNotResumable(String),
    #[error("ingestion resume input drifted from its checkpoint: {0}")]
    ResumeDrift(String),
    #[error("parser contract is invalid: {0}")]
    ParserContract(String),
}

#[derive(Clone)]
struct NormalizedCandidate {
    source_conversation_id: String,
    digest: Option<String>,
    outcome: CandidateOutcome,
}

struct Head {
    persisted_conversation_id: String,
    target_space_id: String,
    source_digest: String,
    parser: ComponentVersion,
    normalizer: ComponentVersion,
}

struct PendingWrite {
    ordinal: usize,
    item_id: String,
    status: IngestionItemStatus,
    previous: Option<Head>,
}

struct ResumeIdentity<'a> {
    source_artifact_version_id: &'a str,
    target_space_id: &'a SpaceId,
    product: SourceProduct,
    source_hash: &'a str,
    parser: &'a ComponentVersion,
    normalizer: &'a ComponentVersion,
}

pub fn ingest(
    vault: &Vault,
    space_id: &SpaceId,
    source_artifact_version_id: &str,
    parser: &dyn ConversationSourceParser,
    options: &IngestionOptions,
) -> Result<IngestionRunReport, IngestionError> {
    let parser_version = parser.parser();
    let normalizer_version = parser.normalizer();
    validate_component("parser", &parser_version)?;
    validate_component("normalizer", &normalizer_version)?;
    let source_product = parser.source_product();
    let target_space_exists: bool = vault.conn().query_row(
        "SELECT EXISTS(SELECT 1 FROM spaces WHERE id = ?1)",
        [&space_id.0],
        |row| row.get(0),
    )?;
    if !target_space_exists {
        return Err(IngestionError::TargetSpaceNotFound(space_id.0.clone()));
    }
    let source_hash = vault
        .conn()
        .query_row(
            "SELECT blob_hash FROM artifact_versions WHERE id = ?1",
            [source_artifact_version_id],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => {
                IngestionError::SourceArtifactVersionNotFound(source_artifact_version_id.into())
            }
            other => IngestionError::Database(other),
        })?;
    let source = vault
        .blobs()
        .get(vault.dek()?, &BlobHash(source_hash.clone()))?;

    let run_id = if let Some(resume) = &options.resume_run_id {
        validate_resume(
            vault,
            resume,
            &ResumeIdentity {
                source_artifact_version_id,
                target_space_id: space_id,
                product: source_product,
                source_hash: &source_hash,
                parser: &parser_version,
                normalizer: &normalizer_version,
            },
        )?;
        resume.clone()
    } else {
        let id = format!("cingest_{}", ulid::Ulid::new());
        let now = chrono::Utc::now().to_rfc3339();
        vault.conn().execute(
            "INSERT INTO conversation_ingestion_runs
             (id, source_artifact_version_id, target_space_id, source_product, source_hash,
              parser_name, parser_version, normalizer_name, normalizer_version,
              status, started_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'running', ?10, ?10)",
            rusqlite::params![
                id,
                source_artifact_version_id,
                space_id.0,
                source_product_str(source_product),
                source_hash,
                parser_version.name,
                parser_version.version,
                normalizer_version.name,
                normalizer_version.version,
                now,
            ],
        )?;
        id
    };

    let candidates = match parser.parse(&source) {
        Ok(candidates) => normalize_candidates(candidates)?,
        Err(issue) => {
            fail_run(vault, &run_id, issue, options.resume_run_id.is_some())?;
            return get_ingestion_run(vault, &run_id);
        }
    };

    if options.resume_run_id.is_some() {
        verify_resume_items(vault, &run_id, &candidates)?;
        mark_resume_attempt(vault, &run_id)?;
    } else {
        initialize_items(vault, &run_id, &candidates)?;
    }

    let existing_items = item_statuses(vault, &run_id)?;
    let limit = options.max_items.unwrap_or(usize::MAX);
    let chosen: BTreeSet<usize> = existing_items
        .iter()
        .filter(|(_, status)| *status == IngestionItemStatus::Pending)
        .map(|(ordinal, _)| *ordinal)
        .take(limit)
        .collect();

    let mut writes = Vec::new();
    let mut selected_ids = Vec::new();
    let valid_conversations: Vec<Conversation> = candidates
        .iter()
        .filter_map(|candidate| match &candidate.outcome {
            CandidateOutcome::Conversation(conversation) => Some(conversation.as_ref().clone()),
            _ => None,
        })
        .collect();
    for ordinal in chosen {
        let candidate = &candidates[ordinal];
        let item_id = stable_item_id(&run_id, ordinal, &candidate.source_conversation_id);
        match &candidate.outcome {
            CandidateOutcome::Quarantined(issue) => {
                complete_issue_item(vault, &item_id, IngestionItemStatus::Quarantined, *issue)?;
            }
            CandidateOutcome::Failed(issue) => {
                complete_issue_item(vault, &item_id, IngestionItemStatus::Failed, *issue)?;
            }
            CandidateOutcome::Conversation(_) => {
                let digest = candidate.digest.as_ref().expect("conversation digest");
                let head = load_head(vault, source_product, &candidate.source_conversation_id)?;
                if head
                    .as_ref()
                    .is_some_and(|head| head.target_space_id != space_id.0)
                {
                    complete_issue_item(
                        vault,
                        &item_id,
                        IngestionItemStatus::Failed,
                        IngestionIssue::TargetSpaceConflict,
                    )?;
                    continue;
                }
                if head.as_ref().is_some_and(|head| {
                    head.source_digest == *digest
                        && head.parser == parser_version
                        && head.normalizer == normalizer_version
                }) {
                    let head = head.expect("matched head");
                    complete_unchanged_item(vault, &item_id, &head)?;
                } else {
                    let status = if head.is_some() {
                        IngestionItemStatus::Updated
                    } else {
                        IngestionItemStatus::Imported
                    };
                    selected_ids.push(candidate.source_conversation_id.clone());
                    writes.push(PendingWrite {
                        ordinal,
                        item_id,
                        status,
                        previous: head,
                    });
                }
            }
        }
    }

    if !selected_ids.is_empty() {
        let archive = ConversationArchive {
            schema_version: SCHEMA_VERSION.into(),
            source: SourceIdentity {
                product: source_product,
                source_hash: source_hash.clone(),
                parser: parser_version.clone(),
                normalizer: normalizer_version.clone(),
                export_id: parser.export_id(),
            },
            conversations: valid_conversations,
            extensions: BTreeMap::new(),
        };
        let persisted = persist_archive_selection(
            vault,
            space_id,
            source_artifact_version_id,
            &archive,
            &ConversationPersistenceConfig::default(),
            &selected_ids,
        )?;
        let by_source: BTreeMap<_, _> = persisted
            .into_iter()
            .map(|item| (item.source_conversation_id.clone(), item))
            .collect();
        vault.conn().execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let now = chrono::Utc::now().to_rfc3339();
            for write in &writes {
                let candidate = &candidates[write.ordinal];
                let item = by_source
                    .get(&candidate.source_conversation_id)
                    .ok_or_else(|| {
                        IngestionError::ParserContract(
                            "persistence omitted a selected conversation".into(),
                        )
                    })?;
                complete_persisted_item(
                    vault,
                    &run_id,
                    source_product,
                    &parser_version,
                    &normalizer_version,
                    candidate.digest.as_deref().expect("digest"),
                    &write.item_id,
                    write.status,
                    write.previous.as_ref(),
                    item,
                    &now,
                )?;
            }
            Ok::<_, IngestionError>(())
        })();
        match result {
            Ok(()) => {
                if let Err(error) = vault.conn().execute_batch("COMMIT") {
                    let _ = vault.conn().execute_batch("ROLLBACK");
                    return Err(error.into());
                }
            }
            Err(error) => {
                let _ = vault.conn().execute_batch("ROLLBACK");
                return Err(error);
            }
        }
    }

    refresh_run(vault, &run_id)?;
    get_ingestion_run(vault, &run_id)
}

pub fn get_ingestion_run(
    vault: &Vault,
    run_id: &str,
) -> Result<IngestionRunReport, IngestionError> {
    let run = vault
        .conn()
        .query_row(
            "SELECT source_artifact_version_id, target_space_id, source_product, source_hash,
                    parser_name, parser_version, normalizer_name, normalizer_version,
                    status, discovered_count, imported_count, unchanged_count,
                    updated_count, quarantined_count, failed_count, checkpoint_ordinal,
                    retry_count, error_code, safe_error_summary, started_at, updated_at,
                    completed_at
             FROM conversation_ingestion_runs WHERE id = ?1",
            [run_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, i64>(16)?,
                    row.get::<_, Option<String>>(17)?,
                    row.get::<_, Option<String>>(18)?,
                    row.get::<_, String>(19)?,
                    row.get::<_, String>(20)?,
                    row.get::<_, Option<String>>(21)?,
                ))
            },
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => IngestionError::RunNotFound(run_id.into()),
            other => IngestionError::Database(other),
        })?;
    Ok(IngestionRunReport {
        id: run_id.into(),
        source_artifact_version_id: run.0,
        target_space_id: run.1,
        source_product: parse_source_product(&run.2)?,
        source_hash: run.3,
        parser: ComponentVersion {
            name: run.4,
            version: run.5,
        },
        normalizer: ComponentVersion {
            name: run.6,
            version: run.7,
        },
        status: IngestionRunStatus::parse(&run.8),
        discovered: run.9 as u64,
        imported: run.10 as u64,
        unchanged: run.11 as u64,
        updated: run.12 as u64,
        quarantined: run.13 as u64,
        failed: run.14 as u64,
        checkpoint_ordinal: run.15 as u64,
        retry_count: run.16 as u64,
        error_code: run.17,
        safe_error_summary: run.18,
        started_at: run.19,
        updated_at: run.20,
        completed_at: run.21,
        items: load_items(vault, run_id)?,
    })
}

pub fn list_ingestion_runs(vault: &Vault) -> Result<Vec<IngestionRunReport>, IngestionError> {
    let mut statement = vault
        .conn()
        .prepare("SELECT id FROM conversation_ingestion_runs ORDER BY started_at DESC, id DESC")?;
    let ids = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    ids.iter().map(|id| get_ingestion_run(vault, id)).collect()
}

fn normalize_candidates(
    candidates: Vec<ConversationCandidate>,
) -> Result<Vec<NormalizedCandidate>, IngestionError> {
    let mut counts = BTreeMap::<String, usize>::new();
    for candidate in &candidates {
        if candidate.source_conversation_id.is_empty() {
            return Err(IngestionError::ParserContract(
                "source conversation ids must not be empty".into(),
            ));
        }
        *counts
            .entry(candidate.source_conversation_id.clone())
            .or_default() += 1;
    }
    candidates
        .into_iter()
        .map(|candidate| {
            if counts[&candidate.source_conversation_id] > 1 {
                return Ok(NormalizedCandidate {
                    source_conversation_id: candidate.source_conversation_id,
                    digest: None,
                    outcome: CandidateOutcome::Quarantined(IngestionIssue::DuplicateConversationId),
                });
            }
            match candidate.outcome {
                CandidateOutcome::Conversation(conversation)
                    if conversation.conversation_id == candidate.source_conversation_id
                        && conversation.validate().is_ok() =>
                {
                    let digest = blake3::hash(&serde_json::to_vec(&conversation)?)
                        .to_hex()
                        .to_string();
                    Ok(NormalizedCandidate {
                        source_conversation_id: candidate.source_conversation_id,
                        digest: Some(digest),
                        outcome: CandidateOutcome::Conversation(conversation),
                    })
                }
                CandidateOutcome::Conversation(_) => Ok(NormalizedCandidate {
                    source_conversation_id: candidate.source_conversation_id,
                    digest: None,
                    outcome: CandidateOutcome::Quarantined(IngestionIssue::NormalFormInvariant),
                }),
                outcome => Ok(NormalizedCandidate {
                    source_conversation_id: candidate.source_conversation_id,
                    digest: None,
                    outcome,
                }),
            }
        })
        .collect()
}

fn initialize_items(
    vault: &Vault,
    run_id: &str,
    candidates: &[NormalizedCandidate],
) -> Result<(), IngestionError> {
    vault.conn().execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| {
        for (ordinal, candidate) in candidates.iter().enumerate() {
            vault.conn().execute(
                "INSERT INTO conversation_ingestion_items
                 (id, run_id, ordinal, source_conversation_id, source_digest, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'pending')",
                rusqlite::params![
                    stable_item_id(run_id, ordinal, &candidate.source_conversation_id),
                    run_id,
                    ordinal as i64,
                    candidate.source_conversation_id,
                    candidate.digest,
                ],
            )?;
        }
        vault.conn().execute(
            "UPDATE conversation_ingestion_runs SET discovered_count = ?1 WHERE id = ?2",
            rusqlite::params![candidates.len() as i64, run_id],
        )?;
        Ok::<_, IngestionError>(())
    })();
    finish_transaction(vault, result)
}

fn verify_resume_items(
    vault: &Vault,
    run_id: &str,
    candidates: &[NormalizedCandidate],
) -> Result<(), IngestionError> {
    let mut statement = vault.conn().prepare(
        "SELECT ordinal, source_conversation_id, source_digest
         FROM conversation_ingestion_items WHERE run_id = ?1 ORDER BY ordinal",
    )?;
    let stored = statement
        .query_map([run_id], |row| {
            Ok((
                row.get::<_, i64>(0)? as usize,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if stored.len() != candidates.len()
        || stored
            .iter()
            .zip(candidates)
            .enumerate()
            .any(|(ordinal, (stored, current))| {
                stored.0 != ordinal
                    || stored.1 != current.source_conversation_id
                    || stored.2 != current.digest
            })
    {
        return Err(IngestionError::ResumeDrift(run_id.into()));
    }
    Ok(())
}

fn validate_resume(
    vault: &Vault,
    run_id: &str,
    identity: &ResumeIdentity<'_>,
) -> Result<(), IngestionError> {
    let row = vault
        .conn()
        .query_row(
            "SELECT source_artifact_version_id, target_space_id, source_product, source_hash,
                    parser_name, parser_version, normalizer_name, normalizer_version, status
             FROM conversation_ingestion_runs WHERE id = ?1",
            [run_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| IngestionError::RunNotFound(run_id.into()))?;
    match row.8.as_str() {
        "completed" => return Err(IngestionError::AlreadyComplete(run_id.into())),
        "failed" => return Err(IngestionError::FailedRunNotResumable(run_id.into())),
        _ => {}
    }
    if row.0 != identity.source_artifact_version_id
        || row.1 != identity.target_space_id.0
        || row.2 != source_product_str(identity.product)
        || row.3 != identity.source_hash
        || row.4 != identity.parser.name
        || row.5 != identity.parser.version
        || row.6 != identity.normalizer.name
        || row.7 != identity.normalizer.version
    {
        return Err(IngestionError::ResumeDrift(run_id.into()));
    }
    Ok(())
}

fn complete_issue_item(
    vault: &Vault,
    item_id: &str,
    status: IngestionItemStatus,
    issue: IngestionIssue,
) -> Result<(), IngestionError> {
    let now = chrono::Utc::now().to_rfc3339();
    vault.conn().execute(
        "UPDATE conversation_ingestion_items
         SET status = ?1, error_code = ?2, safe_error_summary = ?3,
             retry_count = retry_count + CASE WHEN attempted_at IS NULL THEN 0 ELSE 1 END,
             attempted_at = ?4, completed_at = ?4 WHERE id = ?5",
        rusqlite::params![
            item_status_str(status),
            issue.code(),
            issue.safe_summary(),
            now,
            item_id,
        ],
    )?;
    Ok(())
}

fn complete_unchanged_item(
    vault: &Vault,
    item_id: &str,
    head: &Head,
) -> Result<(), IngestionError> {
    let (derived_text_id, derivation_hash, embedding_model): (
        Option<String>,
        Option<String>,
        Option<String>,
    ) = vault
        .conn()
        .query_row(
            "SELECT cd.derived_text_id, cd.derivation_hash,
                (SELECT MIN(em.model_version) FROM chunks ch
                 JOIN embeddings_map em ON em.chunk_id = ch.id
                 WHERE ch.derived_text_id = cd.derived_text_id)
         FROM conversation_derivations cd
         WHERE cd.conversation_id = ?1 ORDER BY cd.processed_at DESC LIMIT 1",
            [&head.persisted_conversation_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .unwrap_or((None, None, None));
    let now = chrono::Utc::now().to_rfc3339();
    vault.conn().execute(
        "UPDATE conversation_ingestion_items
         SET status = 'unchanged', persisted_conversation_id = ?1,
             derived_text_id = ?2, derivation_hash = ?3, embedding_model_version = ?4,
             retry_count = retry_count + CASE WHEN attempted_at IS NULL THEN 0 ELSE 1 END,
             attempted_at = ?5, completed_at = ?5 WHERE id = ?6",
        rusqlite::params![
            head.persisted_conversation_id,
            derived_text_id,
            derivation_hash,
            embedding_model,
            now,
            item_id,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn complete_persisted_item(
    vault: &Vault,
    run_id: &str,
    product: SourceProduct,
    parser: &ComponentVersion,
    normalizer: &ComponentVersion,
    digest: &str,
    item_id: &str,
    status: IngestionItemStatus,
    previous: Option<&Head>,
    persisted: &super::PersistedConversation,
    now: &str,
) -> Result<(), IngestionError> {
    vault.conn().execute(
        "UPDATE conversation_ingestion_items
         SET status = ?1, persisted_conversation_id = ?2,
             previous_persisted_conversation_id = ?3, derived_text_id = ?4,
             derivation_hash = ?5,
             retry_count = retry_count + CASE WHEN attempted_at IS NULL THEN 0 ELSE 1 END,
             attempted_at = ?6, completed_at = ?6 WHERE id = ?7",
        rusqlite::params![
            item_status_str(status),
            persisted.id,
            previous.map(|head| head.persisted_conversation_id.as_str()),
            persisted.derived_text_id,
            persisted.derivation_hash,
            now,
            item_id,
        ],
    )?;
    vault.conn().execute(
        "INSERT INTO conversation_ingestion_heads
         (source_product, source_conversation_id, persisted_conversation_id,
          source_digest, parser_name, parser_version, normalizer_name,
          normalizer_version, run_id, item_id, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(source_product, source_conversation_id) DO UPDATE SET
           persisted_conversation_id = excluded.persisted_conversation_id,
           source_digest = excluded.source_digest,
           parser_name = excluded.parser_name,
           parser_version = excluded.parser_version,
           normalizer_name = excluded.normalizer_name,
           normalizer_version = excluded.normalizer_version,
           run_id = excluded.run_id, item_id = excluded.item_id,
           updated_at = excluded.updated_at",
        rusqlite::params![
            source_product_str(product),
            persisted.source_conversation_id,
            persisted.id,
            digest,
            parser.name,
            parser.version,
            normalizer.name,
            normalizer.version,
            run_id,
            item_id,
            now,
        ],
    )?;
    if let Some(previous) = previous {
        let relationship = if previous.source_digest != digest {
            "corrected_source"
        } else if previous.parser != *parser {
            "parser_upgrade"
        } else {
            "normalizer_upgrade"
        };
        vault.conn().execute(
            "INSERT INTO conversation_ingestion_replacements
             (id, prior_persisted_conversation_id, replacement_conversation_id,
              run_id, item_id, relationship, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                stable_replacement_id(&previous.persisted_conversation_id, &persisted.id),
                previous.persisted_conversation_id,
                persisted.id,
                run_id,
                item_id,
                relationship,
                now,
            ],
        )?;
    }
    Ok(())
}

fn load_head(
    vault: &Vault,
    product: SourceProduct,
    source_conversation_id: &str,
) -> Result<Option<Head>, IngestionError> {
    Ok(vault
        .conn()
        .query_row(
            "SELECT h.persisted_conversation_id, a.space_id, h.source_digest,
                    h.parser_name, h.parser_version, h.normalizer_name,
                    h.normalizer_version
             FROM conversation_ingestion_heads h
             JOIN conversations c ON c.id = h.persisted_conversation_id
             JOIN artifact_versions av ON av.id = c.artifact_version_id
             JOIN artifacts a ON a.id = av.artifact_id
             WHERE h.source_product = ?1 AND h.source_conversation_id = ?2",
            rusqlite::params![source_product_str(product), source_conversation_id],
            |row| {
                Ok(Head {
                    persisted_conversation_id: row.get(0)?,
                    target_space_id: row.get(1)?,
                    source_digest: row.get(2)?,
                    parser: ComponentVersion {
                        name: row.get(3)?,
                        version: row.get(4)?,
                    },
                    normalizer: ComponentVersion {
                        name: row.get(5)?,
                        version: row.get(6)?,
                    },
                })
            },
        )
        .optional()?)
}

fn refresh_run(vault: &Vault, run_id: &str) -> Result<(), IngestionError> {
    let counts = vault.conn().query_row(
        "SELECT COUNT(*),
                COALESCE(SUM(status = 'imported'), 0),
                COALESCE(SUM(status = 'unchanged'), 0),
                COALESCE(SUM(status = 'updated'), 0),
                COALESCE(SUM(status = 'quarantined'), 0),
                COALESCE(SUM(status = 'failed'), 0),
                COALESCE(SUM(status = 'pending'), 0),
                COALESCE(MIN(CASE WHEN status = 'pending' THEN ordinal END), COUNT(*))
         FROM conversation_ingestion_items WHERE run_id = ?1",
        [run_id],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
            ))
        },
    )?;
    let now = chrono::Utc::now().to_rfc3339();
    let status = if counts.6 > 0 {
        "interrupted"
    } else {
        "completed"
    };
    vault.conn().execute(
        "UPDATE conversation_ingestion_runs
         SET status = ?1, discovered_count = ?2, imported_count = ?3,
             unchanged_count = ?4, updated_count = ?5, quarantined_count = ?6,
             failed_count = ?7, checkpoint_ordinal = ?8, updated_at = ?9,
             completed_at = CASE WHEN ?1 = 'completed' THEN ?9 ELSE NULL END
         WHERE id = ?10",
        rusqlite::params![
            status, counts.0, counts.1, counts.2, counts.3, counts.4, counts.5, counts.7, now,
            run_id,
        ],
    )?;
    Ok(())
}

fn mark_resume_attempt(vault: &Vault, run_id: &str) -> Result<(), IngestionError> {
    let now = chrono::Utc::now().to_rfc3339();
    vault.conn().execute(
        "UPDATE conversation_ingestion_runs
         SET status = 'running', retry_count = retry_count + 1,
             error_code = NULL, safe_error_summary = NULL, updated_at = ?1,
             completed_at = NULL WHERE id = ?2",
        rusqlite::params![now, run_id],
    )?;
    Ok(())
}

fn fail_run(
    vault: &Vault,
    run_id: &str,
    issue: IngestionIssue,
    retry: bool,
) -> Result<(), IngestionError> {
    let now = chrono::Utc::now().to_rfc3339();
    vault.conn().execute(
        "UPDATE conversation_ingestion_runs
         SET status = 'failed', failed_count = failed_count + 1,
             retry_count = retry_count + ?1,
             error_code = ?2, safe_error_summary = ?3,
             updated_at = ?4, completed_at = ?4 WHERE id = ?5",
        rusqlite::params![
            i64::from(retry),
            issue.code(),
            issue.safe_summary(),
            now,
            run_id
        ],
    )?;
    Ok(())
}

fn item_statuses(
    vault: &Vault,
    run_id: &str,
) -> Result<Vec<(usize, IngestionItemStatus)>, IngestionError> {
    let mut statement = vault.conn().prepare(
        "SELECT ordinal, status FROM conversation_ingestion_items
         WHERE run_id = ?1 ORDER BY ordinal",
    )?;
    let rows = statement
        .query_map([run_id], |row| {
            Ok((
                row.get::<_, i64>(0)? as usize,
                IngestionItemStatus::parse(&row.get::<_, String>(1)?),
            ))
        })?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

fn load_items(vault: &Vault, run_id: &str) -> Result<Vec<IngestionItemReport>, IngestionError> {
    let mut statement = vault.conn().prepare(
        "SELECT id, ordinal, source_conversation_id, source_digest, status,
                persisted_conversation_id, previous_persisted_conversation_id,
                derived_text_id, derivation_hash, embedding_model_version,
                error_code, safe_error_summary, retry_count
         FROM conversation_ingestion_items WHERE run_id = ?1 ORDER BY ordinal",
    )?;
    let rows = statement
        .query_map([run_id], |row| {
            Ok(IngestionItemReport {
                id: row.get(0)?,
                ordinal: row.get::<_, i64>(1)? as u64,
                source_conversation_id: row.get(2)?,
                source_digest: row.get(3)?,
                status: IngestionItemStatus::parse(&row.get::<_, String>(4)?),
                persisted_conversation_id: row.get(5)?,
                previous_persisted_conversation_id: row.get(6)?,
                derived_text_id: row.get(7)?,
                derivation_hash: row.get(8)?,
                embedding_model_version: row.get(9)?,
                error_code: row.get(10)?,
                safe_error_summary: row.get(11)?,
                retry_count: row.get::<_, i64>(12)? as u64,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

fn finish_transaction(
    vault: &Vault,
    result: Result<(), IngestionError>,
) -> Result<(), IngestionError> {
    match result {
        Ok(()) => {
            if let Err(error) = vault.conn().execute_batch("COMMIT") {
                let _ = vault.conn().execute_batch("ROLLBACK");
                Err(error.into())
            } else {
                Ok(())
            }
        }
        Err(error) => {
            let _ = vault.conn().execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

fn validate_component(label: &str, value: &ComponentVersion) -> Result<(), IngestionError> {
    if value.name.is_empty() || value.version.is_empty() {
        return Err(IngestionError::ParserContract(format!(
            "{label} name and version must not be empty"
        )));
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

fn parse_source_product(value: &str) -> Result<SourceProduct, IngestionError> {
    match value {
        "claude_code" => Ok(SourceProduct::ClaudeCode),
        "claude" => Ok(SourceProduct::Claude),
        "chatgpt" => Ok(SourceProduct::Chatgpt),
        other => Err(IngestionError::ParserContract(format!(
            "unknown persisted source product {other}"
        ))),
    }
}

fn item_status_str(status: IngestionItemStatus) -> &'static str {
    match status {
        IngestionItemStatus::Pending => "pending",
        IngestionItemStatus::Imported => "imported",
        IngestionItemStatus::Unchanged => "unchanged",
        IngestionItemStatus::Updated => "updated",
        IngestionItemStatus::Quarantined => "quarantined",
        IngestionItemStatus::Failed => "failed",
    }
}

fn stable_item_id(run_id: &str, ordinal: usize, source_id: &str) -> String {
    stable_id("citem", &[run_id, &ordinal.to_string(), source_id])
}

fn stable_replacement_id(prior: &str, replacement: &str) -> String {
    stable_id("crepl", &[prior, replacement])
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
    use crate::crypto::KdfParams;
    use crate::space;

    const FIXTURE: &str = include_str!("../../../../tests/fixtures/conversation-tree.json");
    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    #[derive(Clone)]
    struct FakeParser {
        parser_version: String,
        normalizer_version: String,
        candidates: Vec<ConversationCandidate>,
        top_failure: Option<IngestionIssue>,
    }

    impl FakeParser {
        fn new(candidates: Vec<ConversationCandidate>) -> Self {
            Self {
                parser_version: "1".into(),
                normalizer_version: "1".into(),
                candidates,
                top_failure: None,
            }
        }
    }

    impl ConversationSourceParser for FakeParser {
        fn source_product(&self) -> SourceProduct {
            SourceProduct::Chatgpt
        }

        fn parser(&self) -> ComponentVersion {
            ComponentVersion {
                name: "fake-chatgpt".into(),
                version: self.parser_version.clone(),
            }
        }

        fn normalizer(&self) -> ComponentVersion {
            ComponentVersion {
                name: "tessera-conversation".into(),
                version: self.normalizer_version.clone(),
            }
        }

        fn export_id(&self) -> Option<String> {
            Some("fake-export".into())
        }

        fn parse(&self, _source: &[u8]) -> Result<Vec<ConversationCandidate>, IngestionIssue> {
            self.top_failure
                .map_or_else(|| Ok(self.candidates.clone()), Err)
        }
    }

    fn setup() -> (tempfile::TempDir, Vault, SpaceId) {
        let directory = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(
            &directory.path().join("Ingestion.tessera"),
            "test",
            &TEST_PARAMS,
        )
        .expect("vault");
        let space_id = space::create(&vault, "Conversations", None).expect("space");
        (directory, vault, space_id)
    }

    fn source_version(vault: &Vault, space_id: &SpaceId, name: &str, content: &[u8]) -> String {
        let artifact_id = artifact::register(
            vault,
            space_id,
            name,
            "application/json",
            Sensitivity::Restricted,
        )
        .expect("source artifact");
        let hash = vault
            .blobs()
            .put(vault.dek().expect("unlocked"), content)
            .expect("source blob");
        artifact::record_version(vault, &artifact_id, &hash, content.len() as u64)
            .expect("source version")
            .id
    }

    fn conversation(id: &str, text_suffix: &str) -> Conversation {
        let archive = ConversationArchive::from_json(FIXTURE).expect("fixture");
        let mut conversation = archive.conversations[0].clone();
        conversation.conversation_id = id.into();
        conversation.title = Some(format!("Synthetic {id}"));
        conversation.nodes[1].content_parts[0].text =
            Some(format!("Which implementation? {text_suffix}"));
        conversation.validate().expect("conversation");
        conversation
    }

    fn run(
        vault: &Vault,
        space_id: &SpaceId,
        source_version: &str,
        parser: &FakeParser,
    ) -> IngestionRunReport {
        ingest(
            vault,
            space_id,
            source_version,
            parser,
            &IngestionOptions::default(),
        )
        .expect("ingest")
    }

    fn scalar(vault: &Vault, sql: &str) -> i64 {
        vault
            .conn()
            .query_row(sql, [], |row| row.get(0))
            .expect("scalar")
    }

    #[test]
    fn duplicate_archive_is_unchanged_without_duplicate_graph_or_chunks() {
        let (_directory, vault, space_id) = setup();
        let source = source_version(&vault, &space_id, "one.json", b"same immutable export");
        let parser = FakeParser::new(vec![ConversationCandidate::conversation(conversation(
            "conv_a", "v1",
        ))]);
        let first = run(&vault, &space_id, &source, &parser);
        assert_eq!((first.imported, first.unchanged), (1, 0));
        let graph_counts = (
            scalar(&vault, "SELECT COUNT(*) FROM conversations"),
            scalar(&vault, "SELECT COUNT(*) FROM conversation_nodes"),
            scalar(&vault, "SELECT COUNT(*) FROM chunks"),
        );
        let second = run(&vault, &space_id, &source, &parser);
        assert_eq!((second.imported, second.unchanged), (0, 1));
        assert_eq!(
            graph_counts,
            (
                scalar(&vault, "SELECT COUNT(*) FROM conversations"),
                scalar(&vault, "SELECT COUNT(*) FROM conversation_nodes"),
                scalar(&vault, "SELECT COUNT(*) FROM chunks"),
            )
        );

        let other_space = space::create(&vault, "Other conversations", None).expect("other space");
        let conflict = run(&vault, &other_space, &source, &parser);
        assert_eq!(
            (conflict.imported, conflict.unchanged, conflict.failed),
            (0, 0, 1)
        );
        assert_eq!(conflict.items[0].status, IngestionItemStatus::Failed);
        assert_eq!(
            conflict.items[0].error_code.as_deref(),
            Some("target_space_conflict")
        );
        assert_eq!(scalar(&vault, "SELECT COUNT(*) FROM artifacts"), 2);
    }

    #[test]
    fn superset_imports_only_delta_and_corrected_source_records_replacement() {
        let (_directory, vault, space_id) = setup();
        let source_v1 = source_version(&vault, &space_id, "v1.json", b"archive v1");
        let parser_v1 = FakeParser::new(vec![ConversationCandidate::conversation(conversation(
            "conv_a", "v1",
        ))]);
        let first = run(&vault, &space_id, &source_v1, &parser_v1);
        let first_id = first.items[0]
            .persisted_conversation_id
            .clone()
            .expect("persisted");

        let source_v2 = source_version(&vault, &space_id, "v2.json", b"archive v1 plus b");
        let parser_v2 = FakeParser::new(vec![
            ConversationCandidate::conversation(conversation("conv_a", "v1")),
            ConversationCandidate::conversation(conversation("conv_b", "v1")),
        ]);
        let superset = run(&vault, &space_id, &source_v2, &parser_v2);
        assert_eq!(
            (superset.imported, superset.unchanged, superset.updated),
            (1, 1, 0)
        );
        assert_eq!(scalar(&vault, "SELECT COUNT(*) FROM conversations"), 2);

        let source_v3 = source_version(&vault, &space_id, "v3.json", b"corrected archive");
        let parser_v3 = FakeParser::new(vec![
            ConversationCandidate::conversation(conversation("conv_a", "corrected")),
            ConversationCandidate::conversation(conversation("conv_b", "v1")),
        ]);
        let corrected = run(&vault, &space_id, &source_v3, &parser_v3);
        assert_eq!(
            (corrected.imported, corrected.unchanged, corrected.updated),
            (0, 1, 1)
        );
        let updated = corrected
            .items
            .iter()
            .find(|item| item.source_conversation_id == "conv_a")
            .expect("updated item");
        assert_eq!(updated.status, IngestionItemStatus::Updated);
        assert_eq!(
            updated.previous_persisted_conversation_id.as_deref(),
            Some(first_id.as_str())
        );
        let relationship: String = vault
            .conn()
            .query_row(
                "SELECT relationship FROM conversation_ingestion_replacements
                 WHERE replacement_conversation_id = ?1",
                [updated
                    .persisted_conversation_id
                    .as_deref()
                    .expect("new id")],
                |row| row.get(0),
            )
            .expect("replacement");
        assert_eq!(relationship, "corrected_source");
    }

    #[test]
    fn parser_upgrade_regenerates_without_losing_prior_provenance() {
        let (_directory, vault, space_id) = setup();
        let source = source_version(&vault, &space_id, "upgrade.json", b"upgrade source");
        let parser_v1 = FakeParser::new(vec![ConversationCandidate::conversation(conversation(
            "conv_a", "same",
        ))]);
        let first = run(&vault, &space_id, &source, &parser_v1);
        let mut parser_v2 = parser_v1.clone();
        parser_v2.parser_version = "2".into();
        let upgraded = run(&vault, &space_id, &source, &parser_v2);
        assert_eq!((upgraded.updated, upgraded.unchanged), (1, 0));
        assert_ne!(
            first.items[0].persisted_conversation_id,
            upgraded.items[0].persisted_conversation_id
        );
        assert_eq!(scalar(&vault, "SELECT COUNT(*) FROM conversations"), 2);
        let relationship: String = vault
            .conn()
            .query_row(
                "SELECT relationship FROM conversation_ingestion_replacements",
                [],
                |row| row.get(0),
            )
            .expect("replacement");
        assert_eq!(relationship, "parser_upgrade");
    }

    #[test]
    fn interrupted_run_resumes_and_reconciles_a_post_commit_ledger_gap() {
        let (_directory, vault, space_id) = setup();
        let source = source_version(&vault, &space_id, "resume.json", b"resume source");
        let parser = FakeParser::new(vec![
            ConversationCandidate::conversation(conversation("conv_a", "v1")),
            ConversationCandidate::conversation(conversation("conv_b", "v1")),
        ]);
        let interrupted = ingest(
            &vault,
            &space_id,
            &source,
            &parser,
            &IngestionOptions {
                max_items: Some(1),
                resume_run_id: None,
            },
        )
        .expect("partial ingest");
        assert_eq!(interrupted.status, IngestionRunStatus::Interrupted);
        assert_eq!(
            (interrupted.imported, interrupted.checkpoint_ordinal),
            (1, 1)
        );
        assert_eq!(interrupted.target_space_id, space_id.0);

        let other_space = space::create(&vault, "Other conversations", None).expect("other space");
        let target_drift = ingest(
            &vault,
            &other_space,
            &source,
            &parser,
            &IngestionOptions {
                max_items: None,
                resume_run_id: Some(interrupted.id.clone()),
            },
        )
        .expect_err("target drift must fail closed");
        assert!(matches!(target_drift, IngestionError::ResumeDrift(_)));

        let mut drifted = parser.clone();
        drifted.candidates[1] =
            ConversationCandidate::conversation(conversation("conv_b", "drifted"));
        let drift_error = ingest(
            &vault,
            &space_id,
            &source,
            &drifted,
            &IngestionOptions {
                max_items: None,
                resume_run_id: Some(interrupted.id.clone()),
            },
        )
        .expect_err("drift must fail closed");
        assert!(matches!(drift_error, IngestionError::ResumeDrift(_)));
        let preserved = get_ingestion_run(&vault, &interrupted.id).expect("preserved run");
        assert_eq!(preserved.status, IngestionRunStatus::Interrupted);
        assert_eq!(preserved.retry_count, 0);

        // Simulate the narrow crash window after conversation persistence but
        // before its run-ledger/head update. Resume must reconcile the exact
        // committed derivation rather than duplicate it.
        let first_item = &interrupted.items[0];
        vault
            .conn()
            .execute(
                "DELETE FROM conversation_ingestion_heads
                 WHERE source_product = 'chatgpt' AND source_conversation_id = 'conv_a'",
                [],
            )
            .expect("fault head");
        vault
            .conn()
            .execute(
                "UPDATE conversation_ingestion_items
                 SET status = 'pending', persisted_conversation_id = NULL,
                     derived_text_id = NULL, derivation_hash = NULL, completed_at = NULL
                 WHERE id = ?1",
                [&first_item.id],
            )
            .expect("fault item");

        let resumed = ingest(
            &vault,
            &space_id,
            &source,
            &parser,
            &IngestionOptions {
                max_items: None,
                resume_run_id: Some(interrupted.id.clone()),
            },
        )
        .expect("resume");
        assert_eq!(resumed.status, IngestionRunStatus::Completed);
        assert_eq!(
            (resumed.imported, resumed.unchanged, resumed.retry_count),
            (2, 0, 1)
        );
        assert_eq!(scalar(&vault, "SELECT COUNT(*) FROM conversations"), 2);
        assert_eq!(
            scalar(&vault, "SELECT COUNT(*) FROM conversation_ingestion_heads"),
            2
        );
    }

    #[test]
    fn interrupted_run_can_restart_without_duplicates_then_reconcile_original_checkpoint() {
        let (_directory, vault, space_id) = setup();
        let source = source_version(&vault, &space_id, "restart.json", b"restart source");
        let parser = FakeParser::new(vec![
            ConversationCandidate::conversation(conversation("conv_a", "v1")),
            ConversationCandidate::conversation(conversation("conv_b", "v1")),
        ]);
        let interrupted = ingest(
            &vault,
            &space_id,
            &source,
            &parser,
            &IngestionOptions {
                max_items: Some(1),
                resume_run_id: None,
            },
        )
        .expect("partial ingest");

        let restarted = run(&vault, &space_id, &source, &parser);
        assert_eq!(restarted.status, IngestionRunStatus::Completed);
        assert_eq!((restarted.imported, restarted.unchanged), (1, 1));
        assert_eq!(scalar(&vault, "SELECT COUNT(*) FROM conversations"), 2);
        let chunk_count = scalar(&vault, "SELECT COUNT(*) FROM chunks");

        let reconciled = ingest(
            &vault,
            &space_id,
            &source,
            &parser,
            &IngestionOptions {
                max_items: None,
                resume_run_id: Some(interrupted.id),
            },
        )
        .expect("reconcile original run");
        assert_eq!(reconciled.status, IngestionRunStatus::Completed);
        assert_eq!((reconciled.imported, reconciled.unchanged), (1, 1));
        assert_eq!(scalar(&vault, "SELECT COUNT(*) FROM conversations"), 2);
        assert_eq!(scalar(&vault, "SELECT COUNT(*) FROM chunks"), chunk_count);
    }

    #[test]
    fn malformed_sibling_is_quarantined_without_source_plaintext_or_batch_failure() {
        let (_directory, vault, space_id) = setup();
        let secret = b"PRIVATE SOURCE SENTENCE MUST NOT ENTER THE RUN LEDGER";
        let source = source_version(&vault, &space_id, "malformed.json", secret);
        let mut invalid = conversation("conv_invalid", "v1");
        invalid.selected_path.push("missing-node".into());
        let parser = FakeParser::new(vec![
            ConversationCandidate::conversation(conversation("conv_valid", "v1")),
            ConversationCandidate::quarantined("conv_bad", IngestionIssue::ChangedFieldType),
            ConversationCandidate::conversation(invalid),
        ]);
        let report = run(&vault, &space_id, &source, &parser);
        assert_eq!(report.status, IngestionRunStatus::Completed);
        assert_eq!(
            (report.imported, report.quarantined, report.failed),
            (1, 2, 0)
        );
        assert_eq!(scalar(&vault, "SELECT COUNT(*) FROM conversations"), 1);
        let ledger_text: String = vault
            .conn()
            .query_row(
                "SELECT COALESCE(group_concat(safe_error_summary, ' '), '')
                 FROM conversation_ingestion_items WHERE run_id = ?1",
                [&report.id],
                |row| row.get(0),
            )
            .expect("ledger errors");
        assert!(!ledger_text.contains("PRIVATE SOURCE SENTENCE"));
        let source_hash: String = vault
            .conn()
            .query_row(
                "SELECT source_hash FROM conversation_ingestion_runs WHERE id = ?1",
                [&report.id],
                |row| row.get(0),
            )
            .expect("source hash");
        assert_eq!(
            vault
                .blobs()
                .get(vault.dek().expect("dek"), &BlobHash(source_hash))
                .expect("immutable raw"),
            secret
        );
    }

    #[test]
    fn top_level_parser_failure_is_safe_evidence_and_cannot_be_resumed() {
        let (_directory, vault, space_id) = setup();
        let secret = b"PRIVATE SOURCE SENTENCE MUST NOT ENTER A PARSER ERROR";
        let source = source_version(&vault, &space_id, "failed.json", secret);
        let mut parser = FakeParser::new(Vec::new());
        parser.top_failure = Some(IngestionIssue::ParserFailure);

        let report = run(&vault, &space_id, &source, &parser);
        assert_eq!(report.status, IngestionRunStatus::Failed);
        assert_eq!(
            (report.discovered, report.failed, report.retry_count),
            (0, 1, 0)
        );
        assert!(report.items.is_empty());
        assert_eq!(report.error_code.as_deref(), Some("parser_failure"));
        assert!(!report
            .safe_error_summary
            .as_deref()
            .expect("safe summary")
            .contains("PRIVATE SOURCE SENTENCE"));

        let retry = ingest(
            &vault,
            &space_id,
            &source,
            &parser,
            &IngestionOptions {
                max_items: None,
                resume_run_id: Some(report.id.clone()),
            },
        )
        .expect_err("failed run must remain immutable evidence");
        assert!(matches!(retry, IngestionError::FailedRunNotResumable(_)));
        assert_eq!(
            get_ingestion_run(&vault, &report.id)
                .expect("failed run")
                .status,
            IngestionRunStatus::Failed
        );
    }
}
