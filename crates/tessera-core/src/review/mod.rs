//! Owner quarantine review — inspection, retry, classification, and promotion.
//!
//! Review content is decrypted only into memory for the owner's CLI. Nothing
//! in this module writes plaintext previews to disk.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::artifact::{self, Artifact, ArtifactError, ArtifactId, ArtifactState, Sensitivity};
use crate::blob::{BlobError, BlobHash};
use crate::provenance::{self, ProvenanceError, ProvenanceRecord};
use crate::space::SpaceId;
use crate::vault::{Vault, VaultError};

#[derive(Error, Debug)]
pub enum ReviewError {
    #[error("artifact error: {0}")]
    Artifact(#[from] ArtifactError),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("blob error: {0}")]
    Blob(#[from] BlobError),
    #[error("provenance error: {0}")]
    Provenance(#[from] ProvenanceError),
    #[error("extraction error: {0}")]
    Extract(#[from] crate::extract::ExtractError),
    #[error("chunking error: {0}")]
    Chunk(#[from] crate::chunk::ChunkError),
    #[error("summary error: {0}")]
    Summary(#[from] crate::summary::SummaryError),
    #[error("image understanding error: {0}")]
    Image(#[from] crate::image::ImageError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("artifact is not pending: {0}")]
    NotPending(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingErrorRecord {
    pub stage: String,
    pub message: String,
    pub occurred_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewItem {
    pub artifact: Artifact,
    pub artifact_version_id: String,
    pub version: u32,
    pub original_blob_hash: String,
    pub original_size_bytes: u64,
    pub encrypted_original_present: bool,
    pub extractor: Option<String>,
    pub extractor_version: Option<String>,
    pub preview: Option<String>,
    pub summary_present: bool,
    pub provenance: Vec<ProvenanceRecord>,
    pub tags: Vec<String>,
    pub chunk_count: u32,
    pub embedding_count: u32,
    pub processing_errors: Vec<ProcessingErrorRecord>,
    pub warnings: Vec<String>,
    pub ready_for_promotion: bool,
}

fn latest_version(
    vault: &Vault,
    artifact: &ArtifactId,
) -> Result<(String, u32, String, u64), ReviewError> {
    Ok(vault.conn().query_row(
        "SELECT id, version, blob_hash, size_bytes FROM artifact_versions
         WHERE artifact_id = ?1 ORDER BY version DESC LIMIT 1",
        [artifact.0.as_str()],
        |row| {
            Ok((
                row.get(0)?,
                row.get::<_, i64>(1)? as u32,
                row.get(2)?,
                row.get::<_, i64>(3)? as u64,
            ))
        },
    )?)
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

/// Record one bounded active processing error, superseding an older error for
/// the same artifact/stage. Error metadata is plaintext and must not include
/// source content, credentials, or secrets.
pub fn record_processing_error(
    vault: &Vault,
    artifact: &ArtifactId,
    stage: &str,
    message: &str,
) -> Result<(), ReviewError> {
    let conn = vault.conn();
    let now = chrono::Utc::now().to_rfc3339();
    let bounded = truncate_chars(message, 1000);
    conn.execute_batch("BEGIN")?;
    let result = (|| -> Result<(), ReviewError> {
        conn.execute(
            "UPDATE processing_errors SET resolved_at = ?1
             WHERE artifact_id = ?2 AND stage = ?3 AND resolved_at IS NULL",
            rusqlite::params![now, artifact.0, stage],
        )?;
        conn.execute(
            "INSERT INTO processing_errors
               (id, artifact_id, stage, message, occurred_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                format!("perr_{}", ulid::Ulid::new()),
                artifact.0,
                stage,
                bounded,
                now
            ],
        )?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

pub fn resolve_processing_error(
    vault: &Vault,
    artifact: &ArtifactId,
    stage: &str,
) -> Result<(), ReviewError> {
    vault.conn().execute(
        "UPDATE processing_errors SET resolved_at = ?1
         WHERE artifact_id = ?2 AND stage = ?3 AND resolved_at IS NULL",
        rusqlite::params![chrono::Utc::now().to_rfc3339(), artifact.0, stage],
    )?;
    Ok(())
}

/// Build the evidence shown before an owner can promote one pending artifact.
pub fn inspect(
    vault: &Vault,
    artifact_id: &ArtifactId,
    preview_chars: usize,
) -> Result<ReviewItem, ReviewError> {
    let artifact = artifact::get(vault, artifact_id)?;
    let (version_id, version, original_blob_hash, original_size_bytes) =
        latest_version(vault, artifact_id)?;
    let encrypted_original_present = vault.blobs().exists(&BlobHash(original_blob_hash.clone()));

    let derived = vault
        .conn()
        .query_row(
            "SELECT id, blob_hash, extractor, extractor_version FROM derived_text
             WHERE artifact_version_id = ?1 ORDER BY created_at DESC, id DESC LIMIT 1",
            [version_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })?;

    let (derived_id, extractor, extractor_version, preview, empty_extraction) =
        if let Some((derived_id, blob_hash, extractor, extractor_version)) = derived {
            let bytes = vault.blobs().get(vault.dek()?, &BlobHash(blob_hash))?;
            let text = String::from_utf8_lossy(&bytes).into_owned();
            let empty = text.trim().is_empty();
            (
                Some(derived_id),
                Some(extractor),
                Some(extractor_version),
                Some(truncate_chars(&text, preview_chars)),
                empty,
            )
        } else {
            (None, None, None, None, false)
        };

    let (chunk_count, embedding_count) = if let Some(derived_id) = &derived_id {
        vault.conn().query_row(
            "SELECT COUNT(ch.id), COUNT(em.chunk_id)
             FROM chunks ch
             LEFT JOIN embeddings_map em ON em.chunk_id = ch.id
             WHERE ch.derived_text_id = ?1",
            [derived_id.as_str()],
            |row| Ok((row.get::<_, i64>(0)? as u32, row.get::<_, i64>(1)? as u32)),
        )?
    } else {
        (0, 0)
    };
    let summary_present: bool = vault.conn().query_row(
        "SELECT EXISTS(SELECT 1 FROM summaries WHERE artifact_version_id = ?1)",
        [version_id.as_str()],
        |row| row.get(0),
    )?;
    let mut error_stmt = vault.conn().prepare(
        "SELECT stage, message, occurred_at FROM processing_errors
         WHERE artifact_id = ?1 AND resolved_at IS NULL
         ORDER BY occurred_at, id",
    )?;
    let processing_errors = error_stmt
        .query_map([artifact_id.0.as_str()], |row| {
            Ok(ProcessingErrorRecord {
                stage: row.get(0)?,
                message: row.get(1)?,
                occurred_at: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut warnings = Vec::new();
    if !encrypted_original_present {
        warnings.push("encrypted original is missing".into());
    }
    if derived_id.is_none() {
        warnings.push("no supported extraction is available or extraction failed".into());
    } else if empty_extraction {
        warnings.push("extraction produced no reviewable text".into());
    }
    if derived_id.is_some() && chunk_count == 0 {
        warnings.push("no chunks were produced".into());
    }
    if !summary_present {
        warnings.push("no stored summary is available".into());
    }
    if chunk_count > 0 && embedding_count == 0 {
        warnings
            .push("chunks are not embedded yet; semantic retrieval will not find this item".into());
    }
    if !processing_errors.is_empty() {
        warnings.push(format!(
            "{} unresolved processing error(s)",
            processing_errors.len()
        ));
    }
    let ready_for_promotion = encrypted_original_present
        && derived_id.is_some()
        && !empty_extraction
        && chunk_count > 0
        && processing_errors.is_empty();

    Ok(ReviewItem {
        artifact,
        artifact_version_id: version_id,
        version,
        original_blob_hash,
        original_size_bytes,
        encrypted_original_present,
        extractor,
        extractor_version,
        preview,
        summary_present,
        provenance: provenance::chain_for(vault, artifact_id)?,
        tags: artifact::tags_of(vault, artifact_id)?,
        chunk_count,
        embedding_count,
        processing_errors,
        warnings,
        ready_for_promotion,
    })
}

/// Retry the local text processing stages, preserving pending state.
pub fn retry_processing(vault: &Vault, artifact: &ArtifactId) -> Result<ReviewItem, ReviewError> {
    retry_processing_with(vault, artifact, None)
}

/// Retry processing, optionally supplying an image understanding provider.
///
/// Images take a different route than documents: they have no text layer, so
/// OCR and a caption become their searchable surface. The provider is passed
/// in rather than constructed here because loading a vision model is
/// expensive and may legitimately be unavailable — an owner without the model
/// installed should still be able to retry a PDF.
pub fn retry_processing_with(
    vault: &Vault,
    artifact: &ArtifactId,
    image_provider: Option<&dyn crate::image::ImageUnderstandingProvider>,
) -> Result<ReviewItem, ReviewError> {
    let metadata = artifact::get(vault, artifact)?;
    if metadata.state != ArtifactState::Pending {
        return Err(ReviewError::NotPending(artifact.0.clone()));
    }
    if crate::image::decode::is_supported(&metadata.media_type) {
        let Some(provider) = image_provider else {
            record_processing_error(
                vault,
                artifact,
                "image",
                "no image understanding provider is available",
            )?;
            return inspect(vault, artifact, 400);
        };
        match crate::image::understand_and_chunk(
            vault,
            artifact,
            provider,
            &crate::image::ImageUnderstandingOptions::default(),
        ) {
            Ok(_) => resolve_processing_error(vault, artifact, "image")?,
            Err(error) => {
                record_processing_error(vault, artifact, "image", &error.to_string())?;
                return Err(error.into());
            }
        }
        return inspect(vault, artifact, 400);
    }
    let derived = match crate::extract::extract_text(vault, artifact) {
        Ok(derived) => {
            resolve_processing_error(vault, artifact, "extract")?;
            derived
        }
        Err(error) => {
            record_processing_error(vault, artifact, "extract", &error.to_string())?;
            return Err(error.into());
        }
    };
    if let Some(derived) = derived {
        if let Err(error) =
            crate::chunk::chunk_derived_text(vault, &derived, &crate::chunk::ChunkParams::default())
        {
            record_processing_error(vault, artifact, "chunk", &error.to_string())?;
            return Err(error.into());
        }
        resolve_processing_error(vault, artifact, "chunk")?;
        if let Err(error) = crate::summary::generate(vault, artifact, false) {
            record_processing_error(vault, artifact, "summary", &error.to_string())?;
            return Err(error.into());
        }
        resolve_processing_error(vault, artifact, "summary")?;
    }
    inspect(vault, artifact, 400)
}

/// Apply owner classification changes and promote in one database transaction.
pub fn classify_and_promote(
    vault: &Vault,
    artifact: &ArtifactId,
    space: Option<&SpaceId>,
    tags: Option<&[String]>,
    sensitivity: Option<Sensitivity>,
    actor: &str,
) -> Result<(), ReviewError> {
    let conn = vault.conn();
    conn.execute_batch("BEGIN")?;
    let result = (|| -> Result<(), ReviewError> {
        let current = artifact::get(vault, artifact)?;
        if current.state != ArtifactState::Pending {
            return Err(ReviewError::NotPending(artifact.0.clone()));
        }
        if let Some(space) = space {
            conn.execute(
                "UPDATE artifacts SET space_id = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![space.0, chrono::Utc::now().to_rfc3339(), artifact.0],
            )?;
        }
        if let Some(sensitivity) = sensitivity {
            conn.execute(
                "UPDATE artifacts SET sensitivity = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![
                    sensitivity.as_str(),
                    chrono::Utc::now().to_rfc3339(),
                    artifact.0
                ],
            )?;
        }
        if let Some(tags) = tags {
            conn.execute(
                "DELETE FROM artifact_tags WHERE artifact_id = ?1",
                [artifact.0.as_str()],
            )?;
            for tag in tags {
                conn.execute(
                    "INSERT OR IGNORE INTO tags (id, name) VALUES (?1, ?2)",
                    rusqlite::params![format!("tag_{}", ulid::Ulid::new()), tag],
                )?;
                let tag_id: String =
                    conn.query_row("SELECT id FROM tags WHERE name = ?1", [tag], |row| {
                        row.get(0)
                    })?;
                conn.execute(
                    "INSERT INTO artifact_tags (artifact_id, tag_id) VALUES (?1, ?2)",
                    rusqlite::params![artifact.0, tag_id],
                )?;
            }
        }
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE artifacts SET state = 'live', updated_at = ?1 WHERE id = ?2",
            rusqlite::params![now, artifact.0],
        )?;
        conn.execute(
            "INSERT INTO state_transitions
               (id, artifact_id, from_state, to_state, actor, created_at)
             VALUES (?1, ?2, 'pending', 'live', ?3, ?4)",
            rusqlite::params![
                format!("strn_{}", ulid::Ulid::new()),
                artifact.0,
                actor,
                now
            ],
        )?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

/// Promote a confirmed review batch atomically; either every still-pending
/// artifact is made live with the batch audit actor or none are.
pub fn promote_batch(
    vault: &Vault,
    artifacts: &[ArtifactId],
    actor: &str,
) -> Result<(), ReviewError> {
    let conn = vault.conn();
    conn.execute_batch("BEGIN")?;
    let result = (|| -> Result<(), ReviewError> {
        for artifact in artifacts {
            let state: String = conn
                .query_row(
                    "SELECT state FROM artifacts WHERE id = ?1",
                    [artifact.0.as_str()],
                    |row| row.get(0),
                )
                .map_err(|error| match error {
                    rusqlite::Error::QueryReturnedNoRows => {
                        ReviewError::Artifact(ArtifactError::NotFound(artifact.0.clone()))
                    }
                    other => ReviewError::Database(other),
                })?;
            if state != "pending" {
                return Err(ReviewError::NotPending(artifact.0.clone()));
            }
            let now = chrono::Utc::now().to_rfc3339();
            conn.execute(
                "UPDATE artifacts SET state = 'live', updated_at = ?1 WHERE id = ?2",
                rusqlite::params![now, artifact.0],
            )?;
            conn.execute(
                "INSERT INTO state_transitions
                   (id, artifact_id, from_state, to_state, actor, created_at)
                 VALUES (?1, ?2, 'pending', 'live', ?3, ?4)",
                rusqlite::params![
                    format!("strn_{}", ulid::Ulid::new()),
                    artifact.0,
                    actor,
                    now
                ],
            )?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::{chunk, extract, inbox, space, summary};

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    fn pending_text() -> (tempfile::TempDir, Vault, ArtifactId, SpaceId) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("vault");
        let space = space::create(&vault, "Inbox", None).expect("space");
        let file = dir.path().join("review.md");
        std::fs::write(&file, "Exact owner review preview with provenance.").expect("write");
        inbox::add(&vault, &[file]).expect("add");
        let artifact = inbox::process(&vault, &space).expect("process").ingested[0]
            .1
            .clone();
        let derived = extract::extract_text(&vault, &artifact)
            .expect("extract")
            .expect("derived");
        chunk::chunk_derived_text(&vault, &derived, &chunk::ChunkParams::default()).expect("chunk");
        summary::generate(&vault, &artifact, false).expect("summary");
        (dir, vault, artifact, space)
    }

    #[test]
    fn inspection_exposes_owner_evidence_without_promoting() {
        let (_dir, vault, artifact, _space) = pending_text();
        let item = inspect(&vault, &artifact, 20).expect("inspect");
        assert_eq!(item.artifact.state, ArtifactState::Pending);
        assert!(item.encrypted_original_present);
        assert_eq!(item.preview.as_deref(), Some("Exact owner review p"));
        assert_eq!(item.chunk_count, 1);
        assert!(item.summary_present);
        assert!(!item.provenance.is_empty());
        assert!(item.ready_for_promotion);
    }

    #[test]
    fn processing_errors_block_readiness_until_resolved() {
        let (_dir, vault, artifact, _space) = pending_text();
        record_processing_error(&vault, &artifact, "extract", "sanitized failure").expect("record");
        let blocked = inspect(&vault, &artifact, 20).expect("inspect blocked");
        assert!(!blocked.ready_for_promotion);
        assert_eq!(blocked.processing_errors.len(), 1);
        assert_eq!(blocked.processing_errors[0].message, "sanitized failure");
        resolve_processing_error(&vault, &artifact, "extract").expect("resolve");
        assert!(
            inspect(&vault, &artifact, 20)
                .expect("inspect ready")
                .ready_for_promotion
        );
    }

    #[test]
    fn classification_and_promotion_are_audited_together() {
        let (_dir, vault, artifact, _space) = pending_text();
        let target = space::create(&vault, "Reviewed", None).expect("target");
        classify_and_promote(
            &vault,
            &artifact,
            Some(&target),
            Some(&["alpha".into(), "beta".into()]),
            Some(Sensitivity::Restricted),
            "owner:review_edit_accept",
        )
        .expect("promote");
        let promoted = artifact::get(&vault, &artifact).expect("artifact");
        assert_eq!(promoted.state, ArtifactState::Live);
        assert_eq!(promoted.space_id, target);
        assert_eq!(promoted.sensitivity, Sensitivity::Restricted);
        assert_eq!(
            artifact::tags_of(&vault, &artifact).expect("tags"),
            vec!["alpha".to_string(), "beta".to_string()]
        );
        assert_eq!(
            artifact::latest_transition_actor(&vault, &artifact)
                .expect("actor")
                .as_deref(),
            Some("owner:review_edit_accept")
        );
    }

    #[test]
    fn batch_promotion_rolls_back_if_any_item_is_not_pending() {
        let (_dir, vault, pending, space) = pending_text();
        let file = vault.path().join("inbox").join("other.md");
        std::fs::write(&file, "other").expect("write staged");
        let other = inbox::process(&vault, &space).expect("process").ingested[0]
            .1
            .clone();
        artifact::set_state(&vault, &other, ArtifactState::Live).expect("make live");

        assert!(matches!(
            promote_batch(
                &vault,
                &[pending.clone(), other],
                "owner:review_batch_accept"
            ),
            Err(ReviewError::NotPending(_))
        ));
        assert_eq!(
            artifact::get(&vault, &pending).expect("pending").state,
            ArtifactState::Pending,
            "batch rollback preserves every earlier item"
        );
    }
}
