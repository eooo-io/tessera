//! Integrity diagnostics and consistency-barrier backup.
//!
//! Reports identifiers and counts only: never plaintext, passphrases, keys, or
//! decrypted snippets. Repairs are deliberately separate owner actions.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::blob::BlobHash;
use crate::vault::Vault;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityClass {
    Ok,
    Repairable,
    Fatal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityCheck {
    pub component: String,
    pub class: IntegrityClass,
    pub affected: usize,
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub schema: String,
    pub checks: Vec<IntegrityCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedRebuildReport {
    pub artifacts_moved_to_pending: usize,
    pub extracted: usize,
    pub chunked: usize,
    pub summarized: usize,
    pub failed: usize,
}

impl IntegrityReport {
    pub fn is_healthy(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.class == IntegrityClass::Ok)
    }

    pub fn has_fatal(&self) -> bool {
        self.checks
            .iter()
            .any(|check| check.class == IntegrityClass::Fatal)
    }
}

#[derive(Error, Debug)]
pub enum RecoveryError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("database open error: {0}")]
    DatabaseOpen(#[from] crate::db::DbError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("receipt verification failed: {0}")]
    Receipt(#[from] crate::receipt::ReceiptError),
    #[error("vault error: {0}")]
    Vault(#[from] crate::vault::VaultError),
    #[error("artifact error: {0}")]
    Artifact(#[from] crate::artifact::ArtifactError),
    #[error("review-state error: {0}")]
    Review(#[from] crate::review::ReviewError),
    #[error("backup destination already exists: {0}")]
    DestinationExists(PathBuf),
    #[error("backup destination must be outside the source vault: {0}")]
    DestinationInsideSource(PathBuf),
    #[error("backup refused while {0} Guardian session(s) are active; revoke or let them expire")]
    ActiveSessions(usize),
    #[error("backup refused because source diagnostics contain fatal integrity findings")]
    SourceFatal,
    #[error("derived rebuild refused because diagnostics contain fatal integrity findings")]
    RebuildFatal,
}

fn check(component: &str, class: IntegrityClass, affected: usize, action: &str) -> IntegrityCheck {
    IntegrityCheck {
        component: component.into(),
        class,
        affected,
        action: action.into(),
    }
}

fn scalar(conn: &rusqlite::Connection, sql: &str) -> Result<usize, rusqlite::Error> {
    conn.query_row(sql, [], |row| row.get::<_, i64>(0))
        .map(|value| value as usize)
}

/// Check all durable trust boundaries without returning decrypted content.
pub fn diagnose(vault: &Vault) -> Result<IntegrityReport, RecoveryError> {
    let conn = vault.conn();
    let quick: String = conn.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    let fk = scalar(conn, "SELECT COUNT(*) FROM pragma_foreign_key_check")?;

    let source_hashes: Vec<String> = {
        let mut stmt = conn.prepare("SELECT DISTINCT blob_hash FROM artifact_versions")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let dek = vault.dek()?;
    let mut bad_sources = 0;
    for hash in &source_hashes {
        if vault.blobs().get(dek, &BlobHash(hash.clone())).is_err() {
            bad_sources += 1;
        }
    }

    let derived_hashes: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT blob_hash FROM derived_text UNION SELECT blob_hash FROM summaries")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let mut bad_derived = 0;
    for hash in &derived_hashes {
        if vault.blobs().get(dek, &BlobHash(hash.clone())).is_err() {
            bad_derived += 1;
        }
    }
    let provenance_hashes: Vec<String> = {
        let mut stmt = conn.prepare("SELECT DISTINCT derived_blob_hash FROM provenance")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let referenced_blobs: HashSet<String> = source_hashes
        .iter()
        .chain(derived_hashes.iter())
        .chain(provenance_hashes.iter())
        .cloned()
        .collect();
    let mut orphan_blobs = 0;
    for shard in std::fs::read_dir(vault.path().join("blobs"))? {
        let shard = shard?;
        if !shard.file_type()?.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(shard.path())? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.len() == 64 && !referenced_blobs.contains(&name) {
                orphan_blobs += 1;
            }
        }
    }

    let mut bad_chunks = 0;
    {
        let mut stmt = conn.prepare(
            "SELECT ch.byte_offset_start, ch.byte_offset_end, ch.content_hash, dt.blob_hash
             FROM chunks ch JOIN derived_text dt ON dt.id = ch.derived_text_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)? as usize,
                row.get::<_, i64>(1)? as usize,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (start, end, expected_hash, blob_hash) = row?;
            match vault.blobs().get(dek, &BlobHash(blob_hash)) {
                Ok(bytes) => {
                    let text = std::str::from_utf8(&bytes).ok();
                    let slice = text.and_then(|value| value.get(start..end));
                    if slice
                        .map(|value| blake3::hash(value.as_bytes()).to_hex().to_string())
                        .as_deref()
                        != Some(expected_hash.as_str())
                    {
                        bad_chunks += 1;
                    }
                }
                Err(_) => bad_chunks += 1,
            }
        }
    }

    let missing_chunks = scalar(
        conn,
        "SELECT COUNT(*) FROM derived_text dt
         WHERE NOT EXISTS (SELECT 1 FROM chunks ch WHERE ch.derived_text_id = dt.id)",
    )?;
    let missing_embeddings = scalar(
        conn,
        "SELECT COUNT(*) FROM chunks ch
         WHERE NOT EXISTS (SELECT 1 FROM embeddings_map em WHERE em.chunk_id = ch.id)",
    )?;
    let orphan_embedding_rows = scalar(
        conn,
        "SELECT COUNT(*) FROM embeddings_map em
         WHERE NOT EXISTS (SELECT 1 FROM chunk_embeddings ce WHERE ce.rowid = em.vec_rowid)",
    )?;
    let orphan_vector_rows = scalar(
        conn,
        "SELECT COUNT(*) FROM chunk_embeddings ce
         WHERE NOT EXISTS (SELECT 1 FROM embeddings_map em WHERE em.vec_rowid = ce.rowid)",
    )?;
    let malformed_vectors = scalar(
        conn,
        "SELECT COUNT(*) FROM chunk_embeddings WHERE length(embedding) != 1536",
    )?;
    let registered_models: HashSet<String> = vault
        .manifest()
        .embedding_models
        .iter()
        .map(|model| model.version.clone())
        .collect();
    let indexed_models: Vec<String> = {
        let mut stmt = conn.prepare("SELECT DISTINCT model_version FROM embeddings_map")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let unregistered_models = indexed_models
        .iter()
        .filter(|version| !registered_models.contains(*version))
        .count();
    let unresolved_processing = scalar(
        conn,
        "SELECT COUNT(*) FROM processing_errors WHERE resolved_at IS NULL",
    )?;
    let incomplete_artifacts = scalar(
        conn,
        "SELECT COUNT(*) FROM artifacts a
         WHERE NOT EXISTS (SELECT 1 FROM artifact_versions av WHERE av.artifact_id = a.id)",
    )?;
    let abandoned_staging = std::fs::read_dir(vault.path().join("inbox"))?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .map(|name| name.starts_with('.') && name.ends_with(".partial"))
                .unwrap_or(false)
        })
        .count();
    let invalid_lenses = crate::lens::list(vault).map(|_| 0).unwrap_or(1);
    let invalid_sessions = scalar(
        conn,
        "SELECT COUNT(*) FROM sessions s
         LEFT JOIN pairings p ON p.id = s.pairing_id
         LEFT JOIN lenses l ON l.id = s.lens_id
         WHERE s.status = 'active' AND julianday(s.expires_at) > julianday('now')
           AND (p.id IS NULL OR l.id IS NULL OR p.revoked_at IS NOT NULL
                OR p.lens_updated_at IS NULL OR p.lens_updated_at != l.updated_at)",
    )?;
    let orphaned_derivations = crate::provenance::orphaned_derivations(vault)
        .map(|items| items.len())
        .unwrap_or(1);
    let receipt_failure = crate::receipt::verify(vault).is_err() as usize;

    let mut checks = vec![
        check(
            "manifest_keyslots",
            IntegrityClass::Ok,
            0,
            "vault opened and key material authenticated",
        ),
        check(
            "sqlite",
            if quick == "ok" {
                IntegrityClass::Ok
            } else {
                IntegrityClass::Fatal
            },
            usize::from(quick != "ok"),
            "restore a verified backup; do not fabricate database rows",
        ),
        check(
            "foreign_keys",
            if fk == 0 {
                IntegrityClass::Ok
            } else {
                IntegrityClass::Fatal
            },
            fk,
            "restore a verified backup or investigate referential corruption",
        ),
        check(
            "original_blobs",
            if bad_sources == 0 {
                IntegrityClass::Ok
            } else {
                IntegrityClass::Fatal
            },
            bad_sources,
            "authenticated source ciphertext cannot be reconstructed; restore from backup",
        ),
        check(
            "derived_blobs",
            if bad_derived == 0 {
                IntegrityClass::Ok
            } else {
                IntegrityClass::Repairable
            },
            bad_derived,
            "owner may rebuild derived data from authenticated originals",
        ),
        check(
            "chunks",
            if missing_chunks + bad_chunks == 0 {
                IntegrityClass::Ok
            } else {
                IntegrityClass::Repairable
            },
            missing_chunks + bad_chunks,
            "owner may rebuild chunks from authenticated derived text",
        ),
        check(
            "embeddings",
            if missing_embeddings
                + orphan_embedding_rows
                + orphan_vector_rows
                + malformed_vectors
                + unregistered_models
                == 0
            {
                IntegrityClass::Ok
            } else {
                IntegrityClass::Repairable
            },
            missing_embeddings
                + orphan_embedding_rows
                + orphan_vector_rows
                + malformed_vectors
                + unregistered_models,
            "run the explicit model reindex command after reviewing this report",
        ),
        check(
            "orphan_blobs",
            if orphan_blobs == 0 {
                IntegrityClass::Ok
            } else {
                IntegrityClass::Repairable
            },
            orphan_blobs,
            "retain for investigation; Tessera never silently deletes unreferenced ciphertext",
        ),
        check(
            "processing_state",
            if unresolved_processing + incomplete_artifacts + abandoned_staging == 0 {
                IntegrityClass::Ok
            } else {
                IntegrityClass::Repairable
            },
            unresolved_processing + incomplete_artifacts + abandoned_staging,
            "pending items retain actionable per-stage errors for owner review",
        ),
        check(
            "lenses_sessions",
            if invalid_lenses + invalid_sessions == 0 {
                IntegrityClass::Ok
            } else {
                IntegrityClass::Fatal
            },
            invalid_lenses + invalid_sessions,
            "repair policy JSON only from an owner-reviewed export or backup",
        ),
        check(
            "provenance",
            if orphaned_derivations == 0 {
                IntegrityClass::Ok
            } else {
                IntegrityClass::Repairable
            },
            orphaned_derivations,
            "owner may rebuild missing derivations from authenticated originals",
        ),
        check(
            "receipts",
            if receipt_failure == 0 {
                IntegrityClass::Ok
            } else {
                IntegrityClass::Fatal
            },
            receipt_failure,
            "receipt-chain corruption is evidence; restore, never rewrite it",
        ),
    ];
    checks.sort_by(|a, b| a.component.cmp(&b.component));
    Ok(IntegrityReport {
        schema: "tessera.integrity-report.v1".into(),
        checks,
    })
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            copy_file_synced(&entry.path(), &target)?;
        }
    }
    std::fs::File::open(destination)?.sync_all()?;
    Ok(())
}

fn copy_file_synced(source: &Path, destination: &Path) -> Result<(), std::io::Error> {
    std::fs::copy(source, destination)?;
    std::fs::File::open(destination)?.sync_all()
}

/// Create a portable bundle snapshot. Active Guardian sessions fail loudly;
/// an immediate DB barrier blocks concurrent writers while immutable/authenticated
/// files and a SQLite online-backup snapshot are copied.
pub fn backup(vault: &Vault, destination: &Path) -> Result<(), RecoveryError> {
    if destination.exists() {
        return Err(RecoveryError::DestinationExists(destination.to_path_buf()));
    }
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let source_absolute = std::fs::canonicalize(vault.path())?;
    let destination_absolute =
        std::fs::canonicalize(parent)?.join(destination.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing backup filename")
        })?);
    if destination_absolute.starts_with(&source_absolute) {
        return Err(RecoveryError::DestinationInsideSource(
            destination.to_path_buf(),
        ));
    }
    let active = scalar(
        vault.conn(),
        "SELECT COUNT(*) FROM sessions
         WHERE status = 'active' AND julianday(expires_at) > julianday('now')",
    )?;
    if active > 0 {
        return Err(RecoveryError::ActiveSessions(active));
    }
    if diagnose(vault)?.has_fatal() {
        return Err(RecoveryError::SourceFatal);
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let staging = parent.join(format!(
        ".{}.backup-staging-{}-{nonce}",
        destination
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("vault"),
        std::process::id()
    ));
    // Use a dedicated connection for the writer barrier. SQLite's online
    // backup API cannot advance when its own source connection holds a write
    // transaction, but a sibling reader can snapshot while this connection
    // excludes every other writer.
    let barrier = crate::db::open_database(&vault.path().join("vault.db"))?;
    barrier.execute_batch("BEGIN IMMEDIATE")?;
    std::fs::create_dir(&staging)?;
    let result = (|| -> Result<(), RecoveryError> {
        for file in ["tessera.json", "keyslot.bin"] {
            copy_file_synced(&vault.path().join(file), &staging.join(file))?;
        }
        for dir in ["blobs", "receipts", "inbox"] {
            copy_tree(&vault.path().join(dir), &staging.join(dir))?;
        }
        let mut destination_db = rusqlite::Connection::open(staging.join("vault.db"))?;
        let snapshot = rusqlite::backup::Backup::new(vault.conn(), &mut destination_db)?;
        snapshot.run_to_completion(128, Duration::from_millis(10), None)?;
        drop(snapshot);
        destination_db.close().map_err(|(_, error)| error)?;
        std::fs::File::open(staging.join("vault.db"))?.sync_all()?;
        std::fs::File::open(&staging)?.sync_all()?;
        Ok(())
    })();
    let _ = barrier.execute_batch("ROLLBACK");
    if let Err(error) = result {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&staging, destination) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(error.into());
    }
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Explicitly rebuild recoverable derived state from authenticated originals.
/// Existing source rows/blobs, receipts, lenses, and provenance history are
/// untouched. Previously live artifacts move back to pending before derived
/// rows are removed, so no agent can observe a half-rebuilt item.
pub fn rebuild_derived(vault: &Vault) -> Result<DerivedRebuildReport, RecoveryError> {
    let integrity = diagnose(vault)?;
    if integrity.has_fatal() {
        return Err(RecoveryError::RebuildFatal);
    }
    let active = scalar(
        vault.conn(),
        "SELECT COUNT(*) FROM sessions
         WHERE status = 'active' AND julianday(expires_at) > julianday('now')",
    )?;
    if active > 0 {
        return Err(RecoveryError::ActiveSessions(active));
    }

    let artifacts: Vec<(crate::ArtifactId, String)> = {
        let mut stmt = vault
            .conn()
            .prepare("SELECT id, state FROM artifacts WHERE state != 'archived' ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok((crate::ArtifactId(row.get(0)?), row.get::<_, String>(1)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let mut moved = 0;
    for (artifact, state) in &artifacts {
        if state == "live" {
            crate::artifact::set_state(vault, artifact, crate::artifact::ArtifactState::Pending)?;
            moved += 1;
        }
    }

    vault.conn().execute_batch("BEGIN IMMEDIATE")?;
    let cleared = (|| -> Result<(), rusqlite::Error> {
        vault
            .conn()
            .execute("DELETE FROM reindex_embeddings_map", [])?;
        vault
            .conn()
            .execute("DELETE FROM reindex_chunk_embeddings", [])?;
        vault.conn().execute("DELETE FROM reindex_state", [])?;
        vault.conn().execute("DELETE FROM embeddings_map", [])?;
        vault.conn().execute("DELETE FROM chunk_embeddings", [])?;
        vault.conn().execute("DELETE FROM summaries", [])?;
        vault.conn().execute("DELETE FROM chunks", [])?;
        vault.conn().execute("DELETE FROM derived_text", [])?;
        vault.conn().execute_batch("COMMIT")?;
        Ok(())
    })();
    if let Err(error) = cleared {
        let _ = vault.conn().execute_batch("ROLLBACK");
        return Err(error.into());
    }

    let mut report = DerivedRebuildReport {
        artifacts_moved_to_pending: moved,
        extracted: 0,
        chunked: 0,
        summarized: 0,
        failed: 0,
    };
    for (artifact, _) in artifacts {
        match crate::extract::extract_text(vault, &artifact) {
            Ok(Some(derived)) => {
                report.extracted += 1;
                match crate::chunk::chunk_derived_text(
                    vault,
                    &derived,
                    &crate::chunk::ChunkParams::default(),
                ) {
                    Ok(_) => {
                        report.chunked += 1;
                        crate::review::resolve_processing_error(vault, &artifact, "extract")?;
                        crate::review::resolve_processing_error(vault, &artifact, "chunk")?;
                    }
                    Err(error) => {
                        crate::review::record_processing_error(
                            vault,
                            &artifact,
                            "chunk",
                            &error.to_string(),
                        )?;
                        report.failed += 1;
                        continue;
                    }
                }
                match crate::summary::generate(vault, &artifact, true) {
                    Ok(_) => {
                        report.summarized += 1;
                        crate::review::resolve_processing_error(vault, &artifact, "summary")?;
                    }
                    Err(error) => {
                        crate::review::record_processing_error(
                            vault,
                            &artifact,
                            "summary",
                            &error.to_string(),
                        )?;
                        report.failed += 1;
                    }
                }
            }
            Ok(None) => {}
            Err(error) => {
                crate::review::record_processing_error(
                    vault,
                    &artifact,
                    "extract",
                    &error.to_string(),
                )?;
                report.failed += 1;
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactState;
    use crate::crypto::KdfParams;
    use crate::embed::{EmbedError, EmbeddingProvider};
    use crate::{artifact, inbox, space};

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    struct TestEmbedder;
    impl EmbeddingProvider for TestEmbedder {
        fn embed(&self, _text: &str) -> Result<Vec<f32>, EmbedError> {
            let mut vector = vec![0.0; 384];
            vector[0] = 1.0;
            Ok(vector)
        }

        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
            texts.iter().map(|text| self.embed(text)).collect()
        }

        fn model_version(&self) -> &str {
            "recovery-test@1"
        }

        fn dimensions(&self) -> usize {
            384
        }

        fn calibrated_relevance_floor(&self) -> Option<f32> {
            Some(0.0)
        }
    }

    fn vault_with_original() -> (tempfile::TempDir, Vault, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("vault");
        let space = space::create(&vault, "Evidence", None).expect("space");
        let source = dir.path().join("source.md");
        std::fs::write(&source, b"immutable source identity").expect("source");
        inbox::add(&vault, &[source]).expect("stage");
        let report = inbox::process(&vault, &space).expect("process");
        let artifact_id = report.ingested[0].1.clone();
        artifact::set_state(&vault, &artifact_id, ArtifactState::Live).expect("live");
        (dir, vault, artifact_id.0)
    }

    #[test]
    fn missing_authenticated_original_is_fatal_without_fabricated_repair() {
        let (dir, vault, artifact_id) = vault_with_original();
        let hash: String = vault
            .conn()
            .query_row(
                "SELECT blob_hash FROM artifact_versions WHERE artifact_id = ?1",
                [artifact_id],
                |row| row.get(0),
            )
            .expect("hash");
        vault
            .blobs()
            .delete(&BlobHash(hash))
            .expect("fault injection");

        let report = diagnose(&vault).expect("diagnose");
        let originals = report
            .checks
            .iter()
            .find(|item| item.component == "original_blobs")
            .expect("original check");
        assert_eq!(originals.class, IntegrityClass::Fatal);
        assert_eq!(originals.affected, 1);
        assert!(!originals.action.contains("rebuild"));
        let destination = dir.path().join("MustNotExist.tessera");
        assert!(matches!(
            backup(&vault, &destination),
            Err(RecoveryError::SourceFatal)
        ));
        assert!(!destination.exists());
    }

    #[test]
    fn backup_restores_same_source_identity_at_new_path() {
        let (dir, vault, artifact_id) = vault_with_original();
        let artifact = crate::ArtifactId(artifact_id.clone());
        let derived = crate::extract::extract_text(&vault, &artifact)
            .expect("extract")
            .expect("text");
        crate::chunk::chunk_derived_text(&vault, &derived, &crate::chunk::ChunkParams::default())
            .expect("chunk");
        crate::search::embed_missing(&vault, &TestEmbedder).expect("embed");
        let lens = crate::lens::LensPolicy::new("Backup evidence", vec![]);
        let mut receipt_session = crate::receipt::Session::open(
            &vault,
            crate::receipt::AgentRef {
                agent_id: "agent_backup_test".into(),
                name: "Backup test".into(),
            },
            &lens,
            "receipt continuity",
            false,
        )
        .expect("receipt session");
        receipt_session.record_rate_limit("vault_query", "bounded test event");
        receipt_session.finalize().expect("receipt finalize");
        let destination = dir.path().join("Restored.tessera");
        backup(&vault, &destination).expect("backup");
        assert!(!destination.join("vault.db-wal").exists());
        assert!(!destination.join("vault.db-shm").exists());

        let restored = Vault::open(&destination, "pass").expect("restore open");
        let restored_id: String = restored
            .conn()
            .query_row(
                "SELECT artifact_id FROM artifact_versions WHERE artifact_id = ?1",
                [artifact_id.as_str()],
                |row| row.get(0),
            )
            .expect("identity continuity");
        assert_eq!(restored_id, artifact_id);
        assert_eq!(
            crate::receipt::verify(&restored).expect("receipt continuity"),
            1
        );
        let results = crate::search::query(
            &restored,
            &TestEmbedder,
            "identity",
            &crate::search::owner_constraints(),
            5,
        )
        .expect("query continuity");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].artifact_id.0, artifact_id);
        assert!(!diagnose(&restored).expect("restore diagnose").has_fatal());
    }

    #[test]
    fn partial_bundle_fails_loudly() {
        let (dir, vault, _artifact_id) = vault_with_original();
        let partial = dir.path().join("Partial.tessera");
        backup(&vault, &partial).expect("backup");
        std::fs::remove_file(partial.join("keyslot.bin")).expect("fault injection");
        assert!(Vault::open(&partial, "pass").is_err());
    }

    #[test]
    fn owner_derived_rebuild_preserves_source_identity_and_returns_live_items_to_pending() {
        let (_dir, vault, artifact_id) = vault_with_original();
        let artifact = crate::ArtifactId(artifact_id.clone());
        let derived = crate::extract::extract_text(&vault, &artifact)
            .expect("extract")
            .expect("text");
        crate::chunk::chunk_derived_text(&vault, &derived, &crate::chunk::ChunkParams::default())
            .expect("chunk");
        crate::summary::generate(&vault, &artifact, false).expect("summary");
        let source_before: String = vault
            .conn()
            .query_row(
                "SELECT blob_hash FROM artifact_versions WHERE artifact_id = ?1",
                [artifact_id.as_str()],
                |row| row.get(0),
            )
            .expect("source before");

        let rebuilt = rebuild_derived(&vault).expect("rebuild");
        assert_eq!(rebuilt.artifacts_moved_to_pending, 1);
        assert_eq!(rebuilt.extracted, 1);
        assert_eq!(rebuilt.chunked, 1);
        let source_after: String = vault
            .conn()
            .query_row(
                "SELECT blob_hash FROM artifact_versions WHERE artifact_id = ?1",
                [artifact_id.as_str()],
                |row| row.get(0),
            )
            .expect("source after");
        assert_eq!(source_after, source_before);
        assert!(vault
            .blobs()
            .get(vault.dek().expect("dek"), &BlobHash(source_after))
            .is_ok());
        assert_eq!(
            crate::artifact::get(&vault, &artifact)
                .expect("artifact")
                .state,
            ArtifactState::Pending
        );
        assert_eq!(
            scalar(vault.conn(), "SELECT COUNT(*) FROM embeddings_map").unwrap(),
            0
        );
        assert!(crate::receipt::verify(&vault).is_ok());
    }

    #[test]
    fn corrupted_chunk_is_repairable_and_never_returned_as_content() {
        let (_dir, vault, artifact_id) = vault_with_original();
        let artifact = crate::ArtifactId(artifact_id);
        let derived = crate::extract::extract_text(&vault, &artifact)
            .expect("extract")
            .expect("text");
        crate::chunk::chunk_derived_text(&vault, &derived, &crate::chunk::ChunkParams::default())
            .expect("chunk");
        vault
            .conn()
            .execute("UPDATE chunks SET content_hash = 'tampered'", [])
            .expect("fault injection");

        let report = diagnose(&vault).expect("diagnose");
        let chunks = report
            .checks
            .iter()
            .find(|item| item.component == "chunks")
            .expect("chunks check");
        assert_eq!(chunks.class, IntegrityClass::Repairable);
        assert_eq!(chunks.affected, 1);
        let serialized = serde_json::to_string(&report).expect("serialize report");
        assert!(!serialized.contains("immutable source identity"));
    }

    #[test]
    fn backup_refuses_an_active_guardian_session() {
        let (dir, vault, _artifact_id) = vault_with_original();
        let space_id = crate::space::list(&vault).expect("spaces")[0].id.clone();
        let lens = crate::lens::LensPolicy::new("Active backup lens", vec![space_id]);
        let lens_id = crate::lens::create(&vault, &lens).expect("lens");
        let pairing =
            crate::pairing::approve(&vault, &lens_id, "backup exclusion", "active-agent", 5)
                .expect("pairing");
        crate::session::start(&vault, &pairing).expect("active session");
        assert!(!diagnose(&vault)
            .expect("valid active diagnostics")
            .has_fatal());
        let error = backup(&vault, &dir.path().join("Blocked.tessera"))
            .expect_err("active backup must fail");
        assert!(matches!(error, RecoveryError::ActiveSessions(1)));
    }

    #[test]
    fn orphaned_ciphertext_is_reported_and_not_deleted() {
        let (_dir, vault, _artifact_id) = vault_with_original();
        let orphan = vault
            .blobs()
            .put(
                vault.dek().expect("dek"),
                b"crash-before-database-registration",
            )
            .expect("orphan fault injection");
        let report = diagnose(&vault).expect("diagnose");
        let orphan_check = report
            .checks
            .iter()
            .find(|item| item.component == "orphan_blobs")
            .expect("orphan check");
        assert_eq!(orphan_check.class, IntegrityClass::Repairable);
        assert_eq!(orphan_check.affected, 1);
        assert!(
            vault.blobs().exists(&orphan),
            "diagnostics must not delete evidence"
        );
    }

    #[test]
    fn duplicate_chunk_and_embedding_map_rows_are_rejected() {
        let (_dir, vault, artifact_id) = vault_with_original();
        let artifact = crate::ArtifactId(artifact_id);
        let derived = crate::extract::extract_text(&vault, &artifact)
            .expect("extract")
            .expect("text");
        crate::chunk::chunk_derived_text(&vault, &derived, &crate::chunk::ChunkParams::default())
            .expect("chunk");
        crate::search::embed_missing(&vault, &TestEmbedder).expect("embed");

        let duplicate_chunk = vault.conn().execute(
            "INSERT INTO chunks
               (id, derived_text_id, chunk_index, byte_offset_start, byte_offset_end,
                token_count, content_hash, section_heading, created_at)
             SELECT 'chunk_duplicate_fault', derived_text_id, chunk_index, byte_offset_start,
                    byte_offset_end, token_count, content_hash, section_heading, created_at
             FROM chunks LIMIT 1",
            [],
        );
        assert!(duplicate_chunk.is_err());
        let duplicate_map = vault.conn().execute(
            "INSERT INTO embeddings_map (chunk_id, vec_rowid, model_version, created_at)
             SELECT chunk_id, vec_rowid + 1000, model_version, created_at
             FROM embeddings_map LIMIT 1",
            [],
        );
        assert!(duplicate_map.is_err());
        assert!(!diagnose(&vault).expect("diagnose").has_fatal());

        vault
            .conn()
            .execute("DELETE FROM embeddings_map", [])
            .expect("missing-map fault injection");
        let report = diagnose(&vault).expect("diagnose missing map");
        let embeddings = report
            .checks
            .iter()
            .find(|item| item.component == "embeddings")
            .expect("embedding check");
        assert_eq!(embeddings.class, IntegrityClass::Repairable);
        assert!(
            embeddings.affected >= 2,
            "missing map and orphan vector are distinct"
        );
    }
}
