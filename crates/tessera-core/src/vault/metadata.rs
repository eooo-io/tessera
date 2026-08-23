//! Private manifest metadata and explicit format-v3 migration.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{EmbeddingModelEntry, VaultError, VaultManifest, FORMAT_VERSION};
use crate::blob::BlobStore;
use crate::crypto::KeyslotFile;
use crate::db::DbError;

const CREATED_AT: &str = "created_at";
const EMBEDDING_MODELS: &str = "embedding_models";
const MANIFEST_EXTENSIONS: &str = "manifest_extensions";
const MARKER_NAME: &str = ".metadata-migration-v3";
const MARKER_TEMP_NAME: &str = ".metadata-migration-v3.tmp";
const PREPARED_NAME: &str = ".vault.db.v3.prepared";
const RETIRED_NAME: &str = ".vault.db.v2.retired";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataMigrationReport {
    pub migrated: bool,
    pub resumed: bool,
    pub converted_blobs: usize,
    pub source_schema_version: u32,
}

#[derive(Error, Debug)]
pub enum MetadataMigrationError {
    #[error("metadata migration state is malformed or unsupported")]
    InvalidState,
    #[error("metadata migration requires a legacy format-v1 or format-v2 vault")]
    NotLegacy,
    #[error("metadata migration is blocked by {count} active Guardian session(s)")]
    ActiveSessions { count: usize },
    #[error("metadata migration validation failed: {0}")]
    Validation(String),
    #[error("metadata migration was interrupted after {0}")]
    Interrupted(&'static str),
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    Database(#[from] DbError),
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Receipt(#[from] crate::receipt::ReceiptError),
}

impl MetadataMigrationError {
    /// Stable, content-free failure class for user-facing migration output.
    /// Internal error variants may contain paths, logical hashes, receipt IDs,
    /// or database details and must never be rendered by the CLI.
    pub fn safe_code(&self) -> &'static str {
        match self {
            Self::InvalidState | Self::Json(_) => "invalid_state",
            Self::NotLegacy => "not_legacy",
            Self::ActiveSessions { .. } => "active_sessions",
            Self::Validation(_) => "validation_failed",
            Self::Interrupted(_) => "interrupted",
            Self::Vault(VaultError::BadPassphrase) => "bad_passphrase",
            Self::Vault(_) => "vault_error",
            Self::Database(_) | Self::Sql(_) => "database_error",
            Self::Io(_) => "io_error",
            Self::Receipt(_) => "receipt_error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MigrationPhase {
    Started,
    BlobsProtected,
    DatabasePrepared,
    DatabaseSelected,
    ManifestCommitted,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrationMarker {
    version: u32,
    phase: MigrationPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MigrationFailpoint {
    None,
    AfterBlobs,
    AfterPrepare,
    BeforeExportStorageFull,
    AfterPrepareConcurrentCommit,
    DuringExclusiveSelection,
    #[cfg(test)]
    DuringExclusiveLegacyBlobWrite,
    AfterRetire,
    AfterSelect,
    AfterManifest,
    DuringV3Cleanup,
}

fn serialize<T: serde::Serialize>(value: &T) -> Result<String, DbError> {
    serde_json::to_string(value).map_err(|error| {
        DbError::MigrationFailed(format!("private vault metadata serialization: {error}"))
    })
}

fn deserialize<T: serde::de::DeserializeOwned>(value: &str) -> Result<T, DbError> {
    serde_json::from_str(value).map_err(|error| {
        DbError::MigrationFailed(format!("private vault metadata is malformed: {error}"))
    })
}

fn put_json(conn: &Connection, key: &str, value_json: &str) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO vault_metadata (key, value_json, updated_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET
             value_json = excluded.value_json,
             updated_at = excluded.updated_at",
        params![key, value_json, chrono::Utc::now().to_rfc3339()],
    )?;
    Ok(())
}

fn required_json(conn: &Connection, key: &str) -> Result<String, DbError> {
    conn.query_row(
        "SELECT value_json FROM vault_metadata WHERE key = ?1",
        [key],
        |row| row.get::<_, String>(0),
    )
    .map_err(|error| match error {
        rusqlite::Error::QueryReturnedNoRows => {
            DbError::MigrationFailed("required private vault metadata is missing".into())
        }
        other => DbError::QueryFailed(other),
    })
}

pub(crate) fn initialize_from_manifest(
    conn: &Connection,
    manifest: &VaultManifest,
) -> Result<(), DbError> {
    if let Some(created_at) = manifest.created_at {
        put_json(conn, CREATED_AT, &serialize(&created_at)?)?;
    }
    put_json(
        conn,
        EMBEDDING_MODELS,
        &serialize(&manifest.embedding_models)?,
    )?;
    let extensions = serde_json::json!({
        "top_level": manifest.extra,
        "crypto": manifest.crypto.extra,
    });
    put_json(conn, MANIFEST_EXTENSIONS, &serialize(&extensions)?)?;
    Ok(())
}

pub(crate) fn hydrate_manifest(
    conn: &Connection,
    manifest: &mut VaultManifest,
) -> Result<(), DbError> {
    manifest.created_at = Some(deserialize(&required_json(conn, CREATED_AT)?)?);
    manifest.embedding_models = deserialize(&required_json(conn, EMBEDDING_MODELS)?)?;
    let extensions: serde_json::Value = deserialize(&required_json(conn, MANIFEST_EXTENSIONS)?)?;
    let object = extensions.as_object().ok_or_else(|| {
        DbError::MigrationFailed("private manifest extensions are malformed".into())
    })?;
    manifest.extra = object
        .get("top_level")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .ok_or_else(|| {
            DbError::MigrationFailed("private top-level extensions are malformed".into())
        })?;
    manifest.crypto.extra = object
        .get("crypto")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .ok_or_else(|| {
            DbError::MigrationFailed("private crypto extensions are malformed".into())
        })?;
    Ok(())
}

pub(crate) fn embedding_models(conn: &Connection) -> Result<Vec<EmbeddingModelEntry>, DbError> {
    let value = conn
        .query_row(
            "SELECT value_json FROM vault_metadata WHERE key = ?1",
            [EMBEDDING_MODELS],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    match value {
        Some(value) => deserialize(&value),
        None => Ok(Vec::new()),
    }
}

pub(crate) fn register_embedding_model(
    conn: &Connection,
    entry: EmbeddingModelEntry,
) -> Result<(), DbError> {
    let mut models = embedding_models(conn)?;
    if !models.iter().any(|model| model.version == entry.version) {
        models.push(entry);
        put_json(conn, EMBEDDING_MODELS, &serialize(&models)?)?;
    }
    Ok(())
}

pub(crate) fn migration_in_progress(path: &Path) -> bool {
    path.join(MARKER_NAME).exists()
        || path.join(MARKER_TEMP_NAME).exists()
        || path.join(PREPARED_NAME).exists()
        || path.join(RETIRED_NAME).exists()
}

pub(crate) fn migrate(
    path: &Path,
    passphrase: &str,
) -> Result<MetadataMigrationReport, MetadataMigrationError> {
    migrate_at(path, passphrase, MigrationFailpoint::None)
}

fn migrate_at(
    path: &Path,
    passphrase: &str,
    failpoint: MigrationFailpoint,
) -> Result<MetadataMigrationReport, MetadataMigrationError> {
    crate::vault::permissions::validate_migration_layout(path)?;
    crate::vault::permissions::harden_tree(path)?;
    let manifest_path = path.join("tessera.json");
    let mut manifest = VaultManifest::load(&manifest_path).map_err(VaultError::from)?;
    let keyslots = KeyslotFile::load(&path.join("keyslot.bin")).map_err(VaultError::from)?;
    let dek = keyslots.unlock(passphrase).map_err(VaultError::from)?;
    let marker_path = path.join(MARKER_NAME);
    let resumed = migration_in_progress(path);

    if manifest.format_version == FORMAT_VERSION {
        if !resumed {
            validate_protected_state(path, &path.join("vault.db"), &manifest, &dek)?;
            let conn = crate::db::open_database(&path.join("vault.db"), &dek)?;
            return Ok(MetadataMigrationReport {
                migrated: false,
                resumed: false,
                converted_blobs: 0,
                source_schema_version: crate::db::migrations::schema_version(&conn)?,
            });
        }
        if !marker_path.is_file() || path.join(PREPARED_NAME).exists() {
            return Err(MetadataMigrationError::InvalidState);
        }
        let marker = load_marker_or_default(path)?;
        if marker.version != FORMAT_VERSION
            || !matches!(
                marker.phase,
                MigrationPhase::DatabaseSelected | MigrationPhase::ManifestCommitted
            )
        {
            return Err(MetadataMigrationError::InvalidState);
        }
        let blobs = BlobStore::open(&path.join("blobs")).map_err(VaultError::from)?;
        let converted_blobs = blobs.migrate_legacy_blobs(&dek).map_err(VaultError::from)?;
        let conn = crate::db::open_database(&path.join("vault.db"), &dek)?;
        validate_database(&conn)?;
        hydrate_manifest(&conn, &mut manifest)?;
        let retired_path = path.join(RETIRED_NAME);
        let retired_barrier = if retired_path.is_file() {
            let retired = crate::db::open_plaintext_database(&path.join(RETIRED_NAME))?;
            validate_database(&retired)?;
            retired.execute_batch("BEGIN EXCLUSIVE")?;
            let active = active_sessions(&retired)?;
            if active > 0 {
                return Err(MetadataMigrationError::ActiveSessions { count: active });
            }
            compare_logical_inventory(&retired, &conn)?;
            if failpoint == MigrationFailpoint::DuringV3Cleanup {
                let competing = rusqlite::Connection::open(&retired_path)?;
                competing.busy_timeout(std::time::Duration::ZERO)?;
                if competing.execute_batch("BEGIN IMMEDIATE").is_ok() {
                    let _ = competing.execute_batch("ROLLBACK");
                    return Err(MetadataMigrationError::Validation(
                        "v3 cleanup boundary admitted a competing writer".into(),
                    ));
                }
            }
            Some(retired)
        } else {
            None
        };
        let source_schema_version = if let Some(retired) = retired_barrier.as_ref() {
            crate::db::migrations::schema_version(retired)?
        } else {
            crate::db::migrations::schema_version(&conn)?
        };
        drop(conn);
        validate_protected_state(path, &path.join("vault.db"), &manifest, &dek)?;
        let late_blobs = blobs.migrate_legacy_blobs(&dek).map_err(VaultError::from)?;
        if late_blobs > 0 {
            return Err(MetadataMigrationError::Validation(
                "legacy blob set changed during protected-state recovery".into(),
            ));
        }
        remove_if_exists(&path.join(PREPARED_NAME))?;
        if let Some(retired) = retired_barrier {
            remove_if_exists(&retired_path)?;
            retired.execute_batch("ROLLBACK")?;
            drop(retired);
        }
        remove_database_and_sidecars(&retired_path)?;
        remove_if_exists(&marker_path)?;
        remove_if_exists(&path.join(MARKER_TEMP_NAME))?;
        sync_directory(path)?;
        return Ok(MetadataMigrationReport {
            migrated: false,
            resumed: true,
            converted_blobs,
            source_schema_version,
        });
    }
    if manifest.format_version == 0 || manifest.format_version > 2 {
        return Err(MetadataMigrationError::NotLegacy);
    }

    if !marker_path.is_file()
        && (path.join(PREPARED_NAME).exists() || path.join(RETIRED_NAME).exists())
    {
        return Err(MetadataMigrationError::InvalidState);
    }
    let marker = load_marker_or_default(path)?;
    if marker.version != FORMAT_VERSION {
        return Err(MetadataMigrationError::InvalidState);
    }

    let database = path.join("vault.db");
    let prepared = path.join(PREPARED_NAME);
    let retired = path.join(RETIRED_NAME);
    let database_key = dek.database_encryption_key();
    let preflight = if database.is_file() {
        match crate::db::open_encrypted_database(&database, &database_key) {
            Ok(connection) => connection,
            Err(_) if !retired.exists() => crate::db::open_plaintext_database(&database)?,
            Err(_) if retired.is_file() => crate::db::open_plaintext_database(&retired)?,
            Err(_) => {
                return Err(MetadataMigrationError::Validation(
                    "no authoritative database is available for migration preflight".into(),
                ));
            }
        }
    } else if retired.is_file() {
        crate::db::open_plaintext_database(&retired)?
    } else {
        return Err(MetadataMigrationError::Validation(
            "no authoritative database is available for migration preflight".into(),
        ));
    };
    validate_database(&preflight)?;
    let active = active_sessions(&preflight)?;
    if active > 0 {
        return Err(MetadataMigrationError::ActiveSessions { count: active });
    }
    drop(preflight);
    if !marker_path.exists() {
        write_marker(path, &marker)?;
    }

    let blobs = BlobStore::open(&path.join("blobs")).map_err(VaultError::from)?;
    let mut converted_blobs = blobs.migrate_legacy_blobs(&dek).map_err(VaultError::from)?;
    save_marker(path, MigrationPhase::BlobsProtected)?;
    if failpoint == MigrationFailpoint::AfterBlobs {
        return Err(MetadataMigrationError::Interrupted("blob protection"));
    }

    // Never call the create-capable protected opener for a missing selected
    // path. A crash may have retired the legacy database but not yet renamed
    // the validated candidate into place; that state must resume from the
    // retained authority and prepared replacement, not manufacture an empty
    // protected database.
    let selected = if database.is_file() {
        crate::db::open_encrypted_database(&database, &database_key).ok()
    } else {
        None
    };
    let source_version;
    let legacy_barrier;
    if let Some(selected) = selected {
        if !retired.is_file() {
            return Err(MetadataMigrationError::Validation(
                "protected database selected without retained legacy authority".into(),
            ));
        }
        validate_database(&selected)?;
        let retained = crate::db::open_plaintext_database(&retired)?;
        validate_database(&retained)?;
        retained.execute_batch("BEGIN EXCLUSIVE")?;
        let active = active_sessions(&retained)?;
        if active > 0 {
            return Err(MetadataMigrationError::ActiveSessions { count: active });
        }
        compare_logical_inventory(&retained, &selected)?;
        source_version = crate::db::migrations::schema_version(&retained)?;
        let mut protected_manifest = manifest.clone();
        hydrate_manifest(&selected, &mut protected_manifest)?;
        drop(selected);
        legacy_barrier = retained;
    } else {
        let source_path = if database.is_file() {
            if retired.exists() {
                return Err(MetadataMigrationError::InvalidState);
            }
            database.clone()
        } else if retired.is_file() {
            retired.clone()
        } else {
            return Err(MetadataMigrationError::Validation(
                "no authoritative legacy database remains".into(),
            ));
        };
        let source = crate::db::open_plaintext_database(&source_path)?;
        validate_database(&source)?;
        source_version = crate::db::migrations::schema_version(&source)?;
        if source_version > 21 {
            return Err(MetadataMigrationError::Validation(
                "legacy database has an unsupported schema version".into(),
            ));
        }
        let active = active_sessions(&source)?;
        if active > 0 {
            return Err(MetadataMigrationError::ActiveSessions { count: active });
        }
        source.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        let source_data_version: i64 =
            source.query_row("PRAGMA data_version", [], |row| row.get(0))?;

        let prepared_valid = if prepared.is_file() {
            match crate::db::open_encrypted_database(&prepared, &database_key) {
                Ok(candidate) => {
                    let valid = validate_database(&candidate).is_ok()
                        && compare_logical_inventory(&source, &candidate).is_ok();
                    drop(candidate);
                    valid
                }
                Err(_) => false,
            }
        } else {
            false
        };
        if !prepared_valid {
            remove_database_and_sidecars(&prepared)?;
            if failpoint == MigrationFailpoint::BeforeExportStorageFull {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::StorageFull,
                    "fault injection: insufficient migration staging capacity",
                )
                .into());
            }
            crate::db::export_plaintext_to_encrypted(&source, &prepared, &database_key)?;
            let candidate = crate::db::open_encrypted_database(&prepared, &database_key)?;
            initialize_from_manifest(&candidate, &manifest)?;
            validate_database(&candidate)?;
            compare_logical_inventory(&source, &candidate)?;
            candidate.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
            drop(candidate);
        }
        validate_protected_state(path, &prepared, &manifest, &dek)?;
        save_marker(path, MigrationPhase::DatabasePrepared)?;
        if failpoint == MigrationFailpoint::AfterPrepare {
            return Err(MetadataMigrationError::Interrupted("database preparation"));
        }
        if failpoint == MigrationFailpoint::AfterPrepareConcurrentCommit {
            let competing = rusqlite::Connection::open(&source_path)?;
            competing.execute("UPDATE spaces SET name = 'concurrent-writer-preserved'", [])?;
            drop(competing);
        }
        // Final selection is guarded by a SQLite exclusive writer boundary.
        // A writer that committed during export makes the candidate comparison
        // fail; once this transaction begins, no later writer can commit before
        // the legacy authority is retired.
        source.execute_batch("BEGIN EXCLUSIVE")?;
        let selected_data_version: i64 =
            source.query_row("PRAGMA data_version", [], |row| row.get(0))?;
        if selected_data_version != source_data_version {
            return Err(MetadataMigrationError::Validation(
                "legacy source changed while the protected candidate was prepared".into(),
            ));
        }
        #[cfg(test)]
        if failpoint == MigrationFailpoint::DuringExclusiveLegacyBlobWrite {
            blobs
                .put_legacy_test(&dek, b"LATE-LEGACY-BLOB-WRITE-SENTINEL")
                .map_err(VaultError::from)?;
        }
        let late_blobs = blobs.migrate_legacy_blobs(&dek).map_err(VaultError::from)?;
        converted_blobs += late_blobs;
        if late_blobs > 0 {
            return Err(MetadataMigrationError::Validation(
                "legacy blob set changed during protected database preparation".into(),
            ));
        }
        let active = active_sessions(&source)?;
        if active > 0 {
            return Err(MetadataMigrationError::ActiveSessions { count: active });
        }
        let candidate = crate::db::open_encrypted_database(&prepared, &database_key)?;
        validate_database(&candidate)?;
        compare_logical_inventory(&source, &candidate)?;
        drop(candidate);
        if failpoint == MigrationFailpoint::DuringExclusiveSelection {
            let competing = rusqlite::Connection::open(&source_path)?;
            competing.busy_timeout(std::time::Duration::ZERO)?;
            if competing.execute_batch("BEGIN IMMEDIATE").is_ok() {
                let _ = competing.execute_batch("ROLLBACK");
                return Err(MetadataMigrationError::Validation(
                    "exclusive migration boundary admitted a competing writer".into(),
                ));
            }
        }

        if source_path == database {
            std::fs::rename(&database, &retired)?;
            move_sidecar_if_present(&database, &retired, "-wal")?;
            move_sidecar_if_present(&database, &retired, "-shm")?;
            sync_directory(path)?;
            if failpoint == MigrationFailpoint::AfterRetire {
                return Err(MetadataMigrationError::Interrupted(
                    "legacy database retirement",
                ));
            }
        }
        std::fs::rename(&prepared, &database)?;
        sync_directory(path)?;
        let selected = crate::db::open_encrypted_database(&database, &database_key)?;
        validate_database(&selected)?;
        drop(selected);
        legacy_barrier = source;
    }

    save_marker(path, MigrationPhase::DatabaseSelected)?;
    if failpoint == MigrationFailpoint::AfterSelect {
        return Err(MetadataMigrationError::Interrupted("database selection"));
    }

    let selected = crate::db::open_database(&database, &dek)?;
    validate_database(&selected)?;
    validate_referenced_blobs(&selected, &blobs, &dek)?;
    let mut migration_vault = super::Vault {
        path: path.to_path_buf(),
        manifest: manifest.clone(),
        conn: selected,
        blobs,
        dek: Some(dek.duplicate()),
        keyslot_digest: std::sync::Mutex::new(super::keyslot_digest_at(&path.join("keyslot.bin"))?),
    };
    crate::receipt::migrate_legacy_receipts(&mut migration_vault)?;
    crate::receipt::verify(&migration_vault)?;
    drop(migration_vault);
    let late_blobs = BlobStore::open(&path.join("blobs"))
        .map_err(VaultError::from)?
        .migrate_legacy_blobs(&dek)
        .map_err(VaultError::from)?;
    converted_blobs += late_blobs;
    if late_blobs > 0 {
        return Err(MetadataMigrationError::Validation(
            "legacy blob set changed during protected database selection".into(),
        ));
    }
    manifest.format_version = FORMAT_VERSION;
    manifest.save(&manifest_path).map_err(VaultError::from)?;
    save_marker(path, MigrationPhase::ManifestCommitted)?;
    if failpoint == MigrationFailpoint::AfterManifest {
        return Err(MetadataMigrationError::Interrupted("manifest commit"));
    }

    let late_blobs = BlobStore::open(&path.join("blobs"))
        .map_err(VaultError::from)?
        .migrate_legacy_blobs(&dek)
        .map_err(VaultError::from)?;
    converted_blobs += late_blobs;
    if late_blobs > 0 {
        return Err(MetadataMigrationError::Validation(
            "legacy blob set changed during metadata commit".into(),
        ));
    }
    remove_if_exists(&retired)?;
    legacy_barrier.execute_batch("ROLLBACK")?;
    drop(legacy_barrier);
    remove_database_and_sidecars(&retired)?;
    remove_database_and_sidecars(&prepared)?;
    remove_if_exists(&marker_path)?;
    remove_if_exists(&path.join(MARKER_TEMP_NAME))?;
    sync_directory(path)?;

    Ok(MetadataMigrationReport {
        migrated: true,
        resumed,
        converted_blobs,
        source_schema_version: source_version,
    })
}

fn load_marker_or_default(path: &Path) -> Result<MigrationMarker, MetadataMigrationError> {
    let marker_path = path.join(MARKER_NAME);
    if marker_path.is_file() {
        let marker: MigrationMarker = serde_json::from_slice(&std::fs::read(marker_path)?)
            .map_err(|_| MetadataMigrationError::InvalidState)?;
        return Ok(marker);
    }
    Ok(MigrationMarker {
        version: FORMAT_VERSION,
        phase: MigrationPhase::Started,
    })
}

fn save_marker(path: &Path, phase: MigrationPhase) -> Result<(), MetadataMigrationError> {
    write_marker(
        path,
        &MigrationMarker {
            version: FORMAT_VERSION,
            phase,
        },
    )
}

fn write_marker(path: &Path, marker: &MigrationMarker) -> Result<(), MetadataMigrationError> {
    let temporary = path.join(MARKER_TEMP_NAME);
    remove_if_exists(&temporary)?;
    let mut bytes = serde_json::to_vec(marker)?;
    bytes.push(b'\n');
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    crate::vault::permissions::file(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temporary, path.join(MARKER_NAME))?;
    sync_directory(path)?;
    Ok(())
}

fn validate_protected_state(
    path: &Path,
    database: &Path,
    manifest: &VaultManifest,
    dek: &crate::crypto::Dek,
) -> Result<(), MetadataMigrationError> {
    let conn = crate::db::open_database(database, dek)?;
    validate_database(&conn)?;
    let mut hydrated = manifest.clone();
    hydrate_manifest(&conn, &mut hydrated)?;
    let blobs = BlobStore::open(&path.join("blobs")).map_err(VaultError::from)?;
    let candidate = super::Vault {
        path: path.to_path_buf(),
        manifest: hydrated,
        conn,
        blobs,
        dek: Some(dek.duplicate()),
        keyslot_digest: std::sync::Mutex::new(super::keyslot_digest_at(&path.join("keyslot.bin"))?),
    };
    let integrity = crate::recovery::diagnose(&candidate).map_err(|_| {
        MetadataMigrationError::Validation(
            "protected candidate diagnostics could not complete".into(),
        )
    })?;
    if integrity.has_fatal() {
        return Err(MetadataMigrationError::Validation(
            "protected candidate diagnostics contain fatal findings".into(),
        ));
    }
    Ok(())
}

fn validate_database(conn: &Connection) -> Result<(), MetadataMigrationError> {
    let quick: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if quick != "ok" {
        return Err(MetadataMigrationError::Validation(
            "database quick check failed".into(),
        ));
    }
    let foreign_keys: i64 =
        conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if foreign_keys != 0 {
        return Err(MetadataMigrationError::Validation(
            "database foreign-key check failed".into(),
        ));
    }
    Ok(())
}

fn active_sessions(conn: &Connection) -> Result<usize, MetadataMigrationError> {
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'sessions'",
        [],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Ok(0);
    }
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sessions
         WHERE status = 'active' AND julianday(expires_at) > julianday('now')",
        [],
        |row| row.get(0),
    )?;
    Ok(count as usize)
}

fn logical_inventory(
    conn: &Connection,
) -> Result<BTreeMap<String, (i64, [u8; 32])>, MetadataMigrationError> {
    let mut tables = conn.prepare(
        "SELECT name FROM sqlite_master
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
           AND name NOT IN ('vault_metadata', 'schema_migrations')
         ORDER BY name",
    )?;
    let names = tables
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(tables);
    let mut inventory = BTreeMap::new();
    for name in names {
        let quoted = name.replace('"', "\"\"");
        let count = conn.query_row(&format!("SELECT COUNT(*) FROM \"{quoted}\""), [], |row| {
            row.get::<_, i64>(0)
        })?;
        let mut column_statement = conn.prepare(&format!("PRAGMA table_info(\"{quoted}\")"))?;
        let columns = column_statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(column_statement);
        let projection = columns
            .iter()
            .map(|column| format!("\"{}\"", column.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(", ");
        let mut statement = conn.prepare(&format!("SELECT {projection} FROM \"{quoted}\""))?;
        let mut rows = statement.query([])?;
        let mut row_hashes = Vec::new();
        while let Some(row) = rows.next()? {
            let mut hasher = blake3::Hasher::new();
            for index in 0..columns.len() {
                use rusqlite::types::ValueRef;
                match row.get_ref(index)? {
                    ValueRef::Null => hasher.update(&[0]),
                    ValueRef::Integer(value) => {
                        hasher.update(&[1]);
                        hasher.update(&value.to_le_bytes())
                    }
                    ValueRef::Real(value) => {
                        hasher.update(&[2]);
                        hasher.update(&value.to_bits().to_le_bytes())
                    }
                    ValueRef::Text(value) => {
                        hasher.update(&[3]);
                        hasher.update(&(value.len() as u64).to_le_bytes());
                        hasher.update(value)
                    }
                    ValueRef::Blob(value) => {
                        hasher.update(&[4]);
                        hasher.update(&(value.len() as u64).to_le_bytes());
                        hasher.update(value)
                    }
                };
            }
            row_hashes.push(*hasher.finalize().as_bytes());
        }
        row_hashes.sort_unstable();
        let mut table_hasher = blake3::Hasher::new();
        for column in &columns {
            table_hasher.update(&(column.len() as u64).to_le_bytes());
            table_hasher.update(column.as_bytes());
        }
        for row_hash in row_hashes {
            table_hasher.update(&row_hash);
        }
        inventory.insert(name, (count, *table_hasher.finalize().as_bytes()));
    }
    Ok(inventory)
}

fn compare_logical_inventory(
    source: &Connection,
    candidate: &Connection,
) -> Result<(), MetadataMigrationError> {
    let source = logical_inventory(source)?;
    let candidate = logical_inventory(candidate)?;
    for (table, source_state) in source {
        // Legacy receipt indexes are deterministically rebuilt and then
        // authenticated against the protected receipt files before commit.
        if matches!(table.as_str(), "receipts_index" | "receipt_chain_state") {
            continue;
        }
        if candidate.get(&table) != Some(&source_state) {
            return Err(MetadataMigrationError::Validation(format!(
                "protected database inventory differs from legacy source table {table}"
            )));
        }
    }
    Ok(())
}

fn validate_referenced_blobs(
    conn: &Connection,
    blobs: &BlobStore,
    dek: &crate::crypto::Dek,
) -> Result<(), MetadataMigrationError> {
    for (table, column) in [
        ("artifact_versions", "blob_hash"),
        ("derived_text", "blob_hash"),
        ("summaries", "blob_hash"),
        ("provenance", "derived_blob_hash"),
        ("image_derivations", "thumbnail_blob_hash"),
        ("image_derivations", "ocr_blob_hash"),
        ("image_derivations", "caption_blob_hash"),
        ("conversation_archives", "normal_form_blob_hash"),
        ("conversation_derivations", "normalized_blob_hash"),
    ] {
        let exists: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )?;
        if exists == 0 {
            continue;
        }
        let mut statement = conn.prepare(&format!(
            "SELECT DISTINCT \"{column}\" FROM \"{table}\" WHERE \"{column}\" IS NOT NULL"
        ))?;
        let hashes = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for hash in hashes {
            blobs
                .get(dek, &crate::blob::BlobHash(hash))
                .map_err(VaultError::from)?;
        }
    }
    Ok(())
}

fn move_sidecar_if_present(
    source: &Path,
    destination: &Path,
    suffix: &str,
) -> Result<(), std::io::Error> {
    let source_sidecar = PathBuf::from(format!("{}{suffix}", source.display()));
    if source_sidecar.exists() {
        let destination_sidecar = PathBuf::from(format!("{}{suffix}", destination.display()));
        std::fs::rename(source_sidecar, destination_sidecar)?;
    }
    Ok(())
}

fn remove_database_and_sidecars(path: &Path) -> Result<(), std::io::Error> {
    remove_if_exists(path)?;
    remove_if_exists(&PathBuf::from(format!("{}-wal", path.display())))?;
    remove_if_exists(&PathBuf::from(format!("{}-shm", path.display())))?;
    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<(), std::io::Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embed::{EmbedError, EmbeddingProvider};

    const TEST_PARAMS: crate::crypto::KdfParams = crate::crypto::KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    struct MigrationEmbedder;

    fn locked_scan_variants(value: &str) -> Vec<Vec<u8>> {
        let text_variants = [
            value.to_owned(),
            value.to_ascii_lowercase(),
            value.to_ascii_uppercase(),
            blake3::hash(value.as_bytes()).to_hex().to_string(),
        ];
        let mut variants = Vec::new();
        for text in text_variants {
            variants.push(text.as_bytes().to_vec());
            variants.push(
                text.encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>(),
            );
            variants.push(
                text.encode_utf16()
                    .flat_map(u16::to_be_bytes)
                    .collect::<Vec<_>>(),
            );
        }
        variants
    }

    fn assert_locked_value_absent(root: &Path, value: &str) {
        let path_variants = [
            value.to_owned(),
            value.to_ascii_lowercase(),
            value.to_ascii_uppercase(),
            blake3::hash(value.as_bytes()).to_hex().to_string(),
        ];
        let byte_variants = locked_scan_variants(value);
        fn visit(root: &Path, path: &Path, path_variants: &[String], byte_variants: &[Vec<u8>]) {
            for entry in std::fs::read_dir(path).expect("read locked bundle") {
                let entry = entry.expect("bundle entry");
                let path = entry.path();
                let relative = path.strip_prefix(root).expect("relative bundle path");
                let relative_text = relative.to_string_lossy();
                for variant in path_variants {
                    assert!(
                        !relative_text.contains(variant),
                        "protected sentinel encoding leaked through path {}",
                        relative.display()
                    );
                }
                if path.is_dir() {
                    visit(root, &path, path_variants, byte_variants);
                } else {
                    let bytes = std::fs::read(&path).expect("read locked file");
                    for variant in byte_variants {
                        assert!(
                            !bytes
                                .windows(variant.len())
                                .any(|window| window == variant.as_slice()),
                            "protected sentinel encoding leaked through bytes in {}",
                            relative.display()
                        );
                    }
                }
            }
        }
        visit(root, root, &path_variants, &byte_variants);
    }

    impl EmbeddingProvider for MigrationEmbedder {
        fn embed(&self, _text: &str) -> Result<Vec<f32>, EmbedError> {
            let mut vector = vec![0.0; 384];
            vector[0] = 1.0;
            Ok(vector)
        }

        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
            texts.iter().map(|text| self.embed(text)).collect()
        }

        fn model_version(&self) -> &str {
            "metadata-migration-test@v1"
        }

        fn dimensions(&self) -> usize {
            384
        }

        fn calibrated_relevance_floor(&self) -> Option<f32> {
            Some(-1.0)
        }
    }

    fn legacy_fixture() -> (tempfile::TempDir, PathBuf, crate::blob::BlobHash) {
        legacy_fixture_at(21)
    }

    #[test]
    fn migration_error_codes_never_render_internal_payloads() {
        let private_value = "PRIVATE-PATH-HASH-RECEIPT-SENTINEL";
        let validation = MetadataMigrationError::Validation(private_value.into());
        let io = MetadataMigrationError::Io(std::io::Error::other(private_value));
        let database =
            MetadataMigrationError::Database(DbError::MigrationFailed(private_value.into()));

        assert_eq!(validation.safe_code(), "validation_failed");
        assert_eq!(io.safe_code(), "io_error");
        assert_eq!(database.safe_code(), "database_error");
        for code in [validation.safe_code(), io.safe_code(), database.safe_code()] {
            assert!(!code.contains(private_value));
            assert!(code.len() <= 32);
        }
    }

    fn legacy_fixture_at(
        schema_version: usize,
    ) -> (tempfile::TempDir, PathBuf, crate::blob::BlobHash) {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("Legacy.tessera");
        std::fs::create_dir_all(path.join("blobs")).expect("blobs");
        std::fs::create_dir_all(path.join("receipts")).expect("receipts");
        std::fs::create_dir_all(path.join("inbox")).expect("inbox");

        let (keyslots, dek) =
            KeyslotFile::create("migration-passphrase", &TEST_PARAMS).expect("keyslot");
        keyslots
            .save(&path.join("keyslot.bin"))
            .expect("save keyslot");
        let mut manifest = VaultManifest::new("2026-08-23T10:00:00Z".parse().expect("time"));
        manifest.format_version = 2;
        manifest.embedding_models.push(EmbeddingModelEntry {
            name: "MIGRATION-PRIVATE-MODEL-SENTINEL".into(),
            version: "sentinel-model@v1".into(),
            dimensions: 384,
        });
        manifest.save(&path.join("tessera.json")).expect("manifest");

        let blob = BlobStore::open(&path.join("blobs")).expect("store");
        let hash = blob
            .put_legacy_test(&dek, b"MIGRATION-PRIVATE-CONTENT-SENTINEL")
            .expect("legacy blob");
        let conn = crate::db::open_plaintext_database(&path.join("vault.db")).expect("db");
        crate::db::migrations::run_migrations_through(&conn, schema_version)
            .expect("legacy schema");
        conn.execute(
            "INSERT INTO spaces (id, name, created_at, updated_at)
             VALUES ('space-1', 'MIGRATION-PRIVATE-SPACE-SENTINEL', 'now', 'now')",
            [],
        )
        .expect("space");
        conn.execute(
            "INSERT INTO artifacts
             (id, space_id, filename, media_type, sensitivity, state, created_at, updated_at)
             VALUES ('artifact-1', 'space-1', 'PRIVATE-FILENAME-SENTINEL.md',
                     'text/markdown', 'confidential', 'live', 'now', 'now')",
            [],
        )
        .expect("artifact");
        conn.execute(
            "INSERT INTO artifact_versions
             (id, artifact_id, version, blob_hash, size_bytes, created_at)
             VALUES ('version-1', 'artifact-1', 1, ?1, 35, 'now')",
            [&hash.0],
        )
        .expect("version");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint");
        drop(conn);
        (directory, path, hash)
    }

    #[test]
    fn registry_round_trip_stays_inside_database() {
        let directory = tempfile::tempdir().expect("tempdir");
        let connection =
            crate::db::open_encrypted_database(&directory.path().join("vault.db"), &[0x77; 32])
                .expect("open");
        let sentinel = EmbeddingModelEntry {
            name: "PRIVATE-MODEL-REGISTRY-SENTINEL".into(),
            version: "private-model@v1".into(),
            dimensions: 384,
        };
        register_embedding_model(&connection, sentinel.clone()).expect("register");
        assert_eq!(
            embedding_models(&connection).expect("models"),
            vec![sentinel]
        );
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint");
        drop(connection);
        let raw = std::fs::read(directory.path().join("vault.db")).expect("read");
        assert!(!raw
            .windows("PRIVATE-MODEL-REGISTRY-SENTINEL".len())
            .any(|bytes| bytes == b"PRIVATE-MODEL-REGISTRY-SENTINEL"));
    }

    #[test]
    fn complete_synthetic_metadata_category_inventory_is_absent_while_locked() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("CompleteInventory.tessera");
        let vault =
            super::super::Vault::create_with_params(&path, "inventory-passphrase", &TEST_PARAMS)
                .expect("create protected vault");

        let space_name = "PRIVATE-SPACE-CATEGORY-SENTINEL-ISSUE50";
        let filename = "PRIVATE-FILENAME-CATEGORY-SENTINEL-ISSUE50.md";
        let title = "PRIVATE-TITLE-CATEGORY-SENTINEL-ISSUE50";
        let tag_name = "PRIVATE-TAG-CATEGORY-SENTINEL-ISSUE50";
        let timestamp = "PRIVATE-TIMESTAMP-CATEGORY-SENTINEL-ISSUE50";
        let manifest_created_at = "2042-01-02T03:04:05.678901Z";
        let manifest_extension = "PRIVATE-MANIFEST-EXTENSION-SENTINEL-ISSUE50";
        let source_url = "https://metadata.invalid/PRIVATE-SOURCE-URL-SENTINEL-ISSUE50";
        let staged_filename = "PRIVATE-WEB-STAGING-FILENAME-SENTINEL-ISSUE50.md";
        let project = "PRIVATE-PROJECT-CATEGORY-SENTINEL-ISSUE50";
        let repository = "PRIVATE-REPOSITORY-CATEGORY-SENTINEL-ISSUE50";
        let working_directory = "PRIVATE-WORKDIR-CATEGORY-SENTINEL-ISSUE50";
        let branch = "PRIVATE-BRANCH-CATEGORY-SENTINEL-ISSUE50";
        let git_commit = "PRIVATE-COMMIT-CATEGORY-SENTINEL-ISSUE50";
        let source_file = "PRIVATE-SOURCE-FILE-CATEGORY-SENTINEL-ISSUE50";
        let session_purpose = "PRIVATE-SESSION-PURPOSE-SENTINEL-ISSUE50";
        let pairing_agent = "PRIVATE-PAIRING-AGENT-SENTINEL-ISSUE50";
        let processing_error = "PRIVATE-PROCESSING-ERROR-SENTINEL-ISSUE50";
        let ingestion_error = "PRIVATE-INGESTION-ERROR-SENTINEL-ISSUE50";
        let oauth_client = "PRIVATE-OAUTH-CLIENT-SENTINEL-ISSUE50";
        let oauth_client_name = "PRIVATE-OAUTH-CLIENT-NAME-SENTINEL-ISSUE50";
        let oauth_redirect = "https://oauth.invalid/PRIVATE-REDIRECT-SENTINEL-ISSUE50";
        let oauth_code_hash = "PRIVATE-OAUTH-CODE-HASH-SENTINEL-ISSUE50";
        let oauth_challenge = "PRIVATE-OAUTH-CHALLENGE-SENTINEL-ISSUE50";
        let oauth_token_hash = "PRIVATE-OAUTH-TOKEN-HASH-SENTINEL-ISSUE50";
        let oauth_resource = "PRIVATE-OAUTH-RESOURCE-SENTINEL-ISSUE50";
        let conversation_id = "PRIVATE-CONVERSATION-ID-SENTINEL-ISSUE50";
        let archive_id = "PRIVATE-CONVERSATION-ARCHIVE-SENTINEL-ISSUE50";
        let source_record_id = "PRIVATE-SOURCE-RECORD-SENTINEL-ISSUE50";
        let node_id = "PRIVATE-CONVERSATION-NODE-SENTINEL-ISSUE50";
        let part_id = "PRIVATE-CONVERSATION-PART-SENTINEL-ISSUE50";
        let attachment_id = "PRIVATE-ATTACHMENT-ID-SENTINEL-ISSUE50";
        let attachment_hash = "PRIVATE-ATTACHMENT-HASH-SENTINEL-ISSUE50";
        let provenance_tool = "PRIVATE-PROVENANCE-TOOL-SENTINEL-ISSUE50";
        let provenance_id = "PRIVATE-PROVENANCE-ID-SENTINEL-ISSUE50";
        let derived_text_id = "PRIVATE-DERIVED-ID-SENTINEL-ISSUE50";
        let summary_id = "PRIVATE-SUMMARY-ID-SENTINEL-ISSUE50";
        let image_derivation_id = "PRIVATE-IMAGE-DERIVATION-ID-SENTINEL-ISSUE50";
        let conversation_derived_id = "PRIVATE-CONVERSATION-DERIVED-ID-SENTINEL-ISSUE50";
        let conversation_derivation_id = "PRIVATE-CONVERSATION-DERIVATION-ID-SENTINEL-ISSUE50";
        let conversation_chunk_id = "PRIVATE-CONVERSATION-CHUNK-ID-SENTINEL-ISSUE50";
        let ingestion_run_id = "PRIVATE-INGESTION-RUN-SENTINEL-ISSUE50";
        let ingestion_item_id = "PRIVATE-INGESTION-ITEM-SENTINEL-ISSUE50";
        let source_export_id = "PRIVATE-SOURCE-EXPORT-SENTINEL-ISSUE50";
        let model_name = "PRIVATE-MODEL-REGISTRY-SENTINEL-ISSUE50";
        let model_version = "PRIVATE-MODEL-VERSION-SENTINEL-ISSUE50";
        let original_content = "PRIVATE-ORIGINAL-CONTENT-SENTINEL-ISSUE50";
        let derived_content = "PRIVATE-DERIVED-CONTENT-SENTINEL-ISSUE50";
        let summary_content = "PRIVATE-SUMMARY-CONTENT-SENTINEL-ISSUE50";
        let thumbnail_content = "PRIVATE-IMAGE-THUMBNAIL-SENTINEL-ISSUE50";
        let ocr_content = "PRIVATE-IMAGE-OCR-SENTINEL-ISSUE50";
        let caption_content = "PRIVATE-IMAGE-CAPTION-SENTINEL-ISSUE50";
        let conversation_content = "PRIVATE-CONVERSATION-BLOB-SENTINEL-ISSUE50";

        let space = crate::space::create(&vault, space_name, None).expect("space");
        let (artifact, version) = crate::artifact::register_encrypted_bytes(
            &vault,
            &space,
            filename,
            "text/markdown",
            crate::artifact::Sensitivity::Restricted,
            original_content.as_bytes(),
        )
        .expect("artifact");
        crate::artifact::tag(&vault, &artifact, tag_name).expect("tag");
        crate::review::record_processing_error(
            &vault,
            &artifact,
            "metadata-inventory",
            processing_error,
        )
        .expect("processing error");

        let policy = crate::LensPolicy::new(
            "PRIVATE-LENS-CATEGORY-SENTINEL-ISSUE50",
            vec![space.clone()],
        );
        let lens_id = crate::lens::create(&vault, &policy).expect("lens");
        let pairing = crate::pairing::approve(&vault, &lens_id, session_purpose, pairing_agent, 60)
            .expect("pairing");
        let live_session = crate::session::start(&vault, &pairing).expect("session");
        vault
            .conn()
            .execute(
                "INSERT INTO oauth_clients
                 (client_id, client_name, redirect_uris_json, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    oauth_client,
                    oauth_client_name,
                    serde_json::json!([oauth_redirect]).to_string(),
                    timestamp
                ],
            )
            .expect("OAuth client metadata");
        vault
            .conn()
            .execute(
                "INSERT INTO oauth_authorization_codes
                 (code_hash, client_id, pairing_id, redirect_uri, code_challenge,
                  resource, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    oauth_code_hash,
                    oauth_client,
                    pairing.id,
                    oauth_redirect,
                    oauth_challenge,
                    oauth_resource,
                    timestamp
                ],
            )
            .expect("OAuth authorization metadata");
        vault
            .conn()
            .execute(
                "INSERT INTO oauth_access_tokens
                 (token_hash, client_id, pairing_id, lens_id, resource, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                rusqlite::params![
                    oauth_token_hash,
                    oauth_client,
                    pairing.id,
                    lens_id.0,
                    oauth_resource,
                    timestamp
                ],
            )
            .expect("OAuth token metadata");
        let receipt = crate::receipt::Session::open_bound(
            &vault,
            crate::receipt::AgentRef {
                agent_id: "PRIVATE-RECEIPT-AGENT-ID-SENTINEL-ISSUE50".into(),
                name: pairing_agent.into(),
            },
            &policy,
            session_purpose,
            false,
            crate::receipt::SessionBinding {
                session_id: live_session.id.clone(),
                pairing_id: Some(pairing.id.clone()),
            },
        )
        .expect("receipt session")
        .finalize()
        .expect("receipt finalization");
        crate::session::close(&vault, &live_session.id, Some(&receipt.receipt_id))
            .expect("close session");

        register_embedding_model(
            vault.conn(),
            EmbeddingModelEntry {
                name: model_name.into(),
                version: model_version.into(),
                dimensions: 384,
            },
        )
        .expect("model registry");
        put_json(
            vault.conn(),
            CREATED_AT,
            &serde_json::to_string(manifest_created_at).expect("private created-at JSON"),
        )
        .expect("private creation time");
        put_json(
            vault.conn(),
            MANIFEST_EXTENSIONS,
            &serde_json::json!({
                "top_level": {"synthetic_private_extension": manifest_extension},
                "crypto": {"synthetic_private_crypto_extension": manifest_extension}
            })
            .to_string(),
        )
        .expect("private manifest extensions");
        vault
            .conn()
            .execute(
                "UPDATE spaces SET created_at = ?1, updated_at = ?1 WHERE id = ?2",
                rusqlite::params![timestamp, space.0],
            )
            .expect("timestamp category");
        vault
            .conn()
            .execute(
                "INSERT INTO web_staging
                 (staged_filename, source_url, final_url, title, published_at, fetched_at)
                 VALUES (?1, ?2, ?2, ?3, ?4, ?4)",
                rusqlite::params![staged_filename, source_url, title, timestamp],
            )
            .expect("web staging metadata categories");
        vault
            .conn()
            .execute(
                "INSERT INTO web_sources
                 (artifact_version_id, source_url, final_url, title, published_at, fetched_at)
                 VALUES (?1, ?2, ?2, ?3, ?4, ?4)",
                rusqlite::params![version.id, source_url, title, timestamp],
            )
            .expect("web metadata categories");

        let derived_blob = vault
            .blobs()
            .put(vault.dek().expect("DEK"), derived_content.as_bytes())
            .expect("derived blob");
        let summary_blob = vault
            .blobs()
            .put(vault.dek().expect("DEK"), summary_content.as_bytes())
            .expect("summary blob");
        let thumbnail_blob = vault
            .blobs()
            .put(vault.dek().expect("DEK"), thumbnail_content.as_bytes())
            .expect("thumbnail blob");
        let ocr_blob = vault
            .blobs()
            .put(vault.dek().expect("DEK"), ocr_content.as_bytes())
            .expect("OCR blob");
        let caption_blob = vault
            .blobs()
            .put(vault.dek().expect("DEK"), caption_content.as_bytes())
            .expect("caption blob");
        let conversation_blob = vault
            .blobs()
            .put(vault.dek().expect("DEK"), conversation_content.as_bytes())
            .expect("conversation blob");
        vault
            .conn()
            .execute(
                "INSERT INTO derived_text
                 (id, artifact_version_id, blob_hash, extractor, extractor_version, created_at)
                 VALUES (?1, ?2, ?3, 'private-extractor-sentinel', 'private-extractor-v1', ?4)",
                rusqlite::params![derived_text_id, version.id, derived_blob.0, timestamp],
            )
            .expect("derived metadata");
        vault
            .conn()
            .execute(
                "INSERT INTO summaries
                 (id, artifact_version_id, blob_hash, summarizer, summarizer_version,
                  locality, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 'private-summarizer-sentinel',
                         'private-summarizer-v1', 'local', ?4, ?4)",
                rusqlite::params![summary_id, version.id, summary_blob.0, timestamp],
            )
            .expect("summary metadata");
        vault
            .conn()
            .execute(
                "INSERT INTO provenance
                 (id, derived_blob_hash, source_artifact_version_id, tool,
                  tool_version, locality, created_at)
                 VALUES (?1, ?2, ?3, ?4, 'PRIVATE-PROVENANCE-VERSION-SENTINEL-ISSUE50',
                         'local', ?5)",
                rusqlite::params![
                    provenance_id,
                    derived_blob.0,
                    version.id,
                    provenance_tool,
                    timestamp
                ],
            )
            .expect("provenance metadata");
        vault
            .conn()
            .execute(
                "INSERT INTO image_derivations
                 (id, artifact_version_id, searchable_derived_text_id,
                  thumbnail_blob_hash, thumbnail_media_type, ocr_blob_hash,
                  caption_blob_hash, thumbnail_tool, thumbnail_tool_version,
                  ocr_tool, ocr_tool_version, caption_tool, caption_model,
                  caption_model_version, locality, cloud_opt_in, created_at)
                 VALUES (?1, ?2, ?3, ?4, 'image/png', ?5, ?6,
                         'private-thumbnail-tool', 'private-thumbnail-v1',
                         'private-ocr-tool', 'private-ocr-v1',
                         'private-caption-tool', ?7, ?8, 'local', 0, ?9)",
                rusqlite::params![
                    image_derivation_id,
                    version.id,
                    derived_text_id,
                    thumbnail_blob.0,
                    ocr_blob.0,
                    caption_blob.0,
                    model_name,
                    model_version,
                    timestamp
                ],
            )
            .expect("image metadata");
        vault
            .conn()
            .execute(
                "INSERT INTO conversation_archives
                 (id, source_artifact_version_id, schema_version, source_product,
                  source_hash, normal_form_blob_hash, parser_name, parser_version,
                  normalizer_name, normalizer_version, locality, processed_at)
                 VALUES (?1, ?2, '1.0.0', 'claude_code',
                         ?3, ?4, 'synthetic-parser', '1', 'synthetic-normalizer',
                         '1', 'local', ?5)",
                rusqlite::params![
                    archive_id,
                    version.id,
                    version.blob_hash,
                    conversation_blob.0,
                    timestamp
                ],
            )
            .expect("conversation archive");
        vault
            .conn()
            .execute(
                "INSERT INTO conversations
                 (id, archive_id, artifact_version_id, source_conversation_id,
                  source_created_at, source_updated_at, selected_branch_endpoint_id,
                  canonical_hash, created_at)
                 VALUES (?1, ?2, ?3, ?1, ?4, ?4,
                         ?5, 'PRIVATE-CANONICAL-HASH-SENTINEL-ISSUE50', ?4)",
                rusqlite::params![conversation_id, archive_id, version.id, timestamp, node_id],
            )
            .expect("conversation");
        vault
            .conn()
            .execute(
                "INSERT INTO conversation_source_records
                 (id, conversation_id, source_record_id, record_index, source_id,
                  byte_start, byte_end, line_start, line_end)
                 VALUES (?1, ?2, ?1, 0, 'PRIVATE-SOURCE-NATIVE-ID-SENTINEL-ISSUE50',
                         0, 64, 1, 1)",
                rusqlite::params![source_record_id, conversation_id],
            )
            .expect("conversation source record");
        vault
            .conn()
            .execute(
                "INSERT INTO conversation_nodes
                 (id, conversation_id, source_node_id, role, source_state,
                  source_timestamp, selected_order)
                 VALUES (?1, ?2, ?1, 'assistant', 'visible', ?3, 0)",
                rusqlite::params![node_id, conversation_id, timestamp],
            )
            .expect("conversation node");
        vault
            .conn()
            .execute(
                "INSERT INTO conversation_node_source_records (node_id, source_record_id)
                 VALUES (?1, ?2)",
                rusqlite::params![node_id, source_record_id],
            )
            .expect("conversation node source link");
        vault
            .conn()
            .execute(
                "INSERT INTO conversation_content_parts
                 (id, node_id, source_part_id, part_index, kind, attachment_id,
                  attachment_state, attachment_hash)
                 VALUES (?1, ?2, ?1, 0, 'attachment', ?3, 'preserved', ?4)",
                rusqlite::params![part_id, node_id, attachment_id, attachment_hash],
            )
            .expect("conversation content part");
        vault
            .conn()
            .execute(
                "INSERT INTO derived_text
                 (id, artifact_version_id, blob_hash, extractor, extractor_version, created_at)
                 VALUES (?1, ?2, ?3, 'private-conversation-renderer',
                         'private-conversation-renderer-v1', ?4)",
                rusqlite::params![
                    conversation_derived_id,
                    version.id,
                    conversation_blob.0,
                    timestamp
                ],
            )
            .expect("conversation derived text");
        vault
            .conn()
            .execute(
                "INSERT INTO conversation_derivations
                 (id, conversation_id, derived_text_id, normalized_blob_hash,
                  derivation_hash, renderer_name, renderer_version, chunker_name,
                  chunker_version, target_tokens, overlap_tokens, locality, processed_at)
                 VALUES (?1, ?2, ?3, ?4,
                         'PRIVATE-DERIVATION-HASH-SENTINEL-ISSUE50',
                         'private-renderer', 'private-renderer-v1',
                         'private-chunker', 'private-chunker-v1', 128, 16, 'local', ?5)",
                rusqlite::params![
                    conversation_derivation_id,
                    conversation_id,
                    conversation_derived_id,
                    conversation_blob.0,
                    timestamp
                ],
            )
            .expect("conversation derivation");
        vault
            .conn()
            .execute(
                "INSERT INTO conversation_spans
                 (id, derivation_id, node_id, part_id, byte_offset_start, byte_offset_end)
                 VALUES ('PRIVATE-CONVERSATION-SPAN-SENTINEL-ISSUE50', ?1, ?2, ?3, 0, ?4)",
                rusqlite::params![
                    conversation_derivation_id,
                    node_id,
                    part_id,
                    conversation_content.len() as i64
                ],
            )
            .expect("conversation span");
        vault
            .conn()
            .execute(
                "INSERT INTO chunks
                 (id, derived_text_id, chunk_index, byte_offset_start, byte_offset_end,
                  token_count, content_hash, section_heading, created_at)
                 VALUES (?1, ?2, 0, 0, ?3, 8,
                         'PRIVATE-CONVERSATION-CHUNK-HASH-SENTINEL-ISSUE50',
                         'PRIVATE-CONVERSATION-HEADING-SENTINEL-ISSUE50', ?4)",
                rusqlite::params![
                    conversation_chunk_id,
                    conversation_derived_id,
                    conversation_content.len() as i64,
                    timestamp
                ],
            )
            .expect("conversation chunk");
        vault
            .conn()
            .execute(
                "INSERT INTO conversation_chunk_map
                 (chunk_id, derivation_id, first_node_id, last_node_id,
                  branch_endpoint_node_id, mapped_at)
                 VALUES (?1, ?2, ?3, ?3, ?3, ?4)",
                rusqlite::params![
                    conversation_chunk_id,
                    conversation_derivation_id,
                    node_id,
                    timestamp
                ],
            )
            .expect("conversation chunk map");
        vault
            .conn()
            .execute(
                "INSERT INTO conversation_ingestion_runs
                 (id, source_artifact_version_id, target_space_id, source_product,
                  source_hash, parser_name, parser_version, normalizer_name,
                  normalizer_version, status, discovered_count, failed_count,
                  checkpoint_ordinal, retry_count, error_code, safe_error_summary,
                  started_at, updated_at, completed_at, source_export_id)
                 VALUES (?1, ?2, ?3, 'claude_code', ?4,
                         'private-run-parser', 'private-run-parser-v1',
                         'private-run-normalizer', 'private-run-normalizer-v1',
                         'failed', 1, 1, 1, 1,
                         'PRIVATE-INGESTION-ERROR-CODE-SENTINEL-ISSUE50', ?5,
                         ?6, ?6, ?6, ?7)",
                rusqlite::params![
                    ingestion_run_id,
                    version.id,
                    space.0,
                    version.blob_hash,
                    ingestion_error,
                    timestamp,
                    source_export_id
                ],
            )
            .expect("conversation ingestion run");
        vault
            .conn()
            .execute(
                "INSERT INTO conversation_ingestion_items
                 (id, run_id, ordinal, source_conversation_id, source_digest,
                  status, persisted_conversation_id, derived_text_id,
                  derivation_hash, embedding_model_version, error_code,
                  safe_error_summary, retry_count, attempted_at, completed_at)
                 VALUES (?1, ?2, 0, ?3,
                         'PRIVATE-INGESTION-DIGEST-SENTINEL-ISSUE50', 'failed',
                         ?3, ?4, 'PRIVATE-INGESTION-DERIVATION-SENTINEL-ISSUE50',
                         ?5, 'PRIVATE-INGESTION-ITEM-CODE-SENTINEL-ISSUE50',
                         ?6, 1, ?7, ?7)",
                rusqlite::params![
                    ingestion_item_id,
                    ingestion_run_id,
                    conversation_id,
                    conversation_derived_id,
                    model_version,
                    ingestion_error,
                    timestamp
                ],
            )
            .expect("conversation ingestion item");
        vault
            .conn()
            .execute(
                "INSERT INTO conversation_source_metadata
                 (conversation_id, source_product, session_id, project, repository,
                  working_directory, git_branch, git_commit, source_file_identity,
                  models_json, source_created_at, source_updated_at)
                 VALUES (?1, 'claude_code', ?2, ?3, ?4, ?5,
                         ?6, ?7, ?8, ?9, ?10, ?10)",
                rusqlite::params![
                    conversation_id,
                    live_session.id,
                    project,
                    repository,
                    working_directory,
                    branch,
                    git_commit,
                    source_file,
                    serde_json::json!([model_version]).to_string(),
                    timestamp,
                ],
            )
            .expect("conversation source metadata");

        let receipt_hash = receipt.self_hash.expect("receipt self hash");
        let protected_values = [
            manifest_created_at,
            manifest_extension,
            space_name,
            filename,
            title,
            tag_name,
            "restricted",
            timestamp,
            source_url,
            staged_filename,
            project,
            repository,
            working_directory,
            branch,
            git_commit,
            source_file,
            session_purpose,
            pairing_agent,
            processing_error,
            ingestion_error,
            oauth_client,
            oauth_client_name,
            oauth_redirect,
            oauth_code_hash,
            oauth_challenge,
            oauth_token_hash,
            oauth_resource,
            conversation_id,
            archive_id,
            source_record_id,
            node_id,
            part_id,
            attachment_id,
            attachment_hash,
            provenance_id,
            provenance_tool,
            derived_text_id,
            summary_id,
            image_derivation_id,
            conversation_derived_id,
            conversation_derivation_id,
            conversation_chunk_id,
            ingestion_run_id,
            ingestion_item_id,
            source_export_id,
            model_name,
            model_version,
            original_content,
            derived_content,
            summary_content,
            thumbnail_content,
            ocr_content,
            caption_content,
            conversation_content,
            "PRIVATE-RECEIPT-AGENT-ID-SENTINEL-ISSUE50",
            "PRIVATE-PROVENANCE-VERSION-SENTINEL-ISSUE50",
            "PRIVATE-SOURCE-NATIVE-ID-SENTINEL-ISSUE50",
            "PRIVATE-CANONICAL-HASH-SENTINEL-ISSUE50",
            "PRIVATE-DERIVATION-HASH-SENTINEL-ISSUE50",
            "PRIVATE-CONVERSATION-SPAN-SENTINEL-ISSUE50",
            "PRIVATE-CONVERSATION-CHUNK-HASH-SENTINEL-ISSUE50",
            "PRIVATE-CONVERSATION-HEADING-SENTINEL-ISSUE50",
            "PRIVATE-INGESTION-ERROR-CODE-SENTINEL-ISSUE50",
            "PRIVATE-INGESTION-DIGEST-SENTINEL-ISSUE50",
            "PRIVATE-INGESTION-DERIVATION-SENTINEL-ISSUE50",
            "PRIVATE-INGESTION-ITEM-CODE-SENTINEL-ISSUE50",
            "private-extractor-sentinel",
            "private-summarizer-sentinel",
            "private-thumbnail-tool",
            "private-ocr-tool",
            "private-caption-tool",
            "private-renderer",
            "private-chunker",
            "private-run-parser",
            "private-run-normalizer",
            &live_session.id,
            &pairing.id,
            &receipt_hash,
            &version.blob_hash,
            &derived_blob.0,
            &summary_blob.0,
            &thumbnail_blob.0,
            &ocr_blob.0,
            &caption_blob.0,
            &conversation_blob.0,
        ];
        let backup = directory.path().join("CompleteInventoryBackup.tessera");
        crate::recovery::backup(&vault, &backup).expect("protected backup");
        drop(vault);

        for root in [&path, &backup] {
            for value in protected_values {
                assert_locked_value_absent(root, value);
            }
        }
    }

    #[test]
    fn malformed_private_metadata_row_fails_closed() {
        let directory = tempfile::tempdir().expect("tempdir");
        let connection =
            crate::db::open_encrypted_database(&directory.path().join("vault.db"), &[0x78; 32])
                .expect("open");
        connection
            .execute(
                "INSERT INTO vault_metadata (key, value_json, updated_at)
                 VALUES ('embedding_models', '{not-json', 'now')",
                [],
            )
            .expect("malformed row");
        assert!(embedding_models(&connection).is_err());
    }

    #[test]
    fn missing_required_private_metadata_fails_reopen_and_diagnostics() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("MissingMetadata.tessera");
        let vault =
            super::super::Vault::create_with_params(&path, "migration-passphrase", &TEST_PARAMS)
                .expect("create");
        vault
            .conn()
            .execute("DELETE FROM vault_metadata WHERE key = 'created_at'", [])
            .expect("remove required row");
        assert!(crate::recovery::diagnose(&vault).is_err());
        drop(vault);
        assert!(super::super::Vault::open(&path, "migration-passphrase").is_err());
    }

    #[test]
    fn legacy_migration_protects_database_manifest_and_blob_address() {
        let (_directory, path, hash) = legacy_fixture();
        let legacy_path = path.join("blobs").join(&hash.0[..2]).join(&hash.0);
        assert!(matches!(
            super::super::Vault::open(&path, "migration-passphrase"),
            Err(VaultError::MetadataMigrationRequired)
        ));
        let report = migrate(&path, "migration-passphrase").expect("migrate");
        assert!(report.migrated);
        assert_eq!(report.converted_blobs, 1);
        assert_eq!(report.source_schema_version, 21);
        assert!(!legacy_path.exists());
        assert!(!migration_in_progress(&path));

        let raw_database = std::fs::read(path.join("vault.db")).expect("database bytes");
        for sentinel in [
            "MIGRATION-PRIVATE-SPACE-SENTINEL",
            "PRIVATE-FILENAME-SENTINEL.md",
            &hash.0,
        ] {
            assert!(!raw_database
                .windows(sentinel.len())
                .any(|bytes| bytes == sentinel.as_bytes()));
        }
        let public_manifest =
            std::fs::read_to_string(path.join("tessera.json")).expect("public manifest");
        assert!(!public_manifest.contains("MIGRATION-PRIVATE-MODEL-SENTINEL"));

        let vault = super::super::Vault::open(&path, "migration-passphrase").expect("open v3");
        assert_eq!(
            crate::space::list(&vault).expect("spaces")[0].name,
            "MIGRATION-PRIVATE-SPACE-SENTINEL"
        );
        assert_eq!(
            vault
                .blobs()
                .get(vault.dek().expect("dek"), &hash)
                .expect("blob"),
            b"MIGRATION-PRIVATE-CONTENT-SENTINEL"
        );
        assert_eq!(
            vault.embedding_models().expect("models")[0].version,
            "sentinel-model@v1"
        );
        let artifact_id = crate::ArtifactId("artifact-1".into());
        let derived = crate::extract::extract_text(&vault, &artifact_id)
            .expect("extract migrated content")
            .expect("derived migrated content");
        crate::chunk::chunk_derived_text(&vault, &derived, &crate::chunk::ChunkParams::default())
            .expect("chunk migrated content");
        crate::artifact::set_state(&vault, &artifact_id, crate::artifact::ArtifactState::Live)
            .expect("publish migrated fixture");
        crate::search::embed_missing(&vault, &MigrationEmbedder).expect("embed migrated content");
        assert_eq!(
            crate::search::query(
                &vault,
                &MigrationEmbedder,
                "private content sentinel",
                &crate::search::owner_constraints(),
                10,
            )
            .expect("query migrated content")
            .len(),
            1
        );
        let policy =
            crate::LensPolicy::new("post-migration", vec![crate::SpaceId("space-1".into())]);
        for sequence in 1..=2 {
            crate::receipt::Session::open(
                &vault,
                crate::receipt::AgentRef {
                    agent_id: "migration-test-agent".into(),
                    name: "Migration Test Agent".into(),
                },
                &policy,
                format!("post-migration receipt {sequence}"),
                false,
            )
            .expect("receipt session")
            .finalize()
            .expect("receipt finalize");
        }
        assert_eq!(crate::receipt::verify(&vault).expect("verify chain"), 2);
        assert!(!crate::recovery::diagnose(&vault)
            .expect("diagnostics")
            .has_fatal());
        assert_eq!(
            crate::recovery::rebuild_derived(&vault)
                .expect("repair migrated content")
                .failed,
            0
        );
        let backup = path
            .parent()
            .expect("parent")
            .join("MigratedBackup.tessera");
        crate::recovery::backup(&vault, &backup).expect("backup migrated vault");
        drop(vault);

        let restored = super::super::Vault::open(&backup, "migration-passphrase")
            .expect("open restored backup");
        assert_eq!(
            crate::receipt::verify(&restored).expect("restored chain"),
            2
        );
        crate::receipt::Session::open(
            &restored,
            crate::receipt::AgentRef {
                agent_id: "migration-test-agent".into(),
                name: "Migration Test Agent".into(),
            },
            &policy,
            "continued restored chain",
            false,
        )
        .expect("continued session")
        .finalize()
        .expect("continued receipt");
        assert_eq!(
            crate::receipt::verify(&restored).expect("continued chain"),
            3
        );
        drop(restored);

        let repeated = migrate(&path, "migration-passphrase").expect("repeat");
        assert!(!repeated.migrated);
    }

    #[test]
    fn every_durable_migration_boundary_resumes_to_one_valid_vault() {
        for failpoint in [
            MigrationFailpoint::AfterBlobs,
            MigrationFailpoint::AfterPrepare,
            MigrationFailpoint::AfterRetire,
            MigrationFailpoint::AfterSelect,
            MigrationFailpoint::AfterManifest,
        ] {
            let (_directory, path, hash) = legacy_fixture();
            assert!(matches!(
                migrate_at(&path, "migration-passphrase", failpoint),
                Err(MetadataMigrationError::Interrupted(_))
            ));
            assert!(migration_in_progress(&path));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for entry in [path.join(MARKER_NAME), path.join(PREPARED_NAME)] {
                    if entry.is_file() {
                        assert_eq!(
                            std::fs::metadata(&entry)
                                .expect("migration permissions")
                                .permissions()
                                .mode()
                                & 0o077,
                            0,
                            "migration file is not owner-only: {}",
                            entry.display()
                        );
                    }
                }
            }
            let resumed = migrate(&path, "migration-passphrase").expect("resume");
            assert!(resumed.resumed);
            let vault = super::super::Vault::open(&path, "migration-passphrase")
                .expect("open resumed vault");
            assert_eq!(
                vault
                    .blobs()
                    .get(vault.dek().expect("dek"), &hash)
                    .expect("blob"),
                b"MIGRATION-PRIVATE-CONTENT-SENTINEL"
            );
            assert!(!migration_in_progress(&path));
        }
    }

    #[test]
    fn exclusive_selection_boundary_rejects_a_competing_writer() {
        let (_directory, path, hash) = legacy_fixture();
        let report = migrate_at(
            &path,
            "migration-passphrase",
            MigrationFailpoint::DuringExclusiveSelection,
        )
        .expect("migration with competing writer probe");
        assert!(report.migrated);
        let vault = super::super::Vault::open(&path, "migration-passphrase").expect("open");
        assert_eq!(
            vault
                .blobs()
                .get(vault.dek().expect("dek"), &hash)
                .expect("blob"),
            b"MIGRATION-PRIVATE-CONTENT-SENTINEL"
        );
    }

    #[test]
    fn concurrent_commit_after_export_fails_closed_and_is_preserved_on_retry() {
        let (_directory, path, _hash) = legacy_fixture();
        assert!(matches!(
            migrate_at(
                &path,
                "migration-passphrase",
                MigrationFailpoint::AfterPrepareConcurrentCommit,
            ),
            Err(MetadataMigrationError::Validation(_))
        ));
        assert!(path.join("vault.db").is_file());
        assert!(!path.join(RETIRED_NAME).exists());
        let source = crate::db::open_plaintext_database(&path.join("vault.db")).expect("source");
        let name: String = source
            .query_row("SELECT name FROM spaces LIMIT 1", [], |row| row.get(0))
            .expect("concurrent commit remains authoritative");
        assert_eq!(name, "concurrent-writer-preserved");
        drop(source);

        migrate(&path, "migration-passphrase").expect("retry from preserved source");
        let vault = super::super::Vault::open(&path, "migration-passphrase").expect("open");
        assert_eq!(
            crate::space::list(&vault).expect("spaces")[0].name,
            "concurrent-writer-preserved"
        );
    }

    #[test]
    fn late_legacy_blob_write_is_protected_and_forces_retry() {
        let (_directory, path, _hash) = legacy_fixture();
        let late_hash = crate::blob::BlobHash(
            blake3::hash(b"LATE-LEGACY-BLOB-WRITE-SENTINEL")
                .to_hex()
                .to_string(),
        );
        assert!(matches!(
            migrate_at(
                &path,
                "migration-passphrase",
                MigrationFailpoint::DuringExclusiveLegacyBlobWrite,
            ),
            Err(MetadataMigrationError::Validation(_))
        ));
        assert!(!path
            .join("blobs")
            .join(&late_hash.0[..2])
            .join(&late_hash.0)
            .exists());
        assert!(path.join("vault.db").is_file());
        assert!(!path.join(RETIRED_NAME).exists());

        migrate(&path, "migration-passphrase").expect("retry after late blob write");
        let vault = super::super::Vault::open(&path, "migration-passphrase").expect("open");
        assert_eq!(
            vault
                .blobs()
                .get(vault.dek().expect("dek"), &late_hash)
                .expect("late blob retained as protected orphan"),
            b"LATE-LEGACY-BLOB-WRITE-SENTINEL"
        );
    }

    #[test]
    fn post_manifest_cleanup_reacquires_exclusive_legacy_boundary() {
        let (_directory, path, _hash) = legacy_fixture();
        assert!(matches!(
            migrate_at(
                &path,
                "migration-passphrase",
                MigrationFailpoint::AfterManifest,
            ),
            Err(MetadataMigrationError::Interrupted(_))
        ));
        assert!(path.join(RETIRED_NAME).is_file());

        let resumed = migrate_at(
            &path,
            "migration-passphrase",
            MigrationFailpoint::DuringV3Cleanup,
        )
        .expect("exclusive v3 cleanup");
        assert!(resumed.resumed);
        assert!(!path.join(RETIRED_NAME).exists());
        assert!(!migration_in_progress(&path));
    }

    #[test]
    fn malformed_marker_and_active_session_fail_closed() {
        let (_directory, path, _hash) = legacy_fixture();
        std::fs::write(path.join(MARKER_NAME), b"{not-json").expect("marker");
        assert!(matches!(
            migrate(&path, "migration-passphrase"),
            Err(MetadataMigrationError::InvalidState)
        ));

        std::fs::remove_file(path.join(MARKER_NAME)).expect("remove marker");
        let conn = crate::db::open_plaintext_database(&path.join("vault.db")).expect("db");
        conn.execute(
            "INSERT INTO sessions
             (id, pairing_id, lens_id, purpose, agent_name, started_at, expires_at, status)
             VALUES ('session', 'pairing', 'lens', 'test', 'guardian', datetime('now'),
                     datetime('now', '+1 hour'), 'active')",
            [],
        )
        .expect("session");
        drop(conn);
        assert!(matches!(
            migrate(&path, "migration-passphrase"),
            Err(MetadataMigrationError::ActiveSessions { count: 1 })
        ));
    }

    #[test]
    fn v3_resume_validates_marker_and_protected_state_before_cleanup() {
        let (_directory, path, hash) = legacy_fixture();
        assert!(matches!(
            migrate_at(
                &path,
                "migration-passphrase",
                MigrationFailpoint::AfterManifest
            ),
            Err(MetadataMigrationError::Interrupted(_))
        ));
        let keyslots = KeyslotFile::load(&path.join("keyslot.bin")).expect("keyslots");
        let dek = keyslots
            .unlock("migration-passphrase")
            .expect("unlock migration fixture");
        BlobStore::open(&path.join("blobs"))
            .expect("blob store")
            .delete(&dek, &hash)
            .expect("tamper protected original");
        assert!(matches!(
            migrate(&path, "migration-passphrase"),
            Err(MetadataMigrationError::Validation(_))
        ));
        assert!(path.join(RETIRED_NAME).is_file());
        assert!(path.join(MARKER_NAME).is_file());

        std::fs::write(path.join(MARKER_NAME), b"{not-json").expect("malformed v3 marker");
        assert!(matches!(
            migrate(&path, "migration-passphrase"),
            Err(MetadataMigrationError::InvalidState)
        ));
        assert!(path.join(RETIRED_NAME).is_file());
    }

    #[test]
    fn fatal_source_diagnostics_refuse_selection_and_preserve_legacy_authority() {
        let (_directory, path, _hash) = legacy_fixture();
        let conn = crate::db::open_plaintext_database(&path.join("vault.db")).expect("db");
        conn.execute(
            "INSERT INTO lenses (id, name, policy_json, created_at, updated_at)
             VALUES ('invalid-lens', 'invalid', '{not-json', 'now', 'now')",
            [],
        )
        .expect("fatal logical fault");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint fault");
        drop(conn);

        assert!(matches!(
            migrate(&path, "migration-passphrase"),
            Err(MetadataMigrationError::Validation(_))
        ));
        assert!(path.join("vault.db").is_file());
        assert!(!path.join(RETIRED_NAME).exists());
        assert_eq!(
            VaultManifest::load(&path.join("tessera.json"))
                .expect("legacy manifest")
                .format_version,
            2
        );
    }

    #[test]
    fn unmarked_staging_collision_fails_without_overwriting_unknown_residue() {
        let (_directory, path, _hash) = legacy_fixture();
        let collision = path.join(PREPARED_NAME);
        std::fs::write(&collision, b"owner-unknown-staging-residue").expect("collision");
        assert!(matches!(
            migrate(&path, "migration-passphrase"),
            Err(MetadataMigrationError::InvalidState)
        ));
        assert_eq!(
            std::fs::read(&collision).expect("preserved collision"),
            b"owner-unknown-staging-residue"
        );
        assert!(path.join("vault.db").is_file());
        assert!(!path.join(RETIRED_NAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn migration_permission_failure_preserves_legacy_authority() {
        use std::os::unix::fs::PermissionsExt;

        let (_directory, path, _hash) = legacy_fixture();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500))
            .expect("make bundle read-only");
        let result = migrate(&path, "migration-passphrase");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("restore bundle permissions");
        assert!(result.is_err());
        assert!(path.join("vault.db").is_file());
        assert!(!path.join(RETIRED_NAME).exists());
        assert_eq!(
            VaultManifest::load(&path.join("tessera.json"))
                .expect("legacy manifest")
                .format_version,
            2
        );
    }

    #[test]
    fn insufficient_staging_capacity_preserves_legacy_authority() {
        let (_directory, path, hash) = legacy_fixture();
        assert!(matches!(
            migrate_at(
                &path,
                "migration-passphrase",
                MigrationFailpoint::BeforeExportStorageFull
            ),
            Err(MetadataMigrationError::Io(ref error))
                if error.kind() == std::io::ErrorKind::StorageFull
        ));
        assert!(path.join("vault.db").is_file());
        assert!(!path.join(RETIRED_NAME).exists());
        let resumed = migrate(&path, "migration-passphrase").expect("resume after capacity");
        assert!(resumed.migrated);
        let vault = super::super::Vault::open(&path, "migration-passphrase").expect("open");
        assert_eq!(
            vault
                .blobs()
                .get(vault.dek().expect("dek"), &hash)
                .expect("blob"),
            b"MIGRATION-PRIVATE-CONTENT-SENTINEL"
        );
    }

    #[test]
    fn early_legacy_schema_is_upgraded_only_in_the_protected_replacement() {
        let (_directory, path, hash) = legacy_fixture_at(1);
        let report = migrate(&path, "migration-passphrase").expect("migrate early schema");
        assert_eq!(report.source_schema_version, 1);
        let vault = super::super::Vault::open(&path, "migration-passphrase").expect("open v3");
        assert_eq!(
            crate::db::migrations::schema_version(vault.conn()).expect("schema"),
            crate::db::migrations::migration_count() as u32
        );
        assert_eq!(
            vault
                .blobs()
                .get(vault.dek().expect("dek"), &hash)
                .expect("blob"),
            b"MIGRATION-PRIVATE-CONTENT-SENTINEL"
        );
    }

    #[test]
    fn whole_bundle_migration_protects_legacy_receipts_before_v3_commit() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("LegacyReceipt.tessera");
        let mut vault =
            super::super::Vault::create_with_params(&path, "migration-passphrase", &TEST_PARAMS)
                .expect("create");
        let space = crate::space::create(&vault, "receipt space", None).expect("space");
        let policy = crate::LensPolicy::new("receipt lens", vec![space]);
        let receipt = crate::receipt::Session::open(
            &vault,
            crate::receipt::AgentRef {
                agent_id: "legacy-receipt-agent".into(),
                name: "Legacy Receipt Agent".into(),
            },
            &policy,
            "legacy receipt migration",
            false,
        )
        .expect("session")
        .finalize()
        .expect("finalize");
        let receipt_id = receipt.receipt_id.clone();
        crate::receipt::downgrade_receipt_fixture(&mut vault, receipt)
            .expect("legacy receipt fixture");
        vault
            .conn()
            .execute_batch(
                "DROP TABLE vault_metadata;
                 DELETE FROM schema_migrations WHERE version = 22;
                 PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .expect("downgrade metadata schema");
        let plaintext = path.join(".legacy-plaintext-test.db");
        crate::db::export_encrypted_to_plaintext_test(vault.conn(), &plaintext)
            .expect("export legacy plaintext fixture");
        drop(vault);
        remove_database_and_sidecars(&path.join("vault.db")).expect("remove protected fixture");
        std::fs::rename(plaintext, path.join("vault.db")).expect("select legacy fixture");

        let report = migrate(&path, "migration-passphrase").expect("whole bundle migration");
        assert!(report.migrated);
        assert!(!path
            .join("receipts")
            .join(format!("{receipt_id}.json"))
            .exists());
        assert!(path
            .join("receipts")
            .join(format!("{receipt_id}.trc"))
            .is_file());
        let migrated = super::super::Vault::open(&path, "migration-passphrase").expect("open v3");
        assert_eq!(
            crate::receipt::verify(&migrated).expect("verify receipt"),
            1
        );
    }

    #[test]
    #[ignore = "controlled legacy migration performance evidence; run explicitly for issue #50"]
    fn legacy_migration_performance_measurement() {
        let (_directory, path, _hash) = legacy_fixture();
        let before = std::fs::metadata(path.join("vault.db"))
            .expect("legacy size")
            .len();
        let started = std::time::Instant::now();
        let report = migrate(&path, "migration-passphrase").expect("migrate");
        let elapsed_ms = started.elapsed().as_millis();
        let after = std::fs::metadata(path.join("vault.db"))
            .expect("protected size")
            .len();
        assert!(report.migrated);
        println!(
            "metadata_migration_performance_v1 elapsed_ms={elapsed_ms} \
             legacy_database_bytes={before} protected_database_bytes={after}"
        );
    }
}
