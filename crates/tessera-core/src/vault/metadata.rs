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
    AfterSelect,
    AfterManifest,
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
            let conn = crate::db::open_database(&path.join("vault.db"), &dek)?;
            validate_database(&conn)?;
            hydrate_manifest(&conn, &mut manifest)?;
            return Ok(MetadataMigrationReport {
                migrated: false,
                resumed: false,
                converted_blobs: 0,
                source_schema_version: crate::db::migrations::schema_version(&conn)?,
            });
        }
        let conn = crate::db::open_database(&path.join("vault.db"), &dek)?;
        validate_database(&conn)?;
        hydrate_manifest(&conn, &mut manifest)?;
        drop(conn);
        remove_if_exists(&path.join(PREPARED_NAME))?;
        remove_database_and_sidecars(&path.join(RETIRED_NAME))?;
        remove_if_exists(&marker_path)?;
        sync_directory(path)?;
        return Ok(MetadataMigrationReport {
            migrated: false,
            resumed: true,
            converted_blobs: 0,
            source_schema_version: crate::db::migrations::migration_count() as u32,
        });
    }
    if manifest.format_version == 0 || manifest.format_version > 2 {
        return Err(MetadataMigrationError::NotLegacy);
    }

    let marker = load_marker_or_default(path)?;
    if marker.version != FORMAT_VERSION {
        return Err(MetadataMigrationError::InvalidState);
    }

    let database = path.join("vault.db");
    let prepared = path.join(PREPARED_NAME);
    let retired = path.join(RETIRED_NAME);
    let database_key = dek.database_encryption_key();
    let preflight = match crate::db::open_encrypted_database(&database, &database_key) {
        Ok(connection) => connection,
        Err(_) if database.is_file() && !retired.exists() => {
            crate::db::open_plaintext_database(&database)?
        }
        Err(_) if retired.is_file() => crate::db::open_plaintext_database(&retired)?,
        Err(_) => {
            return Err(MetadataMigrationError::Validation(
                "no authoritative database is available for migration preflight".into(),
            ));
        }
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
    let converted_blobs = blobs.migrate_legacy_blobs(&dek).map_err(VaultError::from)?;
    save_marker(path, MigrationPhase::BlobsProtected)?;
    if failpoint == MigrationFailpoint::AfterBlobs {
        return Err(MetadataMigrationError::Interrupted("blob protection"));
    }

    let selected = crate::db::open_encrypted_database(&database, &database_key).ok();
    let source_version;
    if let Some(selected) = selected {
        if !retired.is_file() {
            return Err(MetadataMigrationError::Validation(
                "protected database selected without retained legacy authority".into(),
            ));
        }
        validate_database(&selected)?;
        source_version = plaintext_schema_version(&retired)?;
        drop(selected);
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
        save_marker(path, MigrationPhase::DatabasePrepared)?;
        if failpoint == MigrationFailpoint::AfterPrepare {
            return Err(MetadataMigrationError::Interrupted("database preparation"));
        }
        drop(source);

        if source_path == database {
            std::fs::rename(&database, &retired)?;
            move_sidecar_if_present(&database, &retired, "-wal")?;
            move_sidecar_if_present(&database, &retired, "-shm")?;
            sync_directory(path)?;
        }
        std::fs::rename(&prepared, &database)?;
        sync_directory(path)?;
        let selected = crate::db::open_encrypted_database(&database, &database_key)?;
        validate_database(&selected)?;
        drop(selected);
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
        dek: Some(dek),
    };
    crate::receipt::migrate_legacy_receipts(&mut migration_vault)?;
    crate::receipt::verify(&migration_vault)?;
    drop(migration_vault);
    manifest.format_version = FORMAT_VERSION;
    manifest.save(&manifest_path).map_err(VaultError::from)?;
    save_marker(path, MigrationPhase::ManifestCommitted)?;
    if failpoint == MigrationFailpoint::AfterManifest {
        return Err(MetadataMigrationError::Interrupted("manifest commit"));
    }

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
        let marker: MigrationMarker = serde_json::from_slice(&std::fs::read(marker_path)?)?;
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

fn plaintext_schema_version(path: &Path) -> Result<u32, MetadataMigrationError> {
    let conn = crate::db::open_plaintext_database(path)?;
    validate_database(&conn)?;
    Ok(crate::db::migrations::schema_version(&conn)?)
}

fn logical_inventory(conn: &Connection) -> Result<BTreeMap<String, i64>, MetadataMigrationError> {
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
        inventory.insert(name, count);
    }
    Ok(inventory)
}

fn compare_logical_inventory(
    source: &Connection,
    candidate: &Connection,
) -> Result<(), MetadataMigrationError> {
    let source = logical_inventory(source)?;
    let candidate = logical_inventory(candidate)?;
    for (table, source_count) in source {
        if candidate.get(&table) != Some(&source_count) {
            return Err(MetadataMigrationError::Validation(
                "protected database inventory differs from legacy source".into(),
            ));
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
    fn malformed_marker_and_active_session_fail_closed() {
        let (_directory, path, _hash) = legacy_fixture();
        std::fs::write(path.join(MARKER_NAME), b"{not-json").expect("marker");
        assert!(matches!(
            migrate(&path, "migration-passphrase"),
            Err(MetadataMigrationError::Json(_))
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
