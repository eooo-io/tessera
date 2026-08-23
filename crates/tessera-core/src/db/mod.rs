//! SQLite schema, migrations, and queries.

pub mod migrations;

use std::path::Path;

use rusqlite::Connection;
use thiserror::Error;

use crate::crypto::Dek;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("migration failed: {0}")]
    MigrationFailed(String),
    #[error("query failed: {0}")]
    QueryFailed(#[from] rusqlite::Error),
    #[error("database io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("database encryption is unavailable")]
    EncryptionUnavailable,
    #[error("database key or protected metadata is invalid")]
    InvalidProtectedDatabase,
}

/// Register the sqlite-vec extension for every future connection in this
/// process. Idempotent; the unsafe block is the crate's documented pattern.
fn register_vec_extension() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| unsafe {
        type InitFn = unsafe extern "C" fn(
            *mut rusqlite::ffi::sqlite3,
            *mut *const std::os::raw::c_char,
            *const rusqlite::ffi::sqlite3_api_routines,
        ) -> std::os::raw::c_int;
        let init: InitFn = std::mem::transmute(sqlite_vec::sqlite3_vec_init as *const ());
        rusqlite::ffi::sqlite3_auto_extension(Some(init));
    });
}

/// Open a legacy plaintext database. This exists only for explicit format-v3
/// migration and tests; ordinary vault operation must use [`open_database`].
pub(crate) fn open_plaintext_database(path: &Path) -> Result<Connection, DbError> {
    register_vec_extension();
    let conn = Connection::open(path)?;
    crate::vault::permissions::file(path)?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(conn)
}

/// Export a checkpointed legacy plaintext database to a new SQLCipher file.
/// The raw key is installed on the attached destination before the first
/// destination write; the source connection itself remains unkeyed.
pub(crate) fn export_plaintext_to_encrypted(
    source: &Connection,
    destination: &Path,
    key: &[u8; 32],
) -> Result<(), DbError> {
    if destination.exists() {
        return Err(DbError::MigrationFailed(
            "protected database staging path already exists".into(),
        ));
    }
    let destination = destination.to_str().ok_or_else(|| {
        DbError::MigrationFailed("protected database path is not valid UTF-8".into())
    })?;
    source.execute("ATTACH DATABASE ?1 AS protected KEY ''", [destination])?;
    if let Err(error) = install_raw_key_for_schema(source, "protected", key) {
        let _ = source.execute_batch("DETACH DATABASE protected");
        return Err(error);
    }
    let result = (|| -> Result<(), DbError> {
        source.query_row("SELECT sqlcipher_export('protected')", [], |_| Ok(()))?;
        source.execute_batch("DETACH DATABASE protected")?;
        let destination_path = Path::new(destination);
        std::fs::File::open(destination_path)?.sync_all()?;
        if let Some(parent) = destination_path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = source.execute_batch("DETACH DATABASE protected");
    }
    result
}

/// Open (or create) the protected vault database using a domain-separated key.
pub fn open_database(path: &Path, dek: &Dek) -> Result<Connection, DbError> {
    let key = dek.database_encryption_key();
    open_encrypted_database(path, &key)
}

/// Open or create a SQLCipher-protected database with a 256-bit high-entropy
/// secret.
///
/// The key is installed before the first database read. Existing files are
/// immediately read to prove the key and format before any mutating PRAGMA or
/// migration can run. Non-transaction temporary stores are forced to memory.
pub fn open_encrypted_database(path: &Path, key: &[u8; 32]) -> Result<Connection, DbError> {
    register_vec_extension();
    let existed = path.is_file();
    if existed && std::fs::metadata(path)?.len() < 16 {
        return Err(DbError::InvalidProtectedDatabase);
    }
    let conn = Connection::open(path)?;
    crate::vault::permissions::file(path)?;
    install_raw_key(&conn, key)?;

    let cipher_version: String = conn
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .map_err(|_| DbError::EncryptionUnavailable)?;
    if cipher_version.trim().is_empty() {
        return Err(DbError::EncryptionUnavailable);
    }

    let readable = conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    });
    if readable.is_err() && existed {
        return Err(DbError::InvalidProtectedDatabase);
    }
    readable?;

    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    migrations::run_migrations(&conn)?;
    Ok(conn)
}

fn install_raw_key(conn: &Connection, key: &[u8; 32]) -> Result<(), DbError> {
    // SAFETY: `conn.handle()` is valid for the lifetime of `conn`; SQLCipher
    // copies the exact key bytes during this call. The pointer and length match
    // the fixed-size slice, and this is the first operation after open.
    let status = unsafe {
        rusqlite::ffi::sqlite3_key(
            conn.handle(),
            key.as_ptr().cast::<std::ffi::c_void>(),
            key.len() as std::ffi::c_int,
        )
    };
    if status != rusqlite::ffi::SQLITE_OK {
        return Err(DbError::InvalidProtectedDatabase);
    }
    Ok(())
}

fn install_raw_key_for_schema(
    conn: &Connection,
    schema: &str,
    key: &[u8; 32],
) -> Result<(), DbError> {
    let schema = std::ffi::CString::new(schema)
        .map_err(|_| DbError::MigrationFailed("invalid database schema name".into()))?;
    // SAFETY: the connection and schema C string are live for this call and
    // SQLCipher copies the fixed-size key bytes.
    let status = unsafe {
        rusqlite::ffi::sqlite3_key_v2(
            conn.handle(),
            schema.as_ptr(),
            key.as_ptr().cast::<std::ffi::c_void>(),
            key.len() as std::ffi::c_int,
        )
    };
    if status != rusqlite::ffi::SQLITE_OK {
        return Err(DbError::InvalidProtectedDatabase);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn export_encrypted_to_plaintext_test(
    source: &Connection,
    destination: &Path,
) -> Result<(), DbError> {
    let destination = destination.to_str().ok_or_else(|| {
        DbError::MigrationFailed("plaintext test database path is not valid UTF-8".into())
    })?;
    source.execute("ATTACH DATABASE ?1 AS legacy_plain KEY ''", [destination])?;
    let result = (|| -> Result<(), DbError> {
        source.query_row("SELECT sqlcipher_export('legacy_plain')", [], |_| Ok(()))?;
        source.execute_batch("DETACH DATABASE legacy_plain")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = source.execute_batch("DETACH DATABASE legacy_plain");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn =
            open_encrypted_database(&dir.path().join("vault.db"), &[0x42; 32]).expect("open");
        (dir, conn)
    }

    #[test]
    fn open_enables_wal_and_foreign_keys() {
        let (_dir, conn) = open_temp();

        let journal: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .expect("journal_mode");
        assert_eq!(journal.to_lowercase(), "wal");

        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .expect("foreign_keys");
        assert_eq!(fk, 1);
    }

    #[test]
    fn encrypted_database_rejects_wrong_key_and_plaintext_scans() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.db");
        let correct = [0x11; 32];
        let wrong = [0x22; 32];
        let sentinel = "DB-METADATA-SENTINEL-ISSUE-50";

        let conn = open_encrypted_database(&path, &correct).expect("create encrypted");
        conn.execute(
            "INSERT INTO spaces (id, name, created_at, updated_at) VALUES ('space', ?1, 'now', 'now')",
            [sentinel],
        )
        .expect("insert sentinel");
        let wal = std::fs::read(path.with_extension("db-wal")).expect("read protected WAL");
        assert!(!wal
            .windows(sentinel.len())
            .any(|bytes| bytes == sentinel.as_bytes()));
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint");
        drop(conn);

        let raw = std::fs::read(&path).expect("read raw database");
        assert!(!raw
            .windows(sentinel.len())
            .any(|bytes| bytes == sentinel.as_bytes()));
        assert!(open_encrypted_database(&path, &wrong).is_err());
    }

    #[test]
    fn protected_open_rejects_plaintext_truncated_and_tampered_files() {
        let directory = tempfile::tempdir().expect("tempdir");
        let plaintext = directory.path().join("plaintext.db");
        let plaintext_conn = rusqlite::Connection::open(&plaintext).expect("plaintext open");
        plaintext_conn
            .execute_batch("CREATE TABLE private_sentinel(value TEXT);")
            .expect("plaintext schema");
        drop(plaintext_conn);
        assert!(matches!(
            open_encrypted_database(&plaintext, &[0x31; 32]),
            Err(DbError::InvalidProtectedDatabase)
        ));

        let truncated = directory.path().join("truncated.db");
        std::fs::write(&truncated, b"short").expect("truncated fixture");
        assert!(matches!(
            open_encrypted_database(&truncated, &[0x31; 32]),
            Err(DbError::InvalidProtectedDatabase)
        ));

        let tampered = directory.path().join("tampered.db");
        let conn = open_encrypted_database(&tampered, &[0x31; 32]).expect("protected fixture");
        conn.execute(
            "INSERT INTO spaces (id, name, created_at, updated_at)
             VALUES ('space', 'tamper target', 'now', 'now')",
            [],
        )
        .expect("insert");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint");
        drop(conn);
        let mut bytes = std::fs::read(&tampered).expect("read protected");
        bytes[100] ^= 0xff;
        std::fs::write(&tampered, bytes).expect("tamper");
        assert!(open_encrypted_database(&tampered, &[0x31; 32]).is_err());
    }

    #[test]
    fn encrypted_database_keeps_sqlite_temp_store_in_memory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = open_encrypted_database(&dir.path().join("vault.db"), &[0x33; 32])
            .expect("open encrypted");
        let temp_store: i64 = conn
            .query_row("PRAGMA temp_store", [], |row| row.get(0))
            .expect("temp_store");
        assert_eq!(temp_store, 2);
    }

    #[test]
    fn migrations_create_expected_tables() {
        let (_dir, conn) = open_temp();

        for table in [
            "schema_migrations",
            "spaces",
            "artifacts",
            "artifact_versions",
            "tags",
            "artifact_tags",
            "provenance",
            "receipt_chain_state",
            "receipts_index",
            "processing_errors",
            "oauth_clients",
            "oauth_authorization_codes",
            "oauth_access_tokens",
            "guardian_lock_state",
            "reindex_state",
            "reindex_embeddings_map",
            "conversation_archives",
            "conversations",
            "conversation_source_records",
            "conversation_nodes",
            "conversation_content_parts",
            "conversation_derivations",
            "conversation_spans",
            "conversation_chunk_map",
            "conversation_ingestion_runs",
            "conversation_ingestion_items",
            "conversation_ingestion_heads",
            "conversation_ingestion_replacements",
            "conversation_source_metadata",
        ] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |r| r.get(0),
                )
                .expect("query sqlite_master");
            assert_eq!(count, 1, "missing table: {table}");
        }
    }

    #[test]
    fn migrations_are_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.db");

        let schema_dump = |conn: &Connection| -> Vec<String> {
            let mut stmt = conn
                .prepare("SELECT COALESCE(sql, '') FROM sqlite_master ORDER BY name")
                .expect("prepare");
            stmt.query_map([], |r| r.get::<_, String>(0))
                .expect("query")
                .map(|r| r.expect("row"))
                .collect()
        };

        let conn = open_encrypted_database(&path, &[0x42; 32]).expect("first open");
        let first = schema_dump(&conn);
        let applied_first: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
            .expect("count");
        drop(conn);

        let conn = open_encrypted_database(&path, &[0x42; 32]).expect("second open");
        let second = schema_dump(&conn);
        let applied_second: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
            .expect("count");

        assert_eq!(first, second, "schema changed on re-open");
        assert_eq!(applied_first, applied_second, "migrations re-applied");
    }

    #[test]
    fn interrupted_migration_transaction_leaves_no_schema_or_ledger_fragment() {
        let (_dir, conn) = open_temp();
        conn.execute_batch("BEGIN").expect("begin fault fixture");
        conn.execute_batch("CREATE TABLE interrupted_migration_fixture (id INTEGER)")
            .expect("partial schema");
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at)
             VALUES (999, 'fault_fixture', datetime('now'))",
            [],
        )
        .expect("partial ledger");
        let interrupted = conn.execute_batch("THIS IS NOT VALID SQL");
        assert!(interrupted.is_err());
        conn.execute_batch("ROLLBACK").expect("rollback");

        let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'interrupted_migration_fixture'",
                [],
                |row| row.get(0),
            )
            .expect("table count");
        let ledger_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 999",
                [],
                |row| row.get(0),
            )
            .expect("ledger count");
        assert_eq!((table_count, ledger_count), (0, 0));
    }

    #[test]
    fn schema_version_matches_migration_count() {
        let (_dir, conn) = open_temp();
        let version = migrations::schema_version(&conn).expect("version");
        assert_eq!(version as usize, migrations::migration_count());
        assert!(version >= 1);
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let (_dir, conn) = open_temp();

        let result = conn.execute(
            "INSERT INTO artifacts (id, space_id, filename, media_type, created_at, updated_at)
             VALUES ('art_x', 'space_missing', 'f.txt', 'text/plain', '2026-07-05', '2026-07-05')",
            [],
        );
        assert!(result.is_err(), "insert with dangling space_id succeeded");
    }

    #[test]
    fn artifact_state_is_constrained_and_defaults_to_pending() {
        let (_dir, conn) = open_temp();

        conn.execute(
            "INSERT INTO spaces (id, name, created_at, updated_at)
             VALUES ('space_a', 'A', '2026-07-05', '2026-07-05')",
            [],
        )
        .expect("insert space");

        conn.execute(
            "INSERT INTO artifacts (id, space_id, filename, media_type, created_at, updated_at)
             VALUES ('art_a', 'space_a', 'f.txt', 'text/plain', '2026-07-05', '2026-07-05')",
            [],
        )
        .expect("insert artifact");
        let state: String = conn
            .query_row("SELECT state FROM artifacts WHERE id = 'art_a'", [], |r| {
                r.get(0)
            })
            .expect("select state");
        assert_eq!(state, "pending", "new artifacts must start quarantined");

        let bad = conn.execute(
            "INSERT INTO artifacts (id, space_id, filename, media_type, state, created_at, updated_at)
             VALUES ('art_b', 'space_a', 'g.txt', 'text/plain', 'visible', '2026-07-05', '2026-07-05')",
            [],
        );
        assert!(bad.is_err(), "invalid state value accepted");
    }

    #[test]
    fn provenance_locality_is_constrained() {
        let (_dir, conn) = open_temp();

        let bad = conn.execute(
            "INSERT INTO provenance (id, derived_blob_hash, tool, locality, created_at)
             VALUES ('prov_x', 'abc', 'extractor', 'mainframe', '2026-07-05')",
            [],
        );
        assert!(bad.is_err(), "invalid locality accepted");

        conn.execute(
            "INSERT INTO provenance (id, derived_blob_hash, tool, locality, created_at)
             VALUES ('prov_y', 'abc', 'extractor', 'local', '2026-07-05')",
            [],
        )
        .expect("valid provenance row");
    }
}
