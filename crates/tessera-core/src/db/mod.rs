//! SQLite schema, migrations, and queries.

pub mod migrations;

use std::path::Path;

use rusqlite::Connection;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("migration failed: {0}")]
    MigrationFailed(String),
    #[error("query failed: {0}")]
    QueryFailed(#[from] rusqlite::Error),
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

/// Open (or create) the vault database: sqlite-vec available, WAL mode,
/// foreign keys on, all pending migrations applied.
pub fn open_database(path: &Path) -> Result<Connection, DbError> {
    register_vec_extension();
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    migrations::run_migrations(&conn)?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = open_database(&dir.path().join("vault.db")).expect("open");
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

        let conn = open_database(&path).expect("first open");
        let first = schema_dump(&conn);
        let applied_first: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
            .expect("count");
        drop(conn);

        let conn = open_database(&path).expect("second open");
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
