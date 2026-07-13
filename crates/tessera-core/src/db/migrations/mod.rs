//! Schema migrations for the vault database.
//!
//! Migrations are ordered, applied once, and recorded in
//! `schema_migrations`. Never edit a shipped migration — append a new one.

use rusqlite::Connection;

use super::DbError;

/// Ordered list of (name, SQL) migrations.
const MIGRATIONS: &[(&str, &str)] = &[
    ("0001_initial", include_str!("0001_initial.sql")),
    ("0002_derived_text", include_str!("0002_derived_text.sql")),
    ("0003_chunks", include_str!("0003_chunks.sql")),
    (
        "0004_state_transitions",
        include_str!("0004_state_transitions.sql"),
    ),
    ("0005_embeddings", include_str!("0005_embeddings.sql")),
    ("0006_lenses", include_str!("0006_lenses.sql")),
    ("0007_summaries", include_str!("0007_summaries.sql")),
    ("0008_pairings", include_str!("0008_pairings.sql")),
    ("0009_sessions", include_str!("0009_sessions.sql")),
    ("0010_receipt_chain", include_str!("0010_receipt_chain.sql")),
    (
        "0011_processing_errors",
        include_str!("0011_processing_errors.sql"),
    ),
    ("0012_http_oauth", include_str!("0012_http_oauth.sql")),
    (
        "0013_pairing_grant_version",
        include_str!("0013_pairing_grant_version.sql"),
    ),
    (
        "0014_guardian_lock_generation",
        include_str!("0014_guardian_lock_generation.sql"),
    ),
    ("0015_reindex_state", include_str!("0015_reindex_state.sql")),
    (
        "0016_transcript_turns",
        include_str!("0016_transcript_turns.sql"),
    ),
    ("0017_web_sources", include_str!("0017_web_sources.sql")),
    (
        "0018_conversation_provenance",
        include_str!("0018_conversation_provenance.sql"),
    ),
];

/// Number of migrations this build knows about.
pub fn migration_count() -> usize {
    MIGRATIONS.len()
}

/// Highest applied migration version (0 = empty database).
pub fn schema_version(conn: &Connection) -> Result<u32, DbError> {
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'",
        [],
        |r| r.get(0),
    )?;
    if exists == 0 {
        return Ok(0);
    }
    let version: Option<u32> =
        conn.query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
            r.get(0)
        })?;
    Ok(version.unwrap_or(0))
}

/// Run all pending migrations on the given connection.
pub fn run_migrations(conn: &Connection) -> Result<(), DbError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version    INTEGER PRIMARY KEY,
            name       TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )",
    )?;

    let applied = schema_version(conn)? as usize;
    for (index, (name, sql)) in MIGRATIONS.iter().enumerate().skip(applied) {
        let version = index + 1;
        let tx_result: Result<(), rusqlite::Error> = (|| {
            conn.execute_batch("BEGIN")?;
            conn.execute_batch(sql)?;
            conn.execute(
                "INSERT INTO schema_migrations (version, name, applied_at)
                 VALUES (?1, ?2, datetime('now'))",
                rusqlite::params![version as i64, name],
            )?;
            conn.execute_batch("COMMIT")?;
            Ok(())
        })();
        if let Err(e) = tx_result {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(DbError::MigrationFailed(format!("{name}: {e}")));
        }
    }
    Ok(())
}
