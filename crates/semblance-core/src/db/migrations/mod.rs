//! Schema migrations for the vault database.

/// Run all pending migrations on the given connection.
pub fn run_migrations(_conn: &rusqlite::Connection) -> Result<(), super::DbError> {
    todo!("Iteration 1: implement schema migrations")
}
