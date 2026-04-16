//! SQLite schema, migrations, and queries.

pub mod migrations;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("migration failed: {0}")]
    MigrationFailed(String),
    #[error("query failed: {0}")]
    QueryFailed(#[from] rusqlite::Error),
}

#[cfg(test)]
mod tests {
    // Tests will be added in Iteration 1.
}
