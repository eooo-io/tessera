//! Spaces — hierarchical containers for organizing artifacts.

use serde::{Deserialize, Serialize};

/// Typed wrapper for space identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpaceId(pub String);

/// A space in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Space {
    pub id: SpaceId,
    pub name: String,
    pub parent_id: Option<SpaceId>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    // Tests will be added in Iteration 1.
}
