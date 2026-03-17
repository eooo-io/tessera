//! Artifacts — files/documents with metadata, tags, and version history.

use serde::{Deserialize, Serialize};

/// Typed wrapper for artifact identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactId(pub String);

/// Sensitivity classification for artifacts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    #[default]
    Internal,
    Confidential,
    Restricted,
}

/// An artifact in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: ArtifactId,
    pub space_id: crate::space::SpaceId,
    pub filename: String,
    pub content_type: String,
    pub sensitivity: Sensitivity,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// A version of an artifact, linked to its encrypted blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactVersion {
    pub id: String,
    pub artifact_id: ArtifactId,
    pub version: u32,
    pub blob_hash: String,
    pub size_bytes: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    // Tests will be added in Iteration 1.
}
