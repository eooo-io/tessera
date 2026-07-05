//! Vector index trait and implementations.
//!
//! Default implementation (M3): sqlite-vec — vectors live in the same SQLite
//! database as metadata, so policy filtering happens inside the search query
//! itself (single SQL join), not as post-retrieval over-fetching. The trait
//! boundary is therefore drawn ABOVE filtering: `search` receives the lens's
//! retrieval constraints and returns already-filtered chunk references. A
//! future remote backend (Qdrant, pgvector) implements its own filtered
//! search behind the same signature.

use thiserror::Error;

use crate::artifact::{ArtifactId, Sensitivity};
use crate::space::SpaceId;

#[derive(Error, Debug)]
pub enum IndexError {
    #[error("unknown embedding model: {0}")]
    UnknownModel(String),
    #[error("dimension mismatch: index has {expected}, query has {found}")]
    DimensionMismatch { expected: usize, found: usize },
    #[error("database error: {0}")]
    Database(String),
}

/// Retrieval constraints compiled from a lens policy (M4). The quarantine
/// rule (only `live` artifacts) is NOT expressed here — implementations
/// must always enforce it; it is not optional or overridable.
#[derive(Debug, Clone, Default)]
pub struct RetrievalConstraints {
    pub space_ids: Vec<SpaceId>,
    pub space_exclude_ids: Vec<SpaceId>,
    pub tag_include: Vec<String>,
    pub tag_exclude: Vec<String>,
    pub media_types: Vec<String>,
    pub sensitivity_ceiling: Sensitivity,
}

/// A filtered search hit: a chunk and its source artifact.
#[derive(Debug, Clone, PartialEq)]
pub struct ChunkRef {
    pub chunk_id: String,
    pub artifact_id: ArtifactId,
    /// Distance (lower is closer), as reported by the backend.
    pub distance: f32,
}

/// Trait for vector index implementations — allows swapping backends.
pub trait VectorIndex: Send + Sync {
    /// Insert (or replace) the embedding for a chunk.
    fn insert(&mut self, chunk_id: &str, embedding: &[f32]) -> Result<(), IndexError>;

    /// Remove a chunk's embedding.
    fn delete(&mut self, chunk_id: &str) -> Result<(), IndexError>;

    /// Policy-filtered nearest-neighbor search: top `k` chunks matching the
    /// constraints, closest first. Implementations MUST additionally
    /// restrict results to artifacts in the `live` state (quarantine
    /// invariant).
    fn search(
        &self,
        query: &[f32],
        constraints: &RetrievalConstraints,
        k: usize,
    ) -> Result<Vec<ChunkRef>, IndexError>;

    /// Number of indexed chunks.
    fn len(&self) -> Result<usize, IndexError>;

    /// Whether the index is empty.
    fn is_empty(&self) -> Result<bool, IndexError> {
        Ok(self.len()? == 0)
    }
}

#[cfg(test)]
mod tests {
    // Behavior tests arrive with the sqlite-vec implementation (M3, #15);
    // this module is trait-level scaffolding until then.
}
