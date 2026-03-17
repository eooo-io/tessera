//! Vector index trait and implementations.
//!
//! Default: HNSW index for approximate nearest neighbor search.

use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IndexError {
    #[error("index not found at {0}")]
    NotFound(String),
    #[error("index corrupted")]
    Corrupted,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Trait for vector index implementations — allows swapping backends.
pub trait VectorIndex: Send + Sync {
    /// Insert a vector with the given ID.
    fn insert(&mut self, vector_id: u64, embedding: &[f32]) -> Result<(), IndexError>;

    /// Search for the top-N nearest neighbors to the query vector.
    /// Returns (vector_id, distance) pairs sorted by relevance.
    fn search(&self, query: &[f32], top_n: usize) -> Result<Vec<(u64, f32)>, IndexError>;

    /// Delete a vector by ID.
    fn delete(&mut self, vector_id: u64) -> Result<(), IndexError>;

    /// Persist the index to disk.
    fn persist(&self, path: &Path) -> Result<(), IndexError>;

    /// Return the number of vectors in the index.
    fn len(&self) -> usize;

    /// Check if the index is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    // Tests will be added in Iteration 3.
}
