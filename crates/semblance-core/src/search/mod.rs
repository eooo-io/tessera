//! Policy-filtered semantic retrieval.

use serde::{Deserialize, Serialize};

/// A single search result with citation metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub artifact_id: crate::artifact::ArtifactId,
    pub artifact_title: String,
    pub chunk_id: String,
    pub relevance_score: f32,
    pub byte_range: (u64, u64),
}

#[cfg(test)]
mod tests {
    // Tests will be added in Iteration 4.
}
