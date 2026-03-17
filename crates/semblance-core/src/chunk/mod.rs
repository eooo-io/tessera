//! Sentence-aware chunking — 512 tokens target, 64 token overlap.

use serde::{Deserialize, Serialize};

/// A chunk of extracted text, sized for embedding and retrieval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    pub id: String,
    pub derived_text_id: String,
    pub chunk_index: u32,
    pub byte_offset_start: u64,
    pub byte_offset_end: u64,
    pub token_count: u32,
    pub section_heading: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    // Tests will be added in Iteration 2.
}
