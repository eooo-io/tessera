//! Embedding provider trait and implementations.
//!
//! Default: all-MiniLM-L6-v2 (384 dimensions) via ONNX Runtime.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EmbedError {
    #[error("model loading failed: {0}")]
    ModelLoad(String),
    #[error("inference failed: {0}")]
    InferenceFailed(String),
}

/// Trait for embedding providers — allows swapping models without
/// changing the rest of the pipeline.
pub trait EmbeddingProvider: Send + Sync {
    /// Embed a single text string.
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError>;

    /// Embed a batch of text strings.
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError>;

    /// Return the model version identifier.
    fn model_version(&self) -> &str;

    /// Return the embedding dimensionality.
    fn dimensions(&self) -> usize;
}

#[cfg(test)]
mod tests {
    // Tests will be added in Iteration 3.
}
