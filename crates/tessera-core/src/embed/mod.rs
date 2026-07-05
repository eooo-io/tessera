//! Embedding provider trait and implementations.
//!
//! Default: all-MiniLM-L6-v2 (384 dimensions) via ONNX Runtime. Model files
//! are fetched by `tessera model fetch` (curl subprocess) into the model
//! directory and pinned by BLAKE3 in `models.lock` on first fetch.

pub mod onnx;

use thiserror::Error;

pub use onnx::OnnxEmbedder;

#[derive(Error, Debug)]
pub enum EmbedError {
    #[error("model loading failed: {0}")]
    ModelLoad(String),
    #[error("tokenization failed: {0}")]
    Tokenization(String),
    #[error("inference failed: {0}")]
    InferenceFailed(String),
    #[error("model files missing at {0} — run `tessera model fetch`")]
    ModelMissing(String),
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

/// Mean-pool token embeddings using the attention mask, then L2-normalize.
/// `hidden`: [tokens][dims] for one sequence; `mask`: 1 for real tokens.
pub fn mean_pool_normalize(hidden: &[Vec<f32>], mask: &[u32]) -> Vec<f32> {
    let dims = hidden.first().map(|v| v.len()).unwrap_or(0);
    let mut pooled = vec![0.0f32; dims];
    let mut count = 0u32;
    for (token, &m) in hidden.iter().zip(mask) {
        if m != 0 {
            for (acc, &x) in pooled.iter_mut().zip(token) {
                *acc += x;
            }
            count += 1;
        }
    }
    if count == 0 {
        return pooled; // all-padding input: zero vector, not NaN
    }
    for x in &mut pooled {
        *x /= count as f32;
    }
    let norm: f32 = pooled.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in &mut pooled {
            *x /= norm;
        }
    }
    pooled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mean_pooling_ignores_masked_positions() {
        // Two real tokens [1,0] and [0,1]; one padding token [9,9] that must
        // not contribute.
        let hidden = vec![vec![1.0, 0.0], vec![0.0, 1.0], vec![9.0, 9.0]];
        let mask = vec![1, 1, 0];

        let pooled = mean_pool_normalize(&hidden, &mask);
        // Mean of real tokens = [0.5, 0.5]; normalized = [1/√2, 1/√2].
        let expected = 1.0 / 2.0_f32.sqrt();
        assert!((pooled[0] - expected).abs() < 1e-6, "got {pooled:?}");
        assert!((pooled[1] - expected).abs() < 1e-6, "got {pooled:?}");
    }

    #[test]
    fn output_is_unit_length() {
        let hidden = vec![vec![3.0, 4.0], vec![6.0, 8.0]];
        let mask = vec![1, 1];

        let pooled = mean_pool_normalize(&hidden, &mask);
        let norm: f32 = pooled.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-6, "norm was {norm}");
    }

    #[test]
    fn all_masked_input_yields_zero_vector_not_nan() {
        let hidden = vec![vec![1.0, 2.0]];
        let mask = vec![0];

        let pooled = mean_pool_normalize(&hidden, &mask);
        assert!(pooled.iter().all(|x| x.is_finite()));
        assert!(pooled.iter().all(|&x| x == 0.0));
    }
}
