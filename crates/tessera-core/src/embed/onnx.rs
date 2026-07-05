//! ONNX Runtime implementation of `EmbeddingProvider`.

use std::path::{Path, PathBuf};

use super::{mean_pool_normalize, EmbedError, EmbeddingProvider};

pub const MODEL_NAME: &str = "all-MiniLM-L6-v2";
pub const MODEL_VERSION: &str = "all-MiniLM-L6-v2@onnx-1";
pub const DIMENSIONS: usize = 384;
const MAX_TOKENS: usize = 256;

/// Files expected in the model directory, with their download sources.
pub const MODEL_FILES: &[(&str, &str)] = &[
    (
        "model.onnx",
        "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/onnx/model.onnx",
    ),
    (
        "tokenizer.json",
        "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/tokenizer.json",
    ),
];

/// Default model directory: `$TESSERA_MODEL_DIR` or the per-user data dir.
pub fn default_model_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("TESSERA_MODEL_DIR") {
        return PathBuf::from(dir).join(MODEL_NAME);
    }
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("Library/Application Support/tessera/models")
        .join(MODEL_NAME)
}

/// Whether both model files are present.
pub fn model_present(dir: &Path) -> bool {
    MODEL_FILES.iter().all(|(name, _)| dir.join(name).is_file())
}

pub struct OnnxEmbedder {
    session: std::sync::Mutex<ort::session::Session>,
    tokenizer: tokenizers::Tokenizer,
}

impl OnnxEmbedder {
    /// Load the embedder from a model directory containing `model.onnx` and
    /// `tokenizer.json`.
    pub fn load(dir: &Path) -> Result<Self, EmbedError> {
        if !model_present(dir) {
            return Err(EmbedError::ModelMissing(dir.display().to_string()));
        }
        let session = ort::session::Session::builder()
            .and_then(|mut b| b.commit_from_file(dir.join("model.onnx")))
            .map_err(|e| EmbedError::ModelLoad(e.to_string()))?;
        let tokenizer = tokenizers::Tokenizer::from_file(dir.join("tokenizer.json"))
            .map_err(|e| EmbedError::ModelLoad(e.to_string()))?;
        Ok(Self {
            session: std::sync::Mutex::new(session),
            tokenizer,
        })
    }

    fn embed_one(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| EmbedError::Tokenization(e.to_string()))?;

        let mut ids: Vec<i64> = encoding.get_ids().iter().map(|&x| x as i64).collect();
        let mut mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&x| x as i64)
            .collect();
        ids.truncate(MAX_TOKENS);
        mask.truncate(MAX_TOKENS);
        let len = ids.len();
        let type_ids = vec![0i64; len];

        let shape = [1usize, len];
        let to_tensor = |data: Vec<i64>| {
            ort::value::Tensor::from_array((shape, data))
                .map_err(|e| EmbedError::InferenceFailed(e.to_string()))
        };

        let mut session = self
            .session
            .lock()
            .map_err(|_| EmbedError::InferenceFailed("session lock poisoned".into()))?;
        let outputs = session
            .run(ort::inputs![
                "input_ids" => to_tensor(ids)?,
                "attention_mask" => to_tensor(mask.clone())?,
                "token_type_ids" => to_tensor(type_ids)?,
            ])
            .map_err(|e| EmbedError::InferenceFailed(e.to_string()))?;

        let (shape, data) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| EmbedError::InferenceFailed(e.to_string()))?;
        // shape: [1, tokens, dims]
        let dims = *shape
            .last()
            .ok_or_else(|| EmbedError::InferenceFailed("empty output shape".into()))?
            as usize;
        let hidden: Vec<Vec<f32>> = data.chunks(dims).take(len).map(|c| c.to_vec()).collect();
        let mask_u32: Vec<u32> = mask.iter().map(|&x| x as u32).collect();
        Ok(mean_pool_normalize(&hidden, &mask_u32))
    }
}

impl EmbeddingProvider for OnnxEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        self.embed_one(text)
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        texts.iter().map(|t| self.embed_one(t)).collect()
    }

    fn model_version(&self) -> &str {
        MODEL_VERSION
    }

    fn dimensions(&self) -> usize {
        DIMENSIONS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gated on model presence: run `tessera model fetch` (or set
    /// TESSERA_MODEL_DIR) to enable locally. CI without the model skips.
    #[test]
    fn embeds_real_text_when_model_present() {
        let dir = default_model_dir();
        if !model_present(&dir) {
            eprintln!("SKIP: model not present at {}", dir.display());
            return;
        }

        let embedder = OnnxEmbedder::load(&dir).expect("load");
        assert_eq!(embedder.dimensions(), 384);
        assert_eq!(embedder.model_version(), MODEL_VERSION);

        let a = embedder.embed("The cat sat on the mat.").expect("embed a");
        let b = embedder
            .embed("A feline rested on the rug.")
            .expect("embed b");
        let c = embedder
            .embed("Quarterly financial projections for 2026.")
            .expect("embed c");
        assert_eq!(a.len(), 384);

        // embed/embed_batch parity.
        let batch = embedder
            .embed_batch(&["The cat sat on the mat."])
            .expect("batch");
        assert_eq!(batch[0], a);

        // Semantically similar pair must beat the unrelated pair.
        let dot = |x: &[f32], y: &[f32]| -> f32 { x.iter().zip(y).map(|(a, b)| a * b).sum() };
        assert!(
            dot(&a, &b) > dot(&a, &c),
            "similarity ordering wrong: sim(a,b)={} sim(a,c)={}",
            dot(&a, &b),
            dot(&a, &c)
        );
    }

    #[test]
    #[ignore = "performance budget check — run explicitly (GOAL.md)"]
    fn embedding_latency_budget_50ms_per_chunk() {
        let dir = default_model_dir();
        if !model_present(&dir) {
            eprintln!("SKIP: model not present at {}", dir.display());
            return;
        }
        let embedder = OnnxEmbedder::load(&dir).expect("load");
        let chunk_text = "Tessera stores curated personal context. ".repeat(48); // ~500 est. tokens

        embedder.embed(&chunk_text).expect("warmup");
        let start = std::time::Instant::now();
        let runs = 16;
        for _ in 0..runs {
            embedder.embed(&chunk_text).expect("embed");
        }
        let per_chunk = start.elapsed() / runs;
        eprintln!("per-chunk embedding latency: {per_chunk:?}");
        assert!(
            per_chunk.as_millis() < 50,
            "budget exceeded: {per_chunk:?} (target <50ms)"
        );
    }

    #[test]
    fn missing_model_dir_is_a_clear_error() {
        match OnnxEmbedder::load(Path::new("/nonexistent/models/x")) {
            Err(EmbedError::ModelMissing(_)) => {}
            Err(other) => panic!("expected ModelMissing, got {other:?}"),
            Ok(_) => panic!("load must fail without model files"),
        }
    }
}
