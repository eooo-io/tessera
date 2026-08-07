//! ONNX Runtime implementation of `EmbeddingProvider`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{mean_pool_normalize, EmbedError, EmbeddingProvider};

pub const MODEL_NAME: &str = "all-MiniLM-L6-v2";
pub const MODEL_VERSION: &str = "all-MiniLM-L6-v2@onnx-1";
pub const DIMENSIONS: usize = 384;
/// Conservative v1 floor: separates every unrelated sanitized calibration
/// pair while preserving all relevant pairs. Hard semantic negatives remain a
/// documented limitation for #42/#43 rather than being mislabeled as truth.
pub const CALIBRATED_RELEVANCE_FLOOR: f32 = 0.20;
const MAX_TOKENS: usize = 256;
pub const TRUSTED_MANIFEST_JSON: &str =
    include_str!("../../../../spec/model-manifests/all-MiniLM-L6-v2-onnx-1.json");

pub use crate::model::TrustedModelFile;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedModelManifest {
    pub schema_version: u32,
    pub model_name: String,
    pub model_version: String,
    pub source_repository: String,
    pub revision: String,
    pub license: String,
    pub dimensions: usize,
    pub max_tokens: usize,
    pub tokenizer_version: String,
    pub runtime_versions: String,
    pub provenance: String,
    pub files: Vec<TrustedModelFile>,
}

pub fn trusted_manifest() -> Result<TrustedModelManifest, EmbedError> {
    let manifest: TrustedModelManifest = serde_json::from_str(TRUSTED_MANIFEST_JSON)
        .map_err(|e| EmbedError::ModelVerification(format!("invalid built-in manifest: {e}")))?;
    if manifest.schema_version != 1
        || manifest.model_name != MODEL_NAME
        || manifest.model_version != MODEL_VERSION
        || manifest.dimensions != DIMENSIONS
        || manifest.max_tokens != MAX_TOKENS
    {
        return Err(EmbedError::ModelVerification(
            "built-in manifest disagrees with the fixed v1 runtime contract".into(),
        ));
    }
    Ok(manifest)
}

pub fn download_url(manifest: &TrustedModelManifest, file: &TrustedModelFile) -> String {
    crate::model::download_url(&manifest.source_repository, &manifest.revision, file)
}

/// Default model directory: `$TESSERA_MODEL_DIR` or the per-user data dir.
pub fn default_model_dir() -> PathBuf {
    crate::model::model_dir(MODEL_NAME)
}

/// Whether all trusted model files are present. Loading additionally verifies
/// their sizes and digests.
pub fn model_present(dir: &Path) -> bool {
    trusted_manifest()
        .map(|m| crate::model::files_present(dir, &m.files))
        .unwrap_or(false)
}

/// Verify every activated byte against the repository-controlled manifest.
pub fn verify_model_dir(dir: &Path) -> Result<TrustedModelManifest, EmbedError> {
    let manifest = trusted_manifest()?;
    crate::model::verify_files(dir, &manifest.files)?;
    Ok(manifest)
}

impl From<crate::model::ModelError> for EmbedError {
    fn from(error: crate::model::ModelError) -> Self {
        match error {
            crate::model::ModelError::Missing(message) => Self::ModelMissing(message),
            crate::model::ModelError::Verification(message) => Self::ModelVerification(message),
        }
    }
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
        verify_model_dir(dir)?;
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

    fn calibrated_relevance_floor(&self) -> Option<f32> {
        Some(CALIBRATED_RELEVANCE_FLOOR)
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

    #[test]
    fn substituted_model_files_fail_verification_before_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("model.onnx"), b"not the trusted model").expect("write");
        std::fs::write(dir.path().join("tokenizer.json"), b"{}").expect("write");

        let error = verify_model_dir(dir.path()).expect_err("substitution must fail");
        assert!(
            error.to_string().contains("expected"),
            "diagnostic should identify the violated trusted property: {error}"
        );
        assert!(OnnxEmbedder::load(dir.path()).is_err());
    }

    #[test]
    fn trusted_manifest_is_pinned_and_matches_fixed_v1_contract() {
        let manifest = trusted_manifest().expect("manifest");
        assert_eq!(manifest.revision.len(), 40);
        assert!(!manifest.revision.contains("main"));
        assert_eq!(manifest.dimensions, DIMENSIONS);
        assert_eq!(manifest.license, "Apache-2.0");
        assert!(manifest.files.iter().all(|file| file.sha256.len() == 64));
    }
}
