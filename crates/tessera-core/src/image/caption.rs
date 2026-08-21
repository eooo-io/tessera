//! Local image captioning with a manifest-pinned ONNX vision-language model.
//!
//! A ViT encoder turns the image into patch embeddings; a GPT-2 decoder reads
//! those embeddings and emits a sentence describing the scene. Both halves run
//! locally through ONNX Runtime, and both are verified against the
//! repository-controlled manifest before loading — the same supply chain the
//! embedder uses, for the same reason: a swapped caption model would silently
//! change what the vault says an image is.
//!
//! Decoding is greedy. Captions are a searchable surface, not prose, so
//! sampling would only make the same image describe itself differently on
//! every run and break derivation idempotency.

use std::path::Path;

use image::RgbImage;
use serde::{Deserialize, Serialize};

use super::{CaptionIdentity, ImageError};
use crate::model::{self, TrustedModelFile};

pub const TOOL: &str = "onnxruntime";
pub const MODEL_NAME: &str = "vit-gpt2-image-captioning";
pub const MODEL_VERSION: &str = "vit-gpt2-image-captioning@onnx-1";

pub const TRUSTED_MANIFEST_JSON: &str =
    include_str!("../../../../spec/model-manifests/vit-gpt2-image-captioning-onnx-1.json");

/// ViT preprocessing constants, from the upstream `preprocessor_config.json`.
const IMAGE_MEAN: f32 = 0.5;
const IMAGE_STD: f32 = 0.5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedCaptionManifest {
    pub schema_version: u32,
    pub model_name: String,
    pub model_version: String,
    pub source_repository: String,
    pub revision: String,
    pub license: String,
    pub image_size: u32,
    pub hidden_size: usize,
    pub max_new_tokens: usize,
    pub decoder_start_token_id: i64,
    pub eos_token_id: i64,
    pub tokenizer_version: String,
    pub runtime_versions: String,
    pub provenance: String,
    pub files: Vec<TrustedModelFile>,
}

pub fn trusted_manifest() -> Result<TrustedCaptionManifest, ImageError> {
    let manifest: TrustedCaptionManifest =
        serde_json::from_str(TRUSTED_MANIFEST_JSON).map_err(|error| {
            ImageError::InvalidProvider(format!("invalid caption manifest: {error}"))
        })?;
    if manifest.schema_version != 1
        || manifest.model_name != MODEL_NAME
        || manifest.model_version != MODEL_VERSION
    {
        return Err(ImageError::InvalidProvider(
            "built-in caption manifest disagrees with the fixed v1 runtime contract".into(),
        ));
    }
    Ok(manifest)
}

/// Where the caption model is installed.
pub fn default_model_dir() -> std::path::PathBuf {
    model::model_dir(MODEL_NAME)
}

pub fn model_present(dir: &Path) -> bool {
    trusted_manifest()
        .map(|manifest| model::files_present(dir, &manifest.files))
        .unwrap_or(false)
}

pub fn verify_model_dir(dir: &Path) -> Result<TrustedCaptionManifest, ImageError> {
    let manifest = trusted_manifest()?;
    model::verify_files(dir, &manifest.files)?;
    Ok(manifest)
}

pub struct OnnxCaptioner {
    encoder: std::sync::Mutex<ort::session::Session>,
    decoder: std::sync::Mutex<ort::session::Session>,
    tokenizer: tokenizers::Tokenizer,
    manifest: TrustedCaptionManifest,
}

impl OnnxCaptioner {
    /// Load and verify the captioner from an installed model directory.
    pub fn load(dir: &Path) -> Result<Self, ImageError> {
        if !model_present(dir) {
            return Err(ImageError::Processing(format!(
                "caption model missing at {} — run `tessera model fetch`",
                dir.display()
            )));
        }
        let manifest = verify_model_dir(dir)?;
        let open = |name: &str| {
            ort::session::Session::builder()
                .and_then(|mut builder| builder.commit_from_file(dir.join(name)))
                .map_err(|error| ImageError::Processing(format!("loading caption {name}: {error}")))
        };
        let encoder = open("encoder_model.onnx")?;
        let decoder = open("decoder_model.onnx")?;
        let tokenizer = tokenizers::Tokenizer::from_file(dir.join("tokenizer.json"))
            .map_err(|error| ImageError::Processing(format!("caption tokenizer: {error}")))?;
        Ok(Self {
            encoder: std::sync::Mutex::new(encoder),
            decoder: std::sync::Mutex::new(decoder),
            tokenizer,
            manifest,
        })
    }

    pub fn identity(&self) -> CaptionIdentity {
        CaptionIdentity {
            tool: TOOL.to_owned(),
            model: self.manifest.model_name.clone(),
            model_version: self.manifest.model_version.clone(),
        }
    }

    /// Describe the scene in one sentence.
    pub fn caption(&self, pixels: &RgbImage) -> Result<String, ImageError> {
        let encoder_hidden = self.encode(pixels)?;
        self.decode(&encoder_hidden)
    }

    /// Run the ViT encoder, returning `[patches, hidden_size]` embeddings.
    fn encode(&self, pixels: &RgbImage) -> Result<(Vec<f32>, usize), ImageError> {
        let size = self.manifest.image_size;
        let tensor = preprocess(pixels, size);
        let input =
            ort::value::Tensor::from_array(([1usize, 3, size as usize, size as usize], tensor))
                .map_err(|error| {
                    ImageError::Processing(format!("caption encoder input: {error}"))
                })?;

        let mut session = self
            .encoder
            .lock()
            .map_err(|_| ImageError::Processing("caption encoder lock poisoned".into()))?;
        let outputs = session
            .run(ort::inputs!["pixel_values" => input])
            .map_err(|error| ImageError::Processing(format!("caption encoder: {error}")))?;
        let (shape, data) = outputs["last_hidden_state"]
            .try_extract_tensor::<f32>()
            .map_err(|error| ImageError::Processing(format!("caption encoder output: {error}")))?;
        let hidden = *shape
            .last()
            .ok_or_else(|| ImageError::Processing("empty encoder output shape".into()))?
            as usize;
        if hidden != self.manifest.hidden_size {
            return Err(ImageError::Processing(format!(
                "caption encoder produced hidden size {hidden}, manifest declares {}",
                self.manifest.hidden_size
            )));
        }
        Ok((data.to_vec(), hidden))
    }

    /// Greedy-decode a caption from the encoder embeddings.
    fn decode(&self, (encoder_hidden, hidden): &(Vec<f32>, usize)) -> Result<String, ImageError> {
        let patches = encoder_hidden.len() / hidden;
        let mut ids: Vec<i64> = vec![self.manifest.decoder_start_token_id];

        let mut session = self
            .decoder
            .lock()
            .map_err(|_| ImageError::Processing("caption decoder lock poisoned".into()))?;

        for _ in 0..self.manifest.max_new_tokens {
            let input_ids = ort::value::Tensor::from_array(([1usize, ids.len()], ids.clone()))
                .map_err(|error| {
                    ImageError::Processing(format!("caption decoder input: {error}"))
                })?;
            // Rebuilt each step because the unmerged export takes no cache;
            // captions are short enough that the recomputation is cheap.
            let states = ort::value::Tensor::from_array((
                [1usize, patches, *hidden],
                encoder_hidden.clone(),
            ))
            .map_err(|error| ImageError::Processing(format!("caption encoder states: {error}")))?;

            let outputs = session
                .run(ort::inputs![
                    "input_ids" => input_ids,
                    "encoder_hidden_states" => states,
                ])
                .map_err(|error| ImageError::Processing(format!("caption decoder: {error}")))?;
            let (shape, logits) =
                outputs["logits"]
                    .try_extract_tensor::<f32>()
                    .map_err(|error| {
                        ImageError::Processing(format!("caption decoder output: {error}"))
                    })?;
            let vocabulary = *shape
                .last()
                .ok_or_else(|| ImageError::Processing("empty decoder output shape".into()))?
                as usize;
            let last = logits
                .len()
                .checked_sub(vocabulary)
                .ok_or_else(|| ImageError::Processing("decoder produced no logits".into()))?;
            let next = argmax(&logits[last..]);
            if next == self.manifest.eos_token_id {
                break;
            }
            ids.push(next);
        }

        let generated: Vec<u32> = ids.iter().skip(1).map(|&id| id as u32).collect();
        let text = self
            .tokenizer
            .decode(&generated, true)
            .map_err(|error| ImageError::Processing(format!("caption decode: {error}")))?;
        Ok(text.trim().to_owned())
    }
}

fn argmax(logits: &[f32]) -> i64 {
    let mut best = 0usize;
    for (index, value) in logits.iter().enumerate() {
        if value > &logits[best] {
            best = index;
        }
    }
    best as i64
}

/// Resize to the model's square input and normalize to `[-1, 1]` in CHW order.
fn preprocess(pixels: &RgbImage, size: u32) -> Vec<f32> {
    let resized = image::imageops::resize(
        pixels,
        size,
        size,
        // Upstream `preprocessor_config.json` specifies resample=2 (bilinear).
        image::imageops::FilterType::Triangle,
    );
    let pixel_count = (size * size) as usize;
    let mut tensor = vec![0f32; 3 * pixel_count];
    for (index, pixel) in resized.pixels().enumerate() {
        for channel in 0..3 {
            let scaled = f32::from(pixel.0[channel]) / 255.0;
            tensor[channel * pixel_count + index] = (scaled - IMAGE_MEAN) / IMAGE_STD;
        }
    }
    tensor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_matches_the_fixed_runtime_contract() {
        let manifest = trusted_manifest().expect("manifest");
        assert_eq!(manifest.model_version, MODEL_VERSION);
        assert_eq!(manifest.files.len(), 3);
        assert_eq!(manifest.image_size, 224);
        assert_eq!(manifest.hidden_size, 768);
        // Start and end share GPT-2's endoftext id; decoding relies on it.
        assert_eq!(manifest.decoder_start_token_id, 50256);
        assert_eq!(manifest.eos_token_id, 50256);
        assert!(manifest
            .files
            .iter()
            .all(|file| file.sha256.len() == 64 && file.size > 0));
    }

    #[test]
    fn preprocessing_normalizes_to_the_expected_range_and_layout() {
        let white = RgbImage::from_pixel(8, 8, image::Rgb([255, 255, 255]));
        let tensor = preprocess(&white, 224);
        assert_eq!(tensor.len(), 3 * 224 * 224);
        assert!(tensor.iter().all(|value| (*value - 1.0).abs() < 1e-6));

        let black = RgbImage::from_pixel(8, 8, image::Rgb([0, 0, 0]));
        let tensor = preprocess(&black, 224);
        assert!(tensor.iter().all(|value| (*value + 1.0).abs() < 1e-6));
    }

    #[test]
    fn preprocessing_keeps_channels_separated_in_chw_order() {
        let red = RgbImage::from_pixel(4, 4, image::Rgb([255, 0, 0]));
        let tensor = preprocess(&red, 224);
        let plane = 224 * 224;
        assert!((tensor[0] - 1.0).abs() < 1e-6, "red plane");
        assert!((tensor[plane] + 1.0).abs() < 1e-6, "green plane");
        assert!((tensor[2 * plane] + 1.0).abs() < 1e-6, "blue plane");
    }

    #[test]
    fn argmax_picks_the_highest_scoring_token() {
        assert_eq!(argmax(&[0.1, 0.9, 0.3]), 1);
        assert_eq!(argmax(&[-5.0, -2.0, -9.0]), 1);
        assert_eq!(argmax(&[3.0]), 0);
    }

    #[test]
    fn a_missing_model_directory_names_the_recovery_command() {
        let Err(error) = OnnxCaptioner::load(Path::new("/nonexistent/caption-model")) else {
            panic!("loading a missing model directory must fail");
        };
        assert!(error.to_string().contains("tessera model fetch"));
    }

    /// Gated on model presence, matching the embedder's real-model test.
    /// Run `tessera model fetch` or set TESSERA_MODEL_DIR to enable locally.
    #[test]
    fn captions_a_real_photo_when_the_model_is_present() {
        let dir = default_model_dir();
        if !model_present(&dir) {
            eprintln!("SKIP: caption model not present at {}", dir.display());
            return;
        }
        let captioner = OnnxCaptioner::load(&dir).expect("load");
        assert_eq!(captioner.identity().model_version, MODEL_VERSION);

        let photo = image::load_from_memory_with_format(
            include_bytes!("../../../../tests/fixtures/image-96x96.png"),
            image::ImageFormat::Png,
        )
        .expect("fixture")
        .to_rgb8();
        let caption = captioner.caption(&photo).expect("caption");
        assert!(!caption.is_empty(), "caption must describe something");

        // Greedy decoding must be reproducible: the same pixels always
        // produce the same caption, or derivations stop being idempotent.
        assert_eq!(caption, captioner.caption(&photo).expect("caption again"));
    }
}
