//! The local image understanding provider.
//!
//! Composes the three derivation stages — thumbnail, OCR, caption — into the
//! single [`ImageUnderstandingProvider`] the vault calls. Everything runs on
//! this machine: Vision for text, a manifest-pinned ONNX model for captions,
//! and pure-Rust pixel work for the thumbnail. Nothing leaves the process, so
//! the reported locality is always [`ProcessingLocality::Local`].

use std::path::Path;

use super::{
    caption::OnnxCaptioner, decode, ocr, thumbnail, ImageError, ImageProviderIdentity,
    ImageUnderstandingOutput, ImageUnderstandingProvider, ProcessingLocality,
};

pub struct LocalImageProvider {
    captioner: OnnxCaptioner,
    ocr: super::ToolIdentity,
}

impl LocalImageProvider {
    /// Load from the default model directory.
    pub fn load() -> Result<Self, ImageError> {
        Self::load_from(&super::caption::default_model_dir())
    }

    pub fn load_from(caption_model_dir: &Path) -> Result<Self, ImageError> {
        Ok(Self {
            captioner: OnnxCaptioner::load(caption_model_dir)?,
            // Resolved once at load so every derivation this provider makes
            // records the same recognizer revision.
            ocr: ocr::identity()?,
        })
    }
}

impl ImageUnderstandingProvider for LocalImageProvider {
    fn identity(&self) -> ImageProviderIdentity {
        ImageProviderIdentity {
            thumbnail: thumbnail::identity(),
            ocr: self.ocr.clone(),
            caption: self.captioner.identity(),
            locality: ProcessingLocality::Local,
        }
    }

    fn understand(
        &self,
        original: &[u8],
        media_type: &str,
    ) -> Result<ImageUnderstandingOutput, ImageError> {
        let pixels = decode::decode_rgb8(original, media_type)?;
        let (thumbnail_bytes, thumbnail_media_type) = thumbnail::encode(&pixels)?;
        // Vision reads the original container directly, which keeps HEIC and
        // any embedded orientation handling on Apple's side rather than ours.
        let ocr_text = ocr::recognize(original, media_type)?;
        let caption = self.captioner.caption(&pixels)?;
        Ok(ImageUnderstandingOutput {
            thumbnail: thumbnail_bytes,
            thumbnail_media_type,
            ocr_text,
            caption,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model_available() -> bool {
        super::super::caption::model_present(&super::super::caption::default_model_dir())
    }

    /// Gated on model presence, like the embedder's real-model test.
    #[test]
    fn derives_thumbnail_ocr_and_caption_from_one_image() {
        if !model_available() {
            eprintln!("SKIP: caption model not installed");
            return;
        }
        let provider = LocalImageProvider::load().expect("load provider");
        let png = include_bytes!("../../../../tests/fixtures/image-96x96.png");
        let output = provider.understand(png, "image/png").expect("understand");

        assert_eq!(output.thumbnail_media_type, "image/png");
        assert!(output.thumbnail.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(!output.caption.trim().is_empty());

        let identity = provider.identity();
        assert_eq!(identity.locality, ProcessingLocality::Local);
        assert_eq!(identity.thumbnail.name, thumbnail::TOOL);
        assert_eq!(identity.ocr.name, ocr::TOOL);
        assert_eq!(
            identity.caption.model_version,
            super::super::caption::MODEL_VERSION
        );
    }

    #[test]
    fn unsupported_media_types_never_reach_the_model() {
        if !model_available() {
            eprintln!("SKIP: caption model not installed");
            return;
        }
        let provider = LocalImageProvider::load().expect("load provider");
        let error = provider
            .understand(b"GIF89a", "image/gif")
            .expect_err("must refuse");
        assert!(matches!(error, ImageError::UnsupportedMediaType(_)));
    }
}
