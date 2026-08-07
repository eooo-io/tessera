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

    /// The provider needs both the pinned caption model and a working OCR
    /// stage, and OCR is Vision — so it is constructible on macOS only. The
    /// model being downloaded is not on its own enough.
    fn provider_available() -> bool {
        cfg!(target_os = "macos")
            && super::super::caption::model_present(&super::super::caption::default_model_dir())
    }

    /// Gated on the real provider being loadable, like the embedder's
    /// real-model test.
    #[test]
    fn derives_thumbnail_ocr_and_caption_from_one_image() {
        if !provider_available() {
            eprintln!("SKIP: local image provider unavailable on this host");
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
        if !provider_available() {
            eprintln!("SKIP: local image provider unavailable on this host");
            return;
        }
        let provider = LocalImageProvider::load().expect("load provider");
        let error = provider
            .understand(b"GIF89a", "image/gif")
            .expect_err("must refuse");
        assert!(matches!(error, ImageError::UnsupportedMediaType(_)));
    }

    /// Off macOS there is no Vision, so the provider must refuse to load with
    /// a stated reason rather than come up with a silently text-blind OCR
    /// stage. Downloading the caption model does not change that.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn the_provider_refuses_to_load_without_vision() {
        let caption_dir = super::super::caption::default_model_dir();
        if !super::super::caption::model_present(&caption_dir) {
            eprintln!("SKIP: caption model not installed");
            return;
        }
        let error = LocalImageProvider::load().expect_err("must refuse off macOS");
        assert!(
            error.to_string().contains("Vision"),
            "refusal must name the missing capability, got {error}"
        );
    }
}
