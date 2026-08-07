//! Acceptance evidence for issue #27 — image understanding.
//!
//! These tests run the real local stack end to end: Vision for OCR, the
//! manifest-pinned ONNX vision-language model for captions, and the installed
//! embedder for retrieval. A fixture provider could satisfy every assertion
//! here without proving the pipeline works, so they use the shipped one.
//!
//! They are therefore gated on macOS *and* both models being installed —
//! OCR is Vision, so a Linux runner that has downloaded the caption model
//! still cannot exercise this path. Enable locally with `tessera model
//! fetch`, or point `TESSERA_MODEL_DIR` at a root holding both models.

use tessera_core::artifact::{self, Sensitivity};
use tessera_core::crypto::KdfParams;
use tessera_core::embed::onnx::{self, OnnxEmbedder};
use tessera_core::image::{self, caption, LocalImageProvider};
use tessera_core::{space, Vault};

/// Both pinned models must be installed *and* the host must be able to run
/// the OCR stage. OCR is the macOS Vision framework, so having downloaded the
/// caption model is not on its own enough to exercise the real pipeline.
fn pipeline_available() -> bool {
    cfg!(target_os = "macos")
        && caption::model_present(&caption::default_model_dir())
        && onnx::model_present(&onnx::default_model_dir())
}

/// Render text as a high-contrast raster, the way a screenshot presents it.
/// A blocky bitmap font keeps the fixture self-contained and machine-stable.
fn screenshot_of(text: &str) -> Vec<u8> {
    const GLYPHS: &[(char, [u8; 7])] = &[
        ('A', [0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11]),
        ('B', [0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E]),
        ('C', [0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E]),
        ('D', [0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E]),
        ('E', [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F]),
        ('G', [0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F]),
        ('I', [0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E]),
        ('L', [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F]),
        ('N', [0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11]),
        ('O', [0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E]),
        ('P', [0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10]),
        ('R', [0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11]),
        ('S', [0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E]),
        ('T', [0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04]),
        ('V', [0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04]),
        (' ', [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    ];
    let scale = 6u32;
    let mut canvas = ::image::RgbImage::from_pixel(
        40 + text.chars().count() as u32 * 6 * scale,
        160,
        ::image::Rgb([255, 255, 255]),
    );
    let mut cursor_x = 20u32;
    for symbol in text.chars() {
        let glyph = GLYPHS
            .iter()
            .find(|(candidate, _)| *candidate == symbol)
            .map(|(_, rows)| *rows)
            .unwrap_or([0; 7]);
        for (row_index, row) in glyph.iter().enumerate() {
            for bit in 0..5u32 {
                if row & (1 << (4 - bit)) != 0 {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let x = cursor_x + bit * scale + dx;
                            let y = 50 + row_index as u32 * scale + dy;
                            if x < canvas.width() && y < canvas.height() {
                                canvas.put_pixel(x, y, ::image::Rgb([0, 0, 0]));
                            }
                        }
                    }
                }
            }
        }
        cursor_x += 6 * scale;
    }
    let mut bytes = Vec::new();
    ::image::DynamicImage::ImageRgb8(canvas)
        .write_to(
            &mut std::io::Cursor::new(&mut bytes),
            ::image::ImageFormat::Png,
        )
        .expect("encode screenshot");
    bytes
}

struct Fixture {
    _directory: tempfile::TempDir,
    vault: Vault,
    space: tessera_core::SpaceId,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault = Vault::create_with_params(
        &directory.path().join("Images.tessera"),
        "test",
        &KdfParams {
            m_cost_kib: 1024,
            t_cost: 1,
            p_cost: 1,
        },
    )
    .expect("vault");
    let space = space::create(&vault, "Images", None).expect("space");
    Fixture {
        _directory: directory,
        vault,
        space,
    }
}

/// Ingest one image through the real provider and make it retrievable.
fn ingest_image(
    fixture: &Fixture,
    provider: &LocalImageProvider,
    name: &str,
    bytes: &[u8],
) -> (tessera_core::ArtifactId, image::ImageDerivation) {
    let (artifact, _) = artifact::register_encrypted_bytes(
        &fixture.vault,
        &fixture.space,
        name,
        "image/png",
        Sensitivity::Restricted,
        bytes,
    )
    .expect("register");
    let derivation = image::understand_and_chunk(
        &fixture.vault,
        &artifact,
        provider,
        &image::ImageUnderstandingOptions::default(),
    )
    .expect("understand");
    // Retrieval deliberately excludes pending material, so an image only
    // becomes findable once the owner has promoted it out of quarantine.
    artifact::set_state(&fixture.vault, &artifact, artifact::ArtifactState::Live).expect("promote");
    (artifact, derivation)
}

/// Acceptance: "Screenshot with text is findable by its text (OCR path)."
#[test]
fn a_screenshot_is_findable_by_the_text_it_contains() {
    if !pipeline_available() {
        eprintln!("SKIP: local image pipeline unavailable on this host");
        return;
    }
    let fixture = fixture();
    let provider = LocalImageProvider::load().expect("provider");

    let (artifact, derivation) = ingest_image(
        &fixture,
        &provider,
        "release-gate.png",
        &screenshot_of("CONSTELLATION"),
    );

    // The recognized text must reach the searchable surface.
    let searchable = image::searchable_text(&fixture.vault, &derivation).expect("searchable");
    assert!(
        searchable.to_uppercase().contains("CONSTELLATION"),
        "OCR text missing from searchable surface: {searchable:?}"
    );

    let embedder = OnnxEmbedder::load(&onnx::default_model_dir()).expect("embedder");
    tessera_core::search::embed_missing(&fixture.vault, &embedder).expect("embed");

    let results = tessera_core::search::query(
        &fixture.vault,
        &embedder,
        "constellation",
        &tessera_core::search::owner_constraints(),
        5,
    )
    .expect("query");

    assert!(
        results.iter().any(|hit| hit.artifact_id == artifact),
        "screenshot was not retrievable by its own text; got {:?}",
        results
            .iter()
            .map(|hit| &hit.artifact_title)
            .collect::<Vec<_>>()
    );
}

/// Acceptance: "Photo is findable by scene description (caption path)."
///
/// The query is drawn from the caption the model actually produced, so the
/// assertion tests Tessera's plumbing — caption to derived text to chunk to
/// vector to hit — rather than the vision model's descriptive accuracy, which
/// belongs to the retrieval evaluation work (#43/#55).
#[test]
fn an_image_is_findable_by_its_scene_description() {
    if !pipeline_available() {
        eprintln!("SKIP: local image pipeline unavailable on this host");
        return;
    }
    let fixture = fixture();
    let provider = LocalImageProvider::load().expect("provider");

    let photo = include_bytes!("../../../tests/fixtures/image-96x96.png");
    let (artifact, derivation) = ingest_image(&fixture, &provider, "scene.png", photo);

    let searchable = image::searchable_text(&fixture.vault, &derivation).expect("searchable");
    let caption = caption_from(&searchable);
    assert!(!caption.trim().is_empty(), "caption must not be empty");

    let embedder = OnnxEmbedder::load(&onnx::default_model_dir()).expect("embedder");
    tessera_core::search::embed_missing(&fixture.vault, &embedder).expect("embed");

    let results = tessera_core::search::query(
        &fixture.vault,
        &embedder,
        &caption,
        &tessera_core::search::owner_constraints(),
        5,
    )
    .expect("query");

    assert!(
        results.iter().any(|hit| hit.artifact_id == artifact),
        "image was not retrievable by its own scene description {caption:?}"
    );
}

/// Acceptance: "Model choice + version in provenance."
#[test]
fn provenance_records_the_exact_model_and_version_that_ran() {
    if !pipeline_available() {
        eprintln!("SKIP: local image pipeline unavailable on this host");
        return;
    }
    let fixture = fixture();
    let provider = LocalImageProvider::load().expect("provider");
    let (artifact, derivation) =
        ingest_image(&fixture, &provider, "scene.png", &screenshot_of("TESSERA"));

    assert_eq!(derivation.caption_model, caption::MODEL_NAME);
    assert_eq!(derivation.caption_model_version, caption::MODEL_VERSION);
    assert_eq!(derivation.ocr_tool, image::ocr::TOOL);
    assert!(
        derivation.ocr_tool_version.starts_with("revision-"),
        "OCR provenance must name the recognizer revision, got {:?}",
        derivation.ocr_tool_version
    );
    assert_eq!(derivation.locality, image::ProcessingLocality::Local);
    assert!(!derivation.cloud_opt_in);

    // Every derived blob is attributed, and nothing claims cloud processing.
    let chain = tessera_core::provenance::chain_for(&fixture.vault, &artifact).expect("chain");
    assert_eq!(chain.len(), 4, "thumbnail, OCR, caption, searchable text");
    assert!(chain.iter().all(|record| record.locality == "local"));
    assert!(
        chain.iter().any(|record| {
            record.tool == caption::MODEL_NAME
                || record
                    .tool_version
                    .as_deref()
                    .is_some_and(|version| version.contains(caption::MODEL_VERSION))
        }),
        "no provenance record names the caption model: {chain:?}"
    );
}

/// A cloud-capable provider must fail before the original is decrypted unless
/// the owner opted this exact item in.
#[test]
fn cloud_processing_stays_refused_without_per_item_opt_in() {
    let fixture = fixture();
    let (artifact, _) = artifact::register_encrypted_bytes(
        &fixture.vault,
        &fixture.space,
        "scene.png",
        "image/png",
        Sensitivity::Restricted,
        &screenshot_of("TESSERA"),
    )
    .expect("register");

    struct CloudProvider;
    impl image::ImageUnderstandingProvider for CloudProvider {
        fn identity(&self) -> image::ImageProviderIdentity {
            image::ImageProviderIdentity {
                thumbnail: image::thumbnail::identity(),
                ocr: image::ToolIdentity {
                    name: "remote-ocr".into(),
                    version: "1".into(),
                },
                caption: image::CaptionIdentity {
                    tool: "remote".into(),
                    model: "remote-vlm".into(),
                    model_version: "1".into(),
                },
                locality: image::ProcessingLocality::Cloud,
            }
        }
        fn understand(
            &self,
            _original: &[u8],
            _media_type: &str,
        ) -> Result<image::ImageUnderstandingOutput, image::ImageError> {
            panic!("cloud provider must never receive decrypted bytes without opt-in");
        }
    }

    let error = image::understand_and_chunk(
        &fixture.vault,
        &artifact,
        &CloudProvider,
        &image::ImageUnderstandingOptions::default(),
    )
    .expect_err("must refuse");
    assert!(matches!(error, image::ImageError::CloudOptInRequired));
    assert!(
        tessera_core::provenance::chain_for(&fixture.vault, &artifact)
            .expect("chain")
            .is_empty(),
        "a refused derivation must leave no provenance behind"
    );
}

/// Pull the caption back out of the combined searchable surface, which is
/// laid out as "[image caption]\n<caption>\n\n[image OCR]\n<text>".
fn caption_from(searchable: &str) -> String {
    searchable
        .split("[image OCR]")
        .next()
        .unwrap_or("")
        .replace("[image caption]", "")
        .trim()
        .to_owned()
}
