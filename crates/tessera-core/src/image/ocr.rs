//! Text recognition through the macOS Vision framework.
//!
//! Vision runs entirely on-device, needs no downloaded model, and reads the
//! original container directly — including HEIC — so no intermediate decode is
//! required. Its request revision is recorded in provenance alongside the OS
//! version, because recognition output changes between revisions and a
//! derivation is only reproducible against the revision that produced it.

use super::{ImageError, ToolIdentity};

pub const TOOL: &str = "apple-vision";

/// Vision's identity for provenance: request revision plus OS version.
///
/// Off macOS there is no Vision framework, so this reports the absence
/// explicitly rather than inventing a plausible-looking identity.
pub fn identity() -> Result<ToolIdentity, ImageError> {
    Ok(ToolIdentity {
        name: TOOL.to_owned(),
        version: version()?,
    })
}

#[cfg(not(target_os = "macos"))]
fn version() -> Result<String, ImageError> {
    Err(ImageError::Processing(
        "OCR requires the macOS Vision framework".into(),
    ))
}

#[cfg(not(target_os = "macos"))]
pub fn recognize(_original: &[u8], _media_type: &str) -> Result<String, ImageError> {
    Err(ImageError::Processing(
        "OCR requires the macOS Vision framework".into(),
    ))
}

/// The revision a freshly-created request will run at, paired with the OS
/// build. Read from an instance rather than the class so it reflects the
/// revision that recognition actually uses.
#[cfg(target_os = "macos")]
fn version() -> Result<String, ImageError> {
    use objc2_foundation::NSProcessInfo;
    use objc2_vision::VNRecognizeTextRequest;

    let request = VNRecognizeTextRequest::new();
    // SAFETY: `revision` is a plain property read on a live request.
    let revision = unsafe { request.revision() };
    let os = NSProcessInfo::processInfo().operatingSystemVersion();
    Ok(format!(
        "revision-{revision};macos-{}.{}.{}",
        os.majorVersion, os.minorVersion, os.patchVersion
    ))
}

/// Recognize text in the original image bytes, in reading order.
///
/// Returns an empty string when the image genuinely contains no text — that is
/// a valid result for a photo, not a failure.
#[cfg(target_os = "macos")]
pub fn recognize(original: &[u8], _media_type: &str) -> Result<String, ImageError> {
    use objc2::AllocAnyThread;
    use objc2_foundation::{NSArray, NSData, NSDictionary};
    use objc2_vision::{
        VNImageRequestHandler, VNRecognizeTextRequest, VNRequest, VNRequestTextRecognitionLevel,
    };

    let data = NSData::with_bytes(original);
    let handler = VNImageRequestHandler::initWithData_options(
        VNImageRequestHandler::alloc(),
        &data,
        &NSDictionary::new(),
    );

    let request = VNRecognizeTextRequest::new();
    request.setRecognitionLevel(VNRequestTextRecognitionLevel::Accurate);
    request.setUsesLanguageCorrection(true);

    let requests = NSArray::from_slice(&[&*request as &VNRequest]);
    handler
        .performRequests_error(&requests)
        .map_err(|error| ImageError::Processing(format!("Vision text recognition: {error}")))?;

    let Some(observations) = request.results() else {
        return Ok(String::new());
    };

    let mut lines = Vec::new();
    for index in 0..observations.count() {
        let observation = observations.objectAtIndex(index);
        // One candidate is enough: we index recognized text, and lower-ranked
        // alternates would add noise to the searchable surface.
        let candidates = observation.topCandidates(1);
        if candidates.count() == 0 {
            continue;
        }
        let text = candidates.objectAtIndex(0).string().to_string();
        if !text.trim().is_empty() {
            lines.push(text);
        }
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    fn rendered_text_png(text: &str) -> Vec<u8> {
        // Render with the same ImageIO stack the vault already links, so the
        // test needs no extra dependency to produce a legible raster.
        let width = 900u32;
        let height = 220u32;
        let mut canvas = image::RgbImage::from_pixel(width, height, image::Rgb([255, 255, 255]));
        crate::image::ocr::tests::draw_text(&mut canvas, text);
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgb8(canvas)
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .expect("encode");
        bytes
    }

    /// A deliberately blocky 5x7 bitmap font. Vision reads it reliably at
    /// scale, and it keeps the test self-contained — no font files, no
    /// system text rendering that could differ between machines.
    #[cfg(target_os = "macos")]
    pub(super) fn draw_text(canvas: &mut image::RgbImage, text: &str) {
        const GLYPHS: &[(char, [u8; 7])] = &[
            ('A', [0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11]),
            ('B', [0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E]),
            ('C', [0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E]),
            ('D', [0x1E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1E]),
            ('E', [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F]),
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
        let mut cursor_x = 20u32;
        for symbol in text.chars() {
            let glyph = GLYPHS
                .iter()
                .find(|(c, _)| *c == symbol)
                .map(|(_, rows)| *rows)
                .unwrap_or([0; 7]);
            for (row_index, row) in glyph.iter().enumerate() {
                for bit in 0..5u32 {
                    if row & (1 << (4 - bit)) != 0 {
                        for dy in 0..scale {
                            for dx in 0..scale {
                                let x = cursor_x + bit * scale + dx;
                                let y = 40 + row_index as u32 * scale + dy;
                                if x < canvas.width() && y < canvas.height() {
                                    canvas.put_pixel(x, y, image::Rgb([0, 0, 0]));
                                }
                            }
                        }
                    }
                }
            }
            cursor_x += 6 * scale;
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reads_rendered_text_from_a_screenshot_like_image() {
        let png = rendered_text_png("TESSERA");
        let text = recognize(&png, "image/png").expect("ocr");
        assert!(
            text.to_uppercase().contains("TESSERA"),
            "Vision returned {text:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_blank_image_yields_no_text_rather_than_an_error() {
        let blank = image::RgbImage::from_pixel(200, 200, image::Rgb([255, 255, 255]));
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgb8(blank)
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .expect("encode");
        assert_eq!(recognize(&bytes, "image/png").expect("ocr").trim(), "");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn identity_records_the_revision_that_produced_the_text() {
        let identity = identity().expect("identity");
        assert_eq!(identity.name, TOOL);
        assert!(identity.version.starts_with("revision-"));
        assert!(identity.version.contains("macos-"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn ocr_is_explicitly_unavailable_off_macos() {
        assert!(recognize(b"", "image/png").is_err());
        assert!(identity().is_err());
    }
}
