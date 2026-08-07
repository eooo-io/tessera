//! Bounded, metadata-free thumbnails.
//!
//! Thumbnails are derived from decoded pixels and re-encoded as PNG, so no
//! byte of the source container — EXIF, GPS, maker notes, colour profiles —
//! survives into the derived blob. Aspect ratio is preserved.

use image::RgbImage;

use super::{ImageError, ToolIdentity};

pub const TOOL: &str = "tessera-thumbnail";
pub const TOOL_VERSION: &str = "png-max512-1";

/// Longest edge of a generated thumbnail.
pub const MAX_EDGE: u32 = 512;

pub fn identity() -> ToolIdentity {
    ToolIdentity {
        name: TOOL.to_owned(),
        version: TOOL_VERSION.to_owned(),
    }
}

/// Scale to fit within [`MAX_EDGE`] on the longest edge and encode as PNG.
///
/// Images already inside the bound are re-encoded rather than passed through,
/// because re-encoding is what strips the source metadata.
pub fn encode(pixels: &RgbImage) -> Result<(Vec<u8>, String), ImageError> {
    let (width, height) = pixels.dimensions();
    if width == 0 || height == 0 {
        return Err(ImageError::Processing(
            "image has a zero-length edge".into(),
        ));
    }
    let (target_width, target_height) = fit(width, height);
    let scaled = image::imageops::resize(
        pixels,
        target_width,
        target_height,
        image::imageops::FilterType::Lanczos3,
    );
    let mut bytes = Vec::new();
    image::DynamicImage::ImageRgb8(scaled)
        .write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Png,
        )
        .map_err(|error| ImageError::Processing(format!("thumbnail encode: {error}")))?;
    Ok((bytes, super::decode::PNG.to_owned()))
}

/// Largest size within the bound that preserves aspect ratio. Never upscales.
fn fit(width: u32, height: u32) -> (u32, u32) {
    let longest = width.max(height);
    if longest <= MAX_EDGE {
        return (width, height);
    }
    let scale = f64::from(MAX_EDGE) / f64::from(longest);
    (
        ((f64::from(width) * scale).round() as u32).max(1),
        ((f64::from(height) * scale).round() as u32).max(1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixels(width: u32, height: u32) -> RgbImage {
        RgbImage::from_fn(width, height, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, 200])
        })
    }

    fn decoded_dimensions(bytes: &[u8]) -> (u32, u32) {
        image::load_from_memory_with_format(bytes, image::ImageFormat::Png)
            .expect("thumbnail decodes")
            .to_rgb8()
            .dimensions()
    }

    #[test]
    fn wide_images_are_bounded_on_the_long_edge_keeping_aspect_ratio() {
        let (bytes, media_type) = encode(&pixels(2048, 512)).expect("encode");
        assert_eq!(media_type, "image/png");
        assert_eq!(decoded_dimensions(&bytes), (MAX_EDGE, MAX_EDGE / 4));
    }

    #[test]
    fn tall_images_are_bounded_on_the_long_edge_keeping_aspect_ratio() {
        let (bytes, _) = encode(&pixels(256, 1024)).expect("encode");
        assert_eq!(decoded_dimensions(&bytes), (MAX_EDGE / 4, MAX_EDGE));
    }

    #[test]
    fn small_images_are_never_upscaled() {
        let (bytes, _) = encode(&pixels(40, 30)).expect("encode");
        assert_eq!(decoded_dimensions(&bytes), (40, 30));
    }

    #[test]
    fn source_container_metadata_does_not_survive_re_encoding() {
        // A JPEG carrying EXIF GPS must not yield a thumbnail containing it.
        let source = pixels(64, 64);
        let mut jpeg = Vec::new();
        image::DynamicImage::ImageRgb8(source)
            .write_to(
                &mut std::io::Cursor::new(&mut jpeg),
                image::ImageFormat::Jpeg,
            )
            .expect("encode jpeg");
        let decoded = super::super::decode::decode_rgb8(&jpeg, "image/jpeg").expect("decode");
        let (bytes, _) = encode(&decoded).expect("encode");
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(!bytes.windows(4).any(|w| w == b"Exif"));
    }

    #[test]
    fn zero_sized_images_are_refused() {
        let error = encode(&RgbImage::new(0, 10)).expect_err("must refuse");
        assert!(matches!(error, ImageError::Processing(_)));
    }
}
