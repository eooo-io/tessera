//! Decode encrypted image bytes to RGB8 pixels, in memory.
//!
//! PNG and JPEG decode portably through the `image` crate. HEIC has no
//! portable Rust decoder, so on macOS it is routed through ImageIO, which
//! re-encodes to PNG in memory and rejoins the portable path. Nothing is ever
//! written to a temporary file: decrypted originals stay in process memory.
//!
//! Re-encoding through ImageIO also drops EXIF — including GPS — because
//! `CGImageDestination` copies no metadata unless it is asked to.

use image::RgbImage;

use super::ImageError;

/// Upper bound on either edge of a decoded source image. Images larger than
/// this are downscaled during decode so a hostile or merely enormous file
/// cannot force an unbounded allocation.
pub const MAX_SOURCE_EDGE: u32 = 4096;

pub const PNG: &str = "image/png";
pub const JPEG: &str = "image/jpeg";
pub const HEIC: &str = "image/heic";

/// Media types the image pipeline can derive from.
pub fn is_supported(media_type: &str) -> bool {
    matches!(media_type, PNG | JPEG | HEIC)
}

/// Decode to RGB8, downscaling anything beyond [`MAX_SOURCE_EDGE`].
pub fn decode_rgb8(bytes: &[u8], media_type: &str) -> Result<RgbImage, ImageError> {
    let decoded = match media_type {
        PNG | JPEG => decode_portable(bytes, media_type)?,
        HEIC => decode_heic(bytes)?,
        other => return Err(ImageError::UnsupportedMediaType(other.to_owned())),
    };
    Ok(bound(decoded))
}

fn decode_portable(bytes: &[u8], media_type: &str) -> Result<RgbImage, ImageError> {
    let format = match media_type {
        PNG => image::ImageFormat::Png,
        JPEG => image::ImageFormat::Jpeg,
        other => return Err(ImageError::UnsupportedMediaType(other.to_owned())),
    };
    let decoded = image::load_from_memory_with_format(bytes, format)
        .map_err(|error| ImageError::Processing(format!("decode {media_type}: {error}")))?;
    Ok(decoded.to_rgb8())
}

fn bound(decoded: RgbImage) -> RgbImage {
    if decoded.width() <= MAX_SOURCE_EDGE && decoded.height() <= MAX_SOURCE_EDGE {
        return decoded;
    }
    image::imageops::resize(
        &decoded,
        MAX_SOURCE_EDGE.min(decoded.width()),
        MAX_SOURCE_EDGE.min(decoded.height()),
        image::imageops::FilterType::Triangle,
    )
}

#[cfg(not(target_os = "macos"))]
fn decode_heic(_bytes: &[u8]) -> Result<RgbImage, ImageError> {
    Err(ImageError::UnsupportedMediaType(format!(
        "{HEIC} decoding requires macOS ImageIO"
    )))
}

/// Decode HEIC through ImageIO and hand the result back as PNG bytes, which
/// the portable decoder then turns into pixels.
#[cfg(target_os = "macos")]
fn decode_heic(bytes: &[u8]) -> Result<RgbImage, ImageError> {
    let png = heic_to_png(bytes)?;
    decode_portable(&png, PNG)
}

#[cfg(target_os = "macos")]
fn heic_to_png(bytes: &[u8]) -> Result<Vec<u8>, ImageError> {
    use objc2_core_foundation::{
        kCFBooleanTrue, CFData, CFDictionary, CFMutableData, CFNumber, CFRetained, CFString,
    };
    use objc2_image_io::{
        kCGImageSourceCreateThumbnailFromImageAlways, kCGImageSourceCreateThumbnailWithTransform,
        kCGImageSourceThumbnailMaxPixelSize, CGImageDestination, CGImageSource,
    };

    let source_data = CFData::from_bytes(bytes);
    // SAFETY: `source_data` is a valid CFData for the lifetime of the call and
    // no options dictionary is passed, so there are no generics to mistype.
    let source = unsafe { CGImageSource::with_data(&source_data, None) }.ok_or_else(|| {
        ImageError::Processing("ImageIO could not read the HEIC container".into())
    })?;

    let max_pixel_size = CFNumber::new_i32(MAX_SOURCE_EDGE as i32);
    // SAFETY: reading CoreFoundation's immortal shared boolean constant.
    let truth = unsafe { kCFBooleanTrue }.ok_or_else(|| {
        ImageError::Processing("CoreFoundation kCFBooleanTrue was unavailable".into())
    })?;
    // Keys are ImageIO's own CFString constants and the values match their
    // documented types (CFNumber for the pixel bound, CFBoolean for the flags).
    let options: CFRetained<CFDictionary<CFString, _>> = unsafe {
        CFDictionary::from_slices(
            &[
                kCGImageSourceCreateThumbnailFromImageAlways,
                kCGImageSourceThumbnailMaxPixelSize,
                kCGImageSourceCreateThumbnailWithTransform,
            ],
            &[
                truth as &objc2_core_foundation::CFType,
                &max_pixel_size,
                truth,
            ],
        )
    };

    // SAFETY: the options dictionary above uses the documented key/value types.
    let image = unsafe { source.thumbnail_at_index(0, Some(options.as_opaque())) }
        .ok_or_else(|| ImageError::Processing("HEIC contained no decodable image".into()))?;

    let out = CFMutableData::new(None, 0)
        .ok_or_else(|| ImageError::Processing("could not allocate a PNG buffer".into()))?;
    let png_type = CFString::from_static_str("public.png");
    // SAFETY: `out` is a fresh mutable CFData and `png_type` is a valid UTI.
    let destination = unsafe { CGImageDestination::with_data(&out, &png_type, 1, None) }
        .ok_or_else(|| ImageError::Processing("could not create a PNG encoder".into()))?;
    // SAFETY: `image` is a live CGImage; passing no properties copies no
    // metadata, which is exactly the EXIF-dropping behaviour we want.
    unsafe { destination.add_image(&image, None) };
    // SAFETY: the destination has had its single declared image added.
    if !unsafe { destination.finalize() } {
        return Err(ImageError::Processing(
            "ImageIO failed to encode the decoded HEIC as PNG".into(),
        ));
    }
    Ok(out.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_fixture(width: u32, height: u32) -> Vec<u8> {
        let mut buffer = RgbImage::new(width, height);
        for (x, y, pixel) in buffer.enumerate_pixels_mut() {
            *pixel = image::Rgb([(x % 256) as u8, (y % 256) as u8, 128]);
        }
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgb8(buffer)
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .expect("encode fixture");
        bytes
    }

    #[test]
    fn decodes_png_to_exact_pixel_dimensions() {
        let decoded = decode_rgb8(&png_fixture(64, 32), PNG).expect("decode");
        assert_eq!(decoded.dimensions(), (64, 32));
    }

    #[test]
    fn oversized_sources_are_bounded_before_leaving_the_decoder() {
        let decoded = decode_rgb8(&png_fixture(MAX_SOURCE_EDGE + 800, 64), PNG).expect("decode");
        assert!(decoded.width() <= MAX_SOURCE_EDGE);
    }

    #[test]
    fn unsupported_media_types_are_refused_rather_than_guessed() {
        let error = decode_rgb8(b"GIF89a", "image/gif").expect_err("must refuse");
        assert!(matches!(error, ImageError::UnsupportedMediaType(_)));
    }

    #[test]
    fn corrupt_bytes_fail_without_panicking() {
        let error = decode_rgb8(b"not a png at all", PNG).expect_err("must fail");
        assert!(matches!(error, ImageError::Processing(_)));
    }

    /// HEIC is the format iPhone photos actually arrive in, so the macOS
    /// decode path is proven against a real HEIC container rather than
    /// assumed to work because it compiles.
    #[cfg(target_os = "macos")]
    #[test]
    fn heic_decodes_through_image_io_to_the_source_dimensions() {
        let heic = include_bytes!("../../../../tests/fixtures/image-96x96.heic");
        let decoded = decode_rgb8(heic, HEIC).expect("decode heic");
        assert_eq!(decoded.dimensions(), (96, 96));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn heic_is_refused_with_an_explicit_reason_off_macos() {
        let heic = include_bytes!("../../../../tests/fixtures/image-96x96.heic");
        let error = decode_rgb8(heic, HEIC).expect_err("must refuse");
        assert!(matches!(error, ImageError::UnsupportedMediaType(_)));
    }
}
