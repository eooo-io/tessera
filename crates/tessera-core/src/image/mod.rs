//! Encrypted image understanding: thumbnail, OCR, and caption derivations.

pub mod caption;
pub mod decode;
pub mod local;
pub mod ocr;
pub mod thumbnail;

pub use local::LocalImageProvider;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::artifact::{ArtifactError, ArtifactId};
use crate::blob::{BlobError, BlobHash};
use crate::extract::DerivedText;
use crate::vault::{Vault, VaultError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingLocality {
    Local,
    Cloud,
}

impl ProcessingLocality {
    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Cloud => "cloud",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolIdentity {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptionIdentity {
    pub tool: String,
    pub model: String,
    pub model_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageProviderIdentity {
    pub thumbnail: ToolIdentity,
    pub ocr: ToolIdentity,
    pub caption: CaptionIdentity,
    pub locality: ProcessingLocality,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageUnderstandingOutput {
    pub thumbnail: Vec<u8>,
    pub thumbnail_media_type: String,
    pub ocr_text: String,
    pub caption: String,
}

pub trait ImageUnderstandingProvider {
    fn identity(&self) -> ImageProviderIdentity;
    fn understand(
        &self,
        original: &[u8],
        media_type: &str,
    ) -> Result<ImageUnderstandingOutput, ImageError>;
}

#[derive(Debug, Clone, Default)]
pub struct ImageUnderstandingOptions {
    /// Cloud processing is forbidden unless this is true for this exact item.
    pub allow_cloud: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageDerivation {
    pub id: String,
    pub artifact_version_id: String,
    pub searchable_derived_text_id: String,
    pub thumbnail_blob_hash: String,
    pub thumbnail_media_type: String,
    pub ocr_blob_hash: String,
    pub caption_blob_hash: String,
    pub thumbnail_tool: String,
    pub thumbnail_tool_version: String,
    pub ocr_tool: String,
    pub ocr_tool_version: String,
    pub caption_tool: String,
    pub caption_model: String,
    pub caption_model_version: String,
    pub locality: ProcessingLocality,
    pub cloud_opt_in: bool,
    pub created_at: String,
}

#[derive(Debug, Error)]
pub enum ImageError {
    #[error("artifact has no versions: {0}")]
    NoVersions(String),
    #[error("unsupported image media type: {0}")]
    UnsupportedMediaType(String),
    #[error("cloud image processing requires explicit per-item opt-in")]
    CloudOptInRequired,
    #[error("image provider contract is invalid: {0}")]
    InvalidProvider(String),
    #[error("image processing failed: {0}")]
    Processing(String),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("artifact error: {0}")]
    Artifact(#[from] ArtifactError),
    #[error("blob error: {0}")]
    Blob(#[from] BlobError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

pub fn understand_image(
    vault: &Vault,
    artifact: &ArtifactId,
    provider: &dyn ImageUnderstandingProvider,
    options: &ImageUnderstandingOptions,
) -> Result<ImageDerivation, ImageError> {
    let artifact_metadata = crate::artifact::get(vault, artifact)?;
    if !matches!(
        artifact_metadata.media_type.as_str(),
        "image/png" | "image/jpeg" | "image/heic"
    ) {
        return Err(ImageError::UnsupportedMediaType(
            artifact_metadata.media_type,
        ));
    }
    let identity = provider.identity();
    validate_identity(&identity)?;
    if identity.locality == ProcessingLocality::Cloud && !options.allow_cloud {
        return Err(ImageError::CloudOptInRequired);
    }
    let (version_id, original_hash): (String, String) = vault
        .conn()
        .query_row(
            "SELECT id, blob_hash FROM artifact_versions
             WHERE artifact_id = ?1 ORDER BY version DESC LIMIT 1",
            [artifact.0.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => ImageError::NoVersions(artifact.0.clone()),
            other => ImageError::Database(other),
        })?;
    if let Some(existing) = find_existing(vault, &version_id, &identity)? {
        return Ok(existing);
    }

    let original = vault.blobs().get(vault.dek()?, &BlobHash(original_hash))?;
    let output = provider.understand(&original, &artifact_metadata.media_type)?;
    if output.thumbnail.is_empty()
        || !matches!(
            output.thumbnail_media_type.as_str(),
            "image/png" | "image/jpeg"
        )
        || (output.ocr_text.trim().is_empty() && output.caption.trim().is_empty())
    {
        return Err(ImageError::InvalidProvider(
            "thumbnail and at least one searchable OCR/caption value are required".into(),
        ));
    }

    let dek = vault.dek()?;
    let thumbnail_hash = vault.blobs().put(dek, &output.thumbnail)?;
    let ocr_hash = vault.blobs().put(dek, output.ocr_text.as_bytes())?;
    let caption_hash = vault.blobs().put(dek, output.caption.as_bytes())?;
    let searchable = format!(
        "[image caption]\n{}\n\n[image OCR]\n{}\n",
        output.caption.trim(),
        output.ocr_text.trim()
    );
    let searchable_hash = vault.blobs().put(dek, searchable.as_bytes())?;
    let derived_id = format!("dtx_{}", ulid::Ulid::new());
    let image_id = format!("imgd_{}", ulid::Ulid::new());
    let now = chrono::Utc::now().to_rfc3339();
    let extractor_version = format!(
        "ocr:{};caption:{}:{};thumbnail:{}",
        identity.ocr.version,
        identity.caption.model,
        identity.caption.model_version,
        identity.thumbnail.version
    );

    vault.conn().execute_batch("BEGIN IMMEDIATE")?;
    let persisted = (|| -> Result<(), ImageError> {
        vault.conn().execute(
            "INSERT INTO derived_text
             (id, artifact_version_id, blob_hash, extractor, extractor_version, created_at)
             VALUES (?1, ?2, ?3, 'image-understanding', ?4, ?5)",
            rusqlite::params![
                derived_id,
                version_id,
                searchable_hash.0,
                extractor_version,
                now
            ],
        )?;
        vault.conn().execute(
            "INSERT INTO image_derivations
             (id, artifact_version_id, searchable_derived_text_id,
              thumbnail_blob_hash, thumbnail_media_type, ocr_blob_hash, caption_blob_hash,
              thumbnail_tool, thumbnail_tool_version, ocr_tool, ocr_tool_version,
              caption_tool, caption_model, caption_model_version, locality, cloud_opt_in, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            rusqlite::params![
                image_id,
                version_id,
                derived_id,
                thumbnail_hash.0,
                output.thumbnail_media_type,
                ocr_hash.0,
                caption_hash.0,
                identity.thumbnail.name,
                identity.thumbnail.version,
                identity.ocr.name,
                identity.ocr.version,
                identity.caption.tool,
                identity.caption.model,
                identity.caption.model_version,
                identity.locality.as_str(),
                options.allow_cloud,
                now,
            ],
        )?;
        for (hash, tool, version) in [
            (
                &thumbnail_hash.0,
                &identity.thumbnail.name,
                &identity.thumbnail.version,
            ),
            (&ocr_hash.0, &identity.ocr.name, &identity.ocr.version),
            (
                &caption_hash.0,
                &identity.caption.tool,
                &identity.caption.model_version,
            ),
            (
                &searchable_hash.0,
                &"image-understanding".to_owned(),
                &extractor_version,
            ),
        ] {
            vault.conn().execute(
                "INSERT INTO provenance
                 (id, derived_blob_hash, source_artifact_version_id, tool, tool_version, locality, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    format!("prov_{}", ulid::Ulid::new()),
                    hash,
                    version_id,
                    tool,
                    version,
                    identity.locality.as_str(),
                    now,
                ],
            )?;
        }
        Ok(())
    })();
    match persisted {
        Ok(()) => vault.conn().execute_batch("COMMIT")?,
        Err(error) => {
            let _ = vault.conn().execute_batch("ROLLBACK");
            return Err(error);
        }
    }
    get(vault, &image_id)
}

/// Derive an image and chunk the result so it becomes retrievable.
///
/// The caption and OCR text form one searchable derived text; chunking it is
/// what puts an image in front of semantic search at all. Without this step a
/// derivation exists but the image stays invisible to every query.
pub fn understand_and_chunk(
    vault: &Vault,
    artifact: &ArtifactId,
    provider: &dyn ImageUnderstandingProvider,
    options: &ImageUnderstandingOptions,
) -> Result<ImageDerivation, ImageError> {
    let derivation = understand_image(vault, artifact, provider, options)?;
    let derived = crate::extract::DerivedText {
        id: derivation.searchable_derived_text_id.clone(),
        artifact_version_id: derivation.artifact_version_id.clone(),
        blob_hash: searchable_blob_hash(vault, &derivation)?,
        extractor: "image-understanding".to_owned(),
        extractor_version: extractor_version_of(vault, &derivation)?,
    };
    crate::chunk::chunk_derived_text(vault, &derived, &crate::chunk::ChunkParams::default())
        .map_err(|error| ImageError::Processing(format!("chunking image text: {error}")))?;
    Ok(derivation)
}

fn searchable_blob_hash(vault: &Vault, image: &ImageDerivation) -> Result<String, ImageError> {
    Ok(vault.conn().query_row(
        "SELECT blob_hash FROM derived_text WHERE id = ?1",
        [&image.searchable_derived_text_id],
        |row| row.get(0),
    )?)
}

fn extractor_version_of(vault: &Vault, image: &ImageDerivation) -> Result<String, ImageError> {
    Ok(vault.conn().query_row(
        "SELECT extractor_version FROM derived_text WHERE id = ?1",
        [&image.searchable_derived_text_id],
        |row| row.get(0),
    )?)
}

fn validate_identity(identity: &ImageProviderIdentity) -> Result<(), ImageError> {
    if [
        identity.thumbnail.name.as_str(),
        identity.thumbnail.version.as_str(),
        identity.ocr.name.as_str(),
        identity.ocr.version.as_str(),
        identity.caption.tool.as_str(),
        identity.caption.model.as_str(),
        identity.caption.model_version.as_str(),
    ]
    .iter()
    .any(|value| value.trim().is_empty())
    {
        return Err(ImageError::InvalidProvider(
            "tool, model, and version fields must be non-empty".into(),
        ));
    }
    Ok(())
}

fn find_existing(
    vault: &Vault,
    version_id: &str,
    identity: &ImageProviderIdentity,
) -> Result<Option<ImageDerivation>, ImageError> {
    let id = vault
        .conn()
        .query_row(
            "SELECT id FROM image_derivations
             WHERE artifact_version_id = ?1
               AND thumbnail_tool = ?2 AND thumbnail_tool_version = ?3
               AND ocr_tool = ?4 AND ocr_tool_version = ?5
               AND caption_tool = ?6 AND caption_model = ?7 AND caption_model_version = ?8
               AND locality = ?9",
            rusqlite::params![
                version_id,
                identity.thumbnail.name,
                identity.thumbnail.version,
                identity.ocr.name,
                identity.ocr.version,
                identity.caption.tool,
                identity.caption.model,
                identity.caption.model_version,
                identity.locality.as_str(),
            ],
            |row| row.get::<_, String>(0),
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(ImageError::Database(other)),
        })?;
    id.map(|id| get(vault, &id)).transpose()
}

pub fn get(vault: &Vault, id: &str) -> Result<ImageDerivation, ImageError> {
    vault
        .conn()
        .query_row(
            "SELECT id, artifact_version_id, searchable_derived_text_id,
                    thumbnail_blob_hash, thumbnail_media_type, ocr_blob_hash, caption_blob_hash,
                    thumbnail_tool, thumbnail_tool_version, ocr_tool, ocr_tool_version,
                    caption_tool, caption_model, caption_model_version,
                    locality, cloud_opt_in, created_at
             FROM image_derivations WHERE id = ?1",
            [id],
            |row| {
                Ok(ImageDerivation {
                    id: row.get(0)?,
                    artifact_version_id: row.get(1)?,
                    searchable_derived_text_id: row.get(2)?,
                    thumbnail_blob_hash: row.get(3)?,
                    thumbnail_media_type: row.get(4)?,
                    ocr_blob_hash: row.get(5)?,
                    caption_blob_hash: row.get(6)?,
                    thumbnail_tool: row.get(7)?,
                    thumbnail_tool_version: row.get(8)?,
                    ocr_tool: row.get(9)?,
                    ocr_tool_version: row.get(10)?,
                    caption_tool: row.get(11)?,
                    caption_model: row.get(12)?,
                    caption_model_version: row.get(13)?,
                    locality: match row.get::<_, String>(14)?.as_str() {
                        "cloud" => ProcessingLocality::Cloud,
                        _ => ProcessingLocality::Local,
                    },
                    cloud_opt_in: row.get(15)?,
                    created_at: row.get(16)?,
                })
            },
        )
        .map_err(ImageError::Database)
}

pub fn searchable_text(vault: &Vault, image: &ImageDerivation) -> Result<String, ImageError> {
    let derived = vault.conn().query_row(
        "SELECT artifact_version_id, blob_hash, extractor, extractor_version
         FROM derived_text WHERE id = ?1",
        [&image.searchable_derived_text_id],
        |row| {
            Ok(DerivedText {
                id: image.searchable_derived_text_id.clone(),
                artifact_version_id: row.get(0)?,
                blob_hash: row.get(1)?,
                extractor: row.get(2)?,
                extractor_version: row.get(3)?,
            })
        },
    )?;
    Ok(crate::extract::read_derived_text(vault, &derived)?)
}

impl From<crate::extract::ExtractError> for ImageError {
    fn from(error: crate::extract::ExtractError) -> Self {
        Self::Processing(error.to_string())
    }
}

impl From<crate::model::ModelError> for ImageError {
    fn from(error: crate::model::ModelError) -> Self {
        match error {
            crate::model::ModelError::Missing(message) => Self::Processing(message),
            crate::model::ModelError::Verification(message) => Self::InvalidProvider(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{self, Sensitivity};
    use crate::crypto::KdfParams;
    use crate::{space, Vault};

    struct FixtureProvider {
        locality: ProcessingLocality,
    }

    impl ImageUnderstandingProvider for FixtureProvider {
        fn identity(&self) -> ImageProviderIdentity {
            ImageProviderIdentity {
                thumbnail: ToolIdentity {
                    name: "fixture-thumbnail".into(),
                    version: "1".into(),
                },
                ocr: ToolIdentity {
                    name: "fixture-ocr".into(),
                    version: "1".into(),
                },
                caption: CaptionIdentity {
                    tool: "fixture-vlm".into(),
                    model: "fixture-model".into(),
                    model_version: "sha256:fixture".into(),
                },
                locality: self.locality,
            }
        }

        fn understand(
            &self,
            _original: &[u8],
            _media_type: &str,
        ) -> Result<ImageUnderstandingOutput, ImageError> {
            Ok(ImageUnderstandingOutput {
                thumbnail: b"sanitized-thumbnail".to_vec(),
                thumbnail_media_type: "image/png".into(),
                ocr_text: "BUILD PASSED 285 TESTS".into(),
                caption: "A tabby cat sits beside a green notebook".into(),
            })
        }
    }

    fn fixture() -> (tempfile::TempDir, Vault, ArtifactId) {
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
        let (artifact, _) = artifact::register_encrypted_bytes(
            &vault,
            &space,
            "fixture.png",
            "image/png",
            Sensitivity::Restricted,
            b"sanitized-image-source",
        )
        .expect("source");
        (directory, vault, artifact)
    }

    #[test]
    fn encrypted_outputs_are_searchable_and_idempotent_with_model_provenance() {
        let (_directory, vault, artifact) = fixture();
        let provider = FixtureProvider {
            locality: ProcessingLocality::Local,
        };
        let first = understand_image(
            &vault,
            &artifact,
            &provider,
            &ImageUnderstandingOptions::default(),
        )
        .expect("understand");
        let second = understand_image(
            &vault,
            &artifact,
            &provider,
            &ImageUnderstandingOptions::default(),
        )
        .expect("idempotent");
        assert_eq!(first, second);
        let text = searchable_text(&vault, &first).expect("searchable text");
        assert!(text.contains("BUILD PASSED 285 TESTS"));
        assert!(text.contains("tabby cat sits beside a green notebook"));
        assert_eq!(first.caption_model, "fixture-model");
        assert_eq!(first.caption_model_version, "sha256:fixture");
        assert_eq!(first.locality, ProcessingLocality::Local);
        assert!(!first.cloud_opt_in);
        let chain = crate::provenance::chain_for(&vault, &artifact).expect("provenance");
        assert_eq!(chain.len(), 4);
        assert!(chain.iter().all(|record| record.locality == "local"));
    }

    #[test]
    fn cloud_provider_fails_before_source_decryption_without_item_opt_in() {
        let (_directory, vault, artifact) = fixture();
        let provider = FixtureProvider {
            locality: ProcessingLocality::Cloud,
        };
        let result = understand_image(
            &vault,
            &artifact,
            &provider,
            &ImageUnderstandingOptions::default(),
        );
        assert!(matches!(result, Err(ImageError::CloudOptInRequired)));
        assert!(crate::provenance::chain_for(&vault, &artifact)
            .expect("provenance")
            .is_empty());
    }
}
