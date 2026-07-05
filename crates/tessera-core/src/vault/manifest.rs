//! The `tessera.json` manifest — the vault bundle's portability contract.
//!
//! Carries everything a fresh guardian on a new machine needs to interpret
//! the bundle: format version, crypto parameters, and the registry of
//! embedding models used. See `spec/vault-format.md`.

use std::path::Path;
use thiserror::Error;

use serde::{Deserialize, Serialize};

/// The bundle format version this build of tessera-core writes and the
/// highest version it can read.
pub const FORMAT_VERSION: u32 = 1;

#[derive(Error, Debug)]
pub enum ManifestError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest parse error: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("unsupported vault format version {found} (this build supports up to {supported})")]
    UnsupportedVersion { found: u32, supported: u32 },
}

/// Key-derivation and cipher parameters for the vault.
///
/// Defaults follow the v3 plan: Argon2id (64 MiB, 3 iterations,
/// parallelism 4) and XChaCha20-Poly1305 for blobs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CryptoParams {
    pub kdf: String,
    pub kdf_m_cost_kib: u32,
    pub kdf_t_cost: u32,
    pub kdf_p_cost: u32,
    pub cipher: String,
    /// Unknown fields from newer minor revisions, preserved on round-trip.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// An embedding model that has produced vectors stored in this vault.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbeddingModelEntry {
    pub name: String,
    pub version: String,
    pub dimensions: u32,
}

/// The parsed `tessera.json` manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultManifest {
    pub format_version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub crypto: CryptoParams,
    #[serde(default)]
    pub embedding_models: Vec<EmbeddingModelEntry>,
    /// Unknown top-level fields from newer minor revisions, preserved on
    /// round-trip so an older guardian never destroys newer metadata.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl VaultManifest {
    /// Create a manifest with current-format defaults.
    pub fn new(created_at: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            created_at,
            crypto: CryptoParams {
                kdf: "argon2id".to_owned(),
                kdf_m_cost_kib: 65536,
                kdf_t_cost: 3,
                kdf_p_cost: 4,
                cipher: "xchacha20poly1305".to_owned(),
                extra: serde_json::Map::new(),
            },
            embedding_models: Vec::new(),
            extra: serde_json::Map::new(),
        }
    }

    /// Load and validate a manifest from a `tessera.json` file.
    ///
    /// Fails with [`ManifestError::UnsupportedVersion`] when the file was
    /// written by a newer, incompatible format.
    pub fn load(path: &Path) -> Result<Self, ManifestError> {
        let raw = std::fs::read_to_string(path)?;
        let manifest: Self = serde_json::from_str(&raw)?;
        if manifest.format_version > FORMAT_VERSION {
            return Err(ManifestError::UnsupportedVersion {
                found: manifest.format_version,
                supported: FORMAT_VERSION,
            });
        }
        Ok(manifest)
    }

    /// Serialize the manifest to a `tessera.json` file (pretty-printed,
    /// trailing newline).
    pub fn save(&self, path: &Path) -> Result<(), ManifestError> {
        let mut json = serde_json::to_string_pretty(self)?;
        json.push('\n');
        std::fs::write(path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        "2026-07-05T12:00:00Z".parse().expect("valid timestamp")
    }

    #[test]
    fn new_manifest_has_current_version_and_spec_crypto_defaults() {
        let m = VaultManifest::new(fixed_now());
        assert_eq!(m.format_version, FORMAT_VERSION);
        assert_eq!(m.crypto.kdf, "argon2id");
        assert_eq!(m.crypto.kdf_m_cost_kib, 65536);
        assert_eq!(m.crypto.kdf_t_cost, 3);
        assert_eq!(m.crypto.kdf_p_cost, 4);
        assert_eq!(m.crypto.cipher, "xchacha20poly1305");
        assert!(m.embedding_models.is_empty());
    }

    #[test]
    fn save_load_round_trip_preserves_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tessera.json");

        let mut m = VaultManifest::new(fixed_now());
        m.embedding_models.push(EmbeddingModelEntry {
            name: "all-MiniLM-L6-v2".into(),
            version: "onnx-1".into(),
            dimensions: 384,
        });
        m.save(&path).expect("save");

        let loaded = VaultManifest::load(&path).expect("load");
        assert_eq!(loaded, m);
    }

    #[test]
    fn load_rejects_newer_format_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tessera.json");

        let mut m = VaultManifest::new(fixed_now());
        m.format_version = FORMAT_VERSION + 1;
        // Bypass save() validation concerns: write raw JSON.
        std::fs::write(&path, serde_json::to_string(&m).expect("serialize")).expect("write");

        match VaultManifest::load(&path) {
            Err(ManifestError::UnsupportedVersion { found, supported }) => {
                assert_eq!(found, FORMAT_VERSION + 1);
                assert_eq!(supported, FORMAT_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn unknown_fields_survive_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tessera.json");

        let raw = serde_json::json!({
            "format_version": 1,
            "created_at": "2026-07-05T12:00:00Z",
            "crypto": {
                "kdf": "argon2id",
                "kdf_m_cost_kib": 65536,
                "kdf_t_cost": 3,
                "kdf_p_cost": 4,
                "cipher": "xchacha20poly1305",
                "future_crypto_hint": "keep-me"
            },
            "embedding_models": [],
            "future_top_level_field": {"nested": true}
        });
        std::fs::write(&path, raw.to_string()).expect("write");

        let loaded = VaultManifest::load(&path).expect("load");
        loaded.save(&path).expect("save");
        let reread: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("parse");

        assert_eq!(reread["future_top_level_field"]["nested"], true);
        assert_eq!(reread["crypto"]["future_crypto_hint"], "keep-me");
    }

    #[test]
    fn load_reports_malformed_json_as_parse_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tessera.json");
        std::fs::write(&path, "{ not json").expect("write");

        match VaultManifest::load(&path) {
            Err(ManifestError::Parse(_)) => {}
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn load_reports_missing_file_as_io_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist.json");

        match VaultManifest::load(&path) {
            Err(ManifestError::Io(_)) => {}
            other => panic!("expected Io error, got {other:?}"),
        }
    }
}
