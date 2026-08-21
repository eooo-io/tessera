//! Repository-controlled model supply chain.
//!
//! Every local model Tessera loads — the embedder and the image captioner —
//! is pinned to an immutable upstream revision and bound here by SHA-256
//! digests reviewed in this repository. Verification happens on the exact
//! bytes that will be loaded, immediately before loading them, so a
//! substituted or truncated file fails closed rather than silently changing
//! what the vault means.
//!
//! This module holds the parts that are identical for every model. The
//! per-model manifests and runtime contracts live with their consumers.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("{0}")]
    Missing(String),
    #[error("{0}")]
    Verification(String),
}

/// One file of a pinned model, bound by size and digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedModelFile {
    /// Name on disk inside the model directory.
    pub path: String,
    /// Path within the upstream repository at the pinned revision.
    pub source_path: String,
    pub sha256: String,
    pub size: u64,
}

/// Root for installed models: `$TESSERA_MODEL_DIR` or the per-user data dir.
pub fn models_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("TESSERA_MODEL_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    #[cfg(target_os = "macos")]
    let base = home.join("Library/Application Support/tessera/models");
    #[cfg(not(target_os = "macos"))]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"))
        .join("tessera/models");
    base
}

/// Resolve where a named model is installed.
pub fn model_dir(model_name: &str) -> PathBuf {
    models_root().join(model_name)
}

/// Immutable upstream download location for one pinned file.
pub fn download_url(source_repository: &str, revision: &str, file: &TrustedModelFile) -> String {
    format!(
        "{source_repository}/resolve/{revision}/{}",
        file.source_path
    )
}

/// Whether every declared file exists. Loading additionally verifies digests.
pub fn files_present(dir: &Path, files: &[TrustedModelFile]) -> bool {
    files.iter().all(|file| dir.join(&file.path).is_file())
}

/// Verify every activated byte against the repository-controlled manifest.
///
/// Checks size first because it is cheap and catches truncation immediately,
/// then hashes the full file.
pub fn verify_files(dir: &Path, files: &[TrustedModelFile]) -> Result<(), ModelError> {
    for file in files {
        let path = dir.join(&file.path);
        let metadata = std::fs::metadata(&path).map_err(|error| {
            ModelError::Verification(format!(
                "{} is missing or unreadable ({error}); run `tessera model fetch` or `tessera model install --source DIR`",
                path.display()
            ))
        })?;
        if !metadata.is_file() || metadata.len() != file.size {
            return Err(ModelError::Verification(format!(
                "{} has size {}, expected {}",
                path.display(),
                metadata.len(),
                file.size
            )));
        }
        let actual = sha256_of(&path)?;
        if actual != file.sha256 {
            return Err(ModelError::Verification(format!(
                "{} has SHA-256 {actual}, expected {}",
                path.display(),
                file.sha256
            )));
        }
    }
    Ok(())
}

fn sha256_of(path: &Path) -> Result<String, ModelError> {
    let mut input = std::fs::File::open(path).map_err(|error| {
        ModelError::Verification(format!("cannot read {}: {error}", path.display()))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer).map_err(|error| {
            ModelError::Verification(format!("cannot read {}: {error}", path.display()))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str, contents: &[u8]) -> (tempfile::TempDir, TrustedModelFile) {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(name), contents).expect("write");
        let file = TrustedModelFile {
            path: name.to_owned(),
            source_path: format!("onnx/{name}"),
            sha256: format!("{:x}", Sha256::digest(contents)),
            size: contents.len() as u64,
        };
        (dir, file)
    }

    #[test]
    fn matching_bytes_verify() {
        let (dir, file) = fixture("model.onnx", b"trusted bytes");
        assert!(verify_files(dir.path(), std::slice::from_ref(&file)).is_ok());
    }

    #[test]
    fn substituted_bytes_of_the_same_length_are_rejected() {
        let (dir, file) = fixture("model.onnx", b"trusted bytes");
        std::fs::write(dir.path().join("model.onnx"), b"hostile bytes").expect("substitute");
        let error = verify_files(dir.path(), std::slice::from_ref(&file)).expect_err("must reject");
        assert!(error.to_string().contains("SHA-256"));
    }

    #[test]
    fn truncated_files_are_rejected_on_size_before_hashing() {
        let (dir, file) = fixture("model.onnx", b"trusted bytes");
        std::fs::write(dir.path().join("model.onnx"), b"trunc").expect("truncate");
        let error = verify_files(dir.path(), std::slice::from_ref(&file)).expect_err("must reject");
        assert!(error.to_string().contains("size"));
    }

    #[test]
    fn missing_files_name_the_recovery_command() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = TrustedModelFile {
            path: "model.onnx".into(),
            source_path: "onnx/model.onnx".into(),
            sha256: "0".repeat(64),
            size: 1,
        };
        assert!(!files_present(dir.path(), std::slice::from_ref(&file)));
        let error = verify_files(dir.path(), std::slice::from_ref(&file)).expect_err("must fail");
        assert!(error.to_string().contains("tessera model fetch"));
    }

    #[test]
    fn download_urls_pin_the_immutable_revision() {
        let file = TrustedModelFile {
            path: "model.onnx".into(),
            source_path: "onnx/model.onnx".into(),
            sha256: "0".repeat(64),
            size: 1,
        };
        assert_eq!(
            download_url("https://huggingface.co/org/repo", "abc123", &file),
            "https://huggingface.co/org/repo/resolve/abc123/onnx/model.onnx"
        );
    }
}
