//! Inbox intake — the entry point of the ingestion pipeline.
//!
//! Files are staged in the bundle's `inbox/` directory (the only place
//! plaintext content ever rests), then taken in per item: detect type,
//! hash, dedup, **encrypt the original into the blob store before anything
//! parses it**, register the artifact (quarantined), and remove the staged
//! file. Extraction/chunking are later pipeline stages (M2 #9, #10).

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::artifact::{self, ArtifactError, ArtifactId, Sensitivity};
use crate::blob::BlobError;
use crate::space::SpaceId;
use crate::vault::{Vault, VaultError};

#[derive(Error, Debug)]
pub enum InboxError {
    #[error("not a file: {0}")]
    NotAFile(PathBuf),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("artifact error: {0}")]
    Artifact(#[from] ArtifactError),
    #[error("blob error: {0}")]
    Blob(#[from] BlobError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Outcome of one `process` run. Failures are per-item and never abort the
/// queue; the original stays in `inbox/` for the failed items.
#[derive(Debug, Default)]
pub struct IntakeReport {
    pub ingested: Vec<(PathBuf, ArtifactId)>,
    pub duplicates: Vec<PathBuf>,
    pub failures: Vec<(PathBuf, String)>,
}

fn inbox_dir(vault: &Vault) -> PathBuf {
    vault.path().join("inbox")
}

/// Copy files into the vault's `inbox/` staging area.
pub fn add(vault: &Vault, paths: &[PathBuf]) -> Result<Vec<PathBuf>, InboxError> {
    let inbox = inbox_dir(vault);
    let mut staged = Vec::with_capacity(paths.len());
    for path in paths {
        if !path.is_file() {
            return Err(InboxError::NotAFile(path.clone()));
        }
        let name = path
            .file_name()
            .ok_or_else(|| InboxError::NotAFile(path.clone()))?;
        let mut target = inbox.join(name);
        // Never clobber an already-staged file with the same name.
        let mut counter = 1;
        while target.exists() {
            let stem = Path::new(name)
                .file_stem()
                .unwrap_or(name)
                .to_string_lossy();
            let ext = Path::new(name)
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy()))
                .unwrap_or_default();
            target = inbox.join(format!("{stem}-{counter}{ext}"));
            counter += 1;
        }
        std::fs::copy(path, &target)?;
        staged.push(target);
    }
    Ok(staged)
}

/// Files currently staged in `inbox/`.
pub fn status(vault: &Vault) -> Result<Vec<PathBuf>, InboxError> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(inbox_dir(vault))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|e| e.path())
        .collect();
    entries.sort();
    Ok(entries)
}

/// Take in every staged file: hash → dedup → encrypt original → register
/// artifact (quarantined) + version → remove from staging.
pub fn process(vault: &Vault, space: &SpaceId) -> Result<IntakeReport, InboxError> {
    // Refuse up front on a locked vault — nothing should be half-processed.
    let dek = vault.dek()?;
    let mut report = IntakeReport::default();

    for staged in status(vault)? {
        match intake_one(vault, dek, space, &staged) {
            Ok(Some(artifact_id)) => report.ingested.push((staged, artifact_id)),
            Ok(None) => {
                report.duplicates.push(staged);
            }
            Err(e) => report.failures.push((staged, e.to_string())),
        }
    }
    Ok(report)
}

/// Intake a single staged file. `Ok(None)` = duplicate content.
fn intake_one(
    vault: &Vault,
    dek: &crate::crypto::Dek,
    space: &SpaceId,
    staged: &Path,
) -> Result<Option<ArtifactId>, InboxError> {
    if !staged.is_file() {
        return Err(InboxError::NotAFile(staged.to_path_buf()));
    }
    let content = std::fs::read(staged)?;
    let hash_hex = blake3::hash(&content).to_hex().to_string();

    // Dedup: same content already versioned anywhere in the vault.
    let already: i64 = vault
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM artifact_versions WHERE blob_hash = ?1",
            [hash_hex.as_str()],
            |r| r.get(0),
        )
        .map_err(ArtifactError::Database)?;
    if already > 0 {
        std::fs::remove_file(staged)?;
        return Ok(None);
    }

    // Encrypt-first: the original is safely in the blob store before any
    // downstream stage (extraction etc.) ever sees it.
    let blob_hash = vault.blobs().put(dek, &content)?;

    let filename = staged
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unnamed".to_owned());
    let artifact_id = artifact::register(
        vault,
        space,
        &filename,
        media_type_for(staged),
        Sensitivity::default(),
    )?;
    artifact::record_version(vault, &artifact_id, &blob_hash, content.len() as u64)?;

    std::fs::remove_file(staged)?;
    Ok(Some(artifact_id))
}

/// Media type from filename extension (v1 heuristic; content sniffing may
/// come later).
pub fn media_type_for(path: &Path) -> &'static str {
    match path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .as_deref()
    {
        Some("pdf") => "application/pdf",
        Some("md" | "markdown") => "text/markdown",
        Some("txt") => "text/plain",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("heic") => "image/heic",
        Some("html" | "htm") => "text/html",
        Some("vtt") => "text/vtt",
        Some("srt") => "application/x-subrip",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::space;

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    fn vault_with_space() -> (tempfile::TempDir, Vault, SpaceId) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("create vault");
        let space = space::create(&vault, "Inbox target", None).expect("space");
        (dir, vault, space)
    }

    fn stage_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).expect("write");
        path
    }

    #[test]
    fn add_copies_into_inbox_staging() {
        let (dir, vault, _space) = vault_with_space();
        let src = stage_file(dir.path(), "notes.md", b"# hello");

        let staged = add(&vault, std::slice::from_ref(&src)).expect("add");
        assert_eq!(staged.len(), 1);
        assert!(staged[0].starts_with(vault.path().join("inbox")));
        assert!(staged[0].is_file());
        assert!(src.is_file(), "source must not be moved, only copied");
        assert_eq!(status(&vault).expect("status").len(), 1);
    }

    #[test]
    fn process_ingests_encrypts_and_clears_staging() {
        let (dir, vault, space) = vault_with_space();
        let src = stage_file(dir.path(), "doc.md", b"# content to vault");
        add(&vault, &[src]).expect("add");

        let report = process(&vault, &space).expect("process");
        assert_eq!(report.ingested.len(), 1);
        assert!(report.duplicates.is_empty());
        assert!(report.failures.is_empty());

        // Artifact registered, quarantined, correct media type.
        let (_, artifact_id) = &report.ingested[0];
        let art = artifact::get(&vault, artifact_id).expect("get");
        assert_eq!(art.state, crate::artifact::ArtifactState::Pending);
        assert_eq!(art.media_type, "text/markdown");

        // Version points at a blob whose plaintext round-trips.
        let expected_hash = blake3::hash(b"# content to vault").to_hex().to_string();
        let blob_hash: String = vault
            .conn()
            .query_row(
                "SELECT blob_hash FROM artifact_versions WHERE artifact_id = ?1",
                [artifact_id.0.as_str()],
                |r| r.get(0),
            )
            .expect("version row");
        assert_eq!(blob_hash, expected_hash);
        let plain = vault
            .blobs()
            .get(
                vault.dek().expect("unlocked"),
                &crate::blob::BlobHash(blob_hash),
            )
            .expect("blob readable");
        assert_eq!(plain, b"# content to vault");

        // Staging cleared.
        assert!(status(&vault).expect("status").is_empty());
    }

    #[test]
    fn duplicate_content_is_reported_not_reingested() {
        let (dir, vault, space) = vault_with_space();
        let a = stage_file(dir.path(), "one.txt", b"same content");
        add(&vault, &[a]).expect("add 1");
        process(&vault, &space).expect("process 1");

        let b = stage_file(dir.path(), "two.txt", b"same content");
        add(&vault, &[b]).expect("add 2");
        let report = process(&vault, &space).expect("process 2");

        assert!(report.ingested.is_empty());
        assert_eq!(report.duplicates.len(), 1);
        assert!(
            status(&vault).expect("status").is_empty(),
            "duplicate should be cleared from staging"
        );
        let artifacts = artifact::list(&vault, &space).expect("list");
        assert_eq!(artifacts.len(), 1, "no second artifact for same content");
    }

    #[test]
    fn per_item_failure_does_not_block_queue() {
        let (dir, vault, space) = vault_with_space();

        // A directory inside inbox/ is not ingestible — must be reported as
        // a failure while the good file still lands.
        std::fs::create_dir(vault.path().join("inbox").join("not-a-file")).expect("mkdir");
        let good = stage_file(dir.path(), "good.txt", b"fine");
        add(&vault, &[good]).expect("add");

        let report = process(&vault, &space).expect("process");
        assert_eq!(report.ingested.len(), 1);
        assert_eq!(report.failures.len(), 1);
        assert!(report.failures[0].1.contains("not a file"));
    }

    #[test]
    fn locked_vault_refuses_processing() {
        let (dir, mut vault, space) = vault_with_space();
        let src = stage_file(dir.path(), "f.txt", b"data");
        add(&vault, &[src]).expect("add");

        vault.lock();
        assert!(matches!(
            process(&vault, &space),
            Err(InboxError::Vault(VaultError::Locked))
        ));
        // Staged file untouched by the refused run.
        assert_eq!(status(&vault).expect("status").len(), 1);
    }

    #[test]
    fn media_types_cover_v1_matrix() {
        for (name, expected) in [
            ("a.pdf", "application/pdf"),
            ("b.md", "text/markdown"),
            ("c.txt", "text/plain"),
            (
                "d.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ),
            ("e.png", "image/png"),
            ("f.jpg", "image/jpeg"),
            ("g.unknownext", "application/octet-stream"),
        ] {
            assert_eq!(media_type_for(Path::new(name)), expected, "for {name}");
        }
    }
}
