//! Text extraction — PDF (text layer), Markdown, plaintext, DOCX (pandoc).
//!
//! Extraction reads the encrypted original, produces normalized text, and
//! stores it as a new encrypted blob with a `derived_text` row and a
//! provenance record. Re-running on an unchanged version with the same
//! extractor version is a no-op returning the existing derivation.

use thiserror::Error;

use crate::artifact::{ArtifactError, ArtifactId};
use crate::blob::{BlobError, BlobHash};
use crate::vault::{Vault, VaultError};

#[derive(Error, Debug)]
pub enum ExtractError {
    #[error("artifact not found: {0}")]
    ArtifactNotFound(String),
    #[error("artifact has no versions: {0}")]
    NoVersions(String),
    #[error("extraction failed: {0}")]
    ExtractionFailed(String),
    #[error("pandoc unavailable: {0}")]
    PandocUnavailable(String),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("artifact error: {0}")]
    Artifact(#[from] ArtifactError),
    #[error("blob error: {0}")]
    Blob(#[from] BlobError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("transcript error: {0}")]
    Transcript(#[from] crate::transcript::TranscriptError),
}

/// A stored extraction output.
#[derive(Debug, Clone, PartialEq)]
pub struct DerivedText {
    pub id: String,
    pub artifact_version_id: String,
    pub blob_hash: String,
    pub extractor: String,
    pub extractor_version: String,
}

const DOCX_MIME: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

/// Whether pandoc is available (used by DOCX extraction and `tessera diag`).
pub fn pandoc_available() -> bool {
    std::process::Command::new("pandoc")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// (extractor name, extractor version) for a media type; `None` = no text
/// path for this type yet.
fn extractor_for(media_type: &str) -> Option<(&'static str, String)> {
    match media_type {
        "text/markdown" | "text/plain" => Some(("passthrough", "1".to_owned())),
        "text/vtt" => Some(("transcript-vtt", "1".to_owned())),
        "application/x-subrip" => Some(("transcript-srt", "1".to_owned())),
        "application/pdf" => Some(("pdf-extract", "0.7".to_owned())),
        DOCX_MIME => Some(("pandoc", "docx-markdown-1".to_owned())),
        _ => None,
    }
}

fn run_extractor(extractor: &str, original: &[u8]) -> Result<String, ExtractError> {
    match extractor {
        "passthrough" => Ok(String::from_utf8_lossy(original).into_owned()),
        "pdf-extract" => pdf_extract::extract_text_from_mem(original)
            .map_err(|e| ExtractError::ExtractionFailed(format!("pdf: {e}"))),
        "pandoc" => {
            if !pandoc_available() {
                return Err(ExtractError::PandocUnavailable(
                    "install pandoc for DOCX extraction".into(),
                ));
            }
            // pandoc cannot read docx from stdin reliably; use a temp file.
            let dir = tempfile::TempDir::new()?;
            crate::vault::permissions::directory(dir.path())?;
            let input = dir.path().join("input.docx");
            std::fs::write(&input, original)?;
            crate::vault::permissions::file(&input)?;
            let output = std::process::Command::new("pandoc")
                .arg(&input)
                .args(["-f", "docx", "-t", "markdown"])
                .output()?;
            if !output.status.success() {
                return Err(ExtractError::ExtractionFailed(format!(
                    "pandoc: {}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
        other => Err(ExtractError::ExtractionFailed(format!(
            "unknown extractor {other}"
        ))),
    }
}

/// Extract text from the latest version of an artifact.
///
/// Returns `Ok(None)` for media types with no text path yet (e.g. images —
/// they gain captions/OCR in M7). Skips work when this extractor version
/// already ran on this version.
pub fn extract_text(
    vault: &Vault,
    artifact: &ArtifactId,
) -> Result<Option<DerivedText>, ExtractError> {
    let art = crate::artifact::get(vault, artifact)?;
    let Some((mut extractor, extractor_version)) = extractor_for(&art.media_type) else {
        return Ok(None);
    };

    let (version_id, original_hash): (String, String) = vault
        .conn()
        .query_row(
            "SELECT id, blob_hash FROM artifact_versions
             WHERE artifact_id = ?1 ORDER BY version DESC LIMIT 1",
            [artifact.0.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ExtractError::NoVersions(artifact.0.clone()),
            other => ExtractError::Database(other),
        })?;

    let dek = vault.dek()?;
    let original = vault.blobs().get(dek, &BlobHash(original_hash))?;
    let original_text = String::from_utf8_lossy(&original);
    let parsed_transcript = crate::transcript::parse(&art.media_type, &original_text)?;
    if art.media_type == "text/plain" && parsed_transcript.is_some() {
        extractor = "transcript-plain";
    }

    // Skip when this extractor version already ran on this version.
    let existing = vault
        .conn()
        .query_row(
            "SELECT id, blob_hash FROM derived_text
             WHERE artifact_version_id = ?1 AND extractor = ?2 AND extractor_version = ?3",
            rusqlite::params![version_id, extractor, extractor_version],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(ExtractError::Database(other)),
        })?;
    if let Some((id, blob_hash)) = existing {
        return Ok(Some(DerivedText {
            id,
            artifact_version_id: version_id,
            blob_hash,
            extractor: extractor.to_owned(),
            extractor_version,
        }));
    }

    let (text, transcript_turns) = match parsed_transcript {
        Some(parsed) => (parsed.text, parsed.turns),
        None => (run_extractor(extractor, &original)?, Vec::new()),
    };

    let derived_hash = vault.blobs().put(dek, text.as_bytes())?;
    let id = format!("dtx_{}", ulid::Ulid::new());
    let now = chrono::Utc::now().to_rfc3339();
    vault.conn().execute_batch("BEGIN IMMEDIATE")?;
    let persisted = (|| -> Result<(), ExtractError> {
        vault.conn().execute(
            "INSERT INTO derived_text (id, artifact_version_id, blob_hash, extractor, extractor_version, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![id, version_id, derived_hash.0, extractor, extractor_version, now],
        )?;
        vault.conn().execute(
            "INSERT INTO provenance (id, derived_blob_hash, source_artifact_version_id, tool, tool_version, locality, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'local', ?6)",
            rusqlite::params![
                format!("prov_{}", ulid::Ulid::new()),
                derived_hash.0,
                version_id,
                extractor,
                extractor_version,
                now
            ],
        )?;
        crate::transcript::persist_turns(vault, &id, &transcript_turns)?;
        Ok(())
    })();
    match persisted {
        Ok(()) => vault.conn().execute_batch("COMMIT")?,
        Err(error) => {
            let _ = vault.conn().execute_batch("ROLLBACK");
            return Err(error);
        }
    }

    Ok(Some(DerivedText {
        id,
        artifact_version_id: version_id,
        blob_hash: derived_hash.0,
        extractor: extractor.to_owned(),
        extractor_version,
    }))
}

/// Read a stored derivation's text (decrypted).
pub fn read_derived_text(vault: &Vault, derived: &DerivedText) -> Result<String, ExtractError> {
    let bytes = vault
        .blobs()
        .get(vault.dek()?, &BlobHash(derived.blob_hash.clone()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::space::SpaceId;
    use crate::{inbox, space};
    use std::path::{Path, PathBuf};

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    fn vault_with_space() -> (tempfile::TempDir, Vault, SpaceId) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("create vault");
        let space = space::create(&vault, "Docs", None).expect("space");
        (dir, vault, space)
    }

    fn ingest(
        vault: &Vault,
        space: &SpaceId,
        dir: &Path,
        name: &str,
        content: &[u8],
    ) -> ArtifactId {
        let path: PathBuf = dir.join(name);
        std::fs::write(&path, content).expect("write");
        inbox::add(vault, std::slice::from_ref(&path)).expect("add");
        let report = inbox::process(vault, space).expect("process");
        report.ingested[0].1.clone()
    }

    /// Build a minimal but structurally valid single-page PDF whose text
    /// layer contains `text`, with a correct xref table.
    fn minimal_pdf(text: &str) -> Vec<u8> {
        let stream = format!("BT /F1 24 Tf 72 700 Td ({text}) Tj ET");
        let objects = [
            "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R \
             /Resources << /Font << /F1 5 0 R >> >> >>"
                .to_string(),
            format!(
                "<< /Length {} >>\nstream\n{stream}\nendstream",
                stream.len()
            ),
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
        ];

        let mut pdf = String::from("%PDF-1.4\n");
        let mut offsets = Vec::new();
        for (i, obj) in objects.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.push_str(&format!("{} 0 obj\n{obj}\nendobj\n", i + 1));
        }
        let xref_offset = pdf.len();
        pdf.push_str(&format!("xref\n0 {}\n", objects.len() + 1));
        pdf.push_str("0000000000 65535 f \n");
        for off in &offsets {
            pdf.push_str(&format!("{off:010} 00000 n \n"));
        }
        pdf.push_str(&format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n",
            objects.len() + 1
        ));
        pdf.into_bytes()
    }

    #[test]
    fn markdown_passes_through_with_provenance() {
        let (dir, vault, space) = vault_with_space();
        let id = ingest(
            &vault,
            &space,
            dir.path(),
            "notes.md",
            b"# Title\n\nBody text.",
        );

        let derived = extract_text(&vault, &id)
            .expect("extract")
            .expect("markdown has text");
        assert_eq!(
            read_derived_text(&vault, &derived).expect("read"),
            "# Title\n\nBody text."
        );

        // Provenance recorded, local.
        let (tool, locality): (String, String) = vault
            .conn()
            .query_row(
                "SELECT tool, locality FROM provenance WHERE derived_blob_hash = ?1",
                [derived.blob_hash.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("provenance row");
        assert_eq!(tool, "passthrough");
        assert_eq!(locality, "local");
    }

    #[test]
    fn re_extraction_is_skipped_for_unchanged_version() {
        let (dir, vault, space) = vault_with_space();
        let id = ingest(&vault, &space, dir.path(), "a.txt", b"stable content");

        let first = extract_text(&vault, &id).expect("first").expect("text");
        let second = extract_text(&vault, &id).expect("second").expect("text");
        assert_eq!(first.id, second.id, "second run must return existing row");

        let derivations: i64 = vault
            .conn()
            .query_row("SELECT COUNT(*) FROM derived_text", [], |r| r.get(0))
            .expect("count");
        assert_eq!(derivations, 1);
    }

    #[test]
    fn pdf_text_layer_is_extracted() {
        let (dir, vault, space) = vault_with_space();
        let pdf = minimal_pdf("Hello Tessera PDF");
        let id = ingest(&vault, &space, dir.path(), "doc.pdf", &pdf);

        let derived = extract_text(&vault, &id)
            .expect("extract")
            .expect("pdf has text layer");
        let text = read_derived_text(&vault, &derived).expect("read");
        assert!(
            text.contains("Hello Tessera PDF"),
            "extracted text was: {text:?}"
        );
    }

    #[test]
    fn image_types_have_no_text_path_yet() {
        let (dir, vault, space) = vault_with_space();
        let id = ingest(&vault, &space, dir.path(), "pic.png", b"\x89PNG\r\n fake");

        assert!(extract_text(&vault, &id).expect("extract").is_none());
    }

    #[test]
    fn extraction_is_deterministic_across_artifacts() {
        let (dir, vault, space) = vault_with_space();
        let id1 = ingest(&vault, &space, dir.path(), "x.md", b"same body");
        let id2 = ingest(&vault, &space, dir.path(), "y.md", b"same body ");

        let d1 = extract_text(&vault, &id1).expect("e1").expect("t1");
        let d2 = extract_text(&vault, &id2).expect("e2").expect("t2");
        // Different inputs → different derived blobs; same pipeline version.
        assert_ne!(d1.blob_hash, d2.blob_hash);
        assert_eq!(d1.extractor_version, d2.extractor_version);
    }

    #[test]
    fn docx_extracts_via_pandoc_when_available() {
        if !pandoc_available() {
            eprintln!("SKIP: pandoc not installed");
            return;
        }
        let (dir, vault, space) = vault_with_space();

        // Build a real DOCX with pandoc itself, then extract from it.
        let docx_path = dir.path().join("made.docx");
        let status = std::process::Command::new("pandoc")
            .args(["-f", "markdown", "-o"])
            .arg(&docx_path)
            .arg("--")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .take()
                    .expect("stdin")
                    .write_all(b"Tessera docx body")?;
                child.wait()
            })
            .expect("pandoc run");
        assert!(status.success());

        let content = std::fs::read(&docx_path).expect("read docx");
        let id = ingest(&vault, &space, dir.path(), "made2.docx", &content);
        let derived = extract_text(&vault, &id).expect("extract").expect("text");
        let text = read_derived_text(&vault, &derived).expect("read");
        assert!(text.contains("Tessera docx body"), "got: {text:?}");
    }
}
