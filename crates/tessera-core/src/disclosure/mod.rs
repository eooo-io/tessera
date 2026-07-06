//! Disclosure rendering — summary, excerpt, and full modes.
//!
//! [`render`] turns a retrieval hit into exactly what an agent is allowed to
//! see under a lens. It is the single chokepoint where the disclosure mode is
//! applied:
//!
//! - **summary** — metadata + the stored summary only; never any verbatim
//!   source text (bytes disclosed = 0).
//! - **excerpt** — the matched chunk, verbatim, truncated to
//!   `max_quote_chars` on a UTF-8 char boundary, recording the exact byte
//!   range disclosed.
//! - **full** — the entire derived text. Disabled by default: unless the
//!   caller passes `allow_full`, a full lens is fail-closed down to an
//!   excerpt. When honored, the result is flagged so the receipt logs it.

use thiserror::Error;

use crate::artifact::ArtifactId;
use crate::blob::{BlobError, BlobHash};
use crate::lens::{DisclosureMode, LensPolicy};
use crate::search::SearchResult;
use crate::summary::{self, SummaryError};
use crate::vault::{Vault, VaultError};

#[derive(Error, Debug)]
pub enum DisclosureError {
    #[error("no summary available for {0} — generate one first")]
    NoSummary(String),
    #[error("chunk not found or byte range invalid: {0}")]
    BadChunk(String),
    #[error("summary error: {0}")]
    Summary(#[from] SummaryError),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("blob error: {0}")]
    Blob(#[from] BlobError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

/// What an agent actually receives for one retrieval hit.
#[derive(Debug, Clone, PartialEq)]
pub struct RenderedContext {
    pub artifact_id: ArtifactId,
    /// Present only when the lens allows metadata.
    pub title: Option<String>,
    /// The mode actually applied — may be a fail-closed downgrade of the lens's
    /// mode (full → excerpt) when full disclosure was not permitted.
    pub mode: DisclosureMode,
    /// The disclosed text the agent sees.
    pub body: String,
    /// Count of verbatim source bytes disclosed (0 in summary mode).
    pub bytes_disclosed: u64,
    /// The exact `[start, end)` byte range of the derived text disclosed
    /// verbatim (excerpt/full). `None` in summary mode.
    pub disclosed_range: Option<(u64, u64)>,
    /// True only when the full derived text was actually returned. The receipt
    /// layer logs this loudly.
    pub full_disclosure: bool,
}

/// Render one retrieval hit under a lens.
///
/// `allow_full` gates full disclosure: with it false (the default posture) a
/// lens whose mode is `full` is downgraded to an excerpt so nothing over-
/// discloses by accident.
pub fn render(
    vault: &Vault,
    result: &SearchResult,
    lens: &LensPolicy,
    allow_full: bool,
) -> Result<RenderedContext, DisclosureError> {
    let title = lens.allow_metadata.then(|| result.artifact_title.clone());

    // Fail-closed: an un-permitted full lens becomes an excerpt.
    let mode = match lens.disclosure_mode {
        DisclosureMode::Full if !allow_full => DisclosureMode::Excerpt,
        other => other,
    };

    match mode {
        DisclosureMode::Summary => {
            let body = summary::get_summary_text(vault, &result.artifact_id)?
                .ok_or_else(|| DisclosureError::NoSummary(result.artifact_id.0.clone()))?;
            Ok(RenderedContext {
                artifact_id: result.artifact_id.clone(),
                title,
                mode,
                body,
                bytes_disclosed: 0,
                disclosed_range: None,
                full_disclosure: false,
            })
        }
        DisclosureMode::Excerpt => {
            let derived = read_chunk_derived(vault, &result.chunk_id)?;
            let (start, end) = (result.byte_range.0 as usize, result.byte_range.1 as usize);
            let slice = derived
                .get(start..end)
                .ok_or_else(|| DisclosureError::BadChunk(result.chunk_id.clone()))?;
            // Truncate to at most max_quote_chars CHARACTERS — taking whole
            // chars is inherently UTF-8-boundary-safe.
            let max = lens.max_quote_chars.unwrap_or(u32::MAX) as usize;
            let excerpt: String = slice.chars().take(max).collect();
            let bytes = excerpt.len() as u64;
            Ok(RenderedContext {
                artifact_id: result.artifact_id.clone(),
                title,
                mode,
                body: excerpt,
                bytes_disclosed: bytes,
                disclosed_range: Some((start as u64, start as u64 + bytes)),
                full_disclosure: false,
            })
        }
        DisclosureMode::Full => {
            let derived = read_chunk_derived(vault, &result.chunk_id)?;
            let bytes = derived.len() as u64;
            Ok(RenderedContext {
                artifact_id: result.artifact_id.clone(),
                title,
                mode,
                body: derived,
                bytes_disclosed: bytes,
                disclosed_range: Some((0, bytes)),
                full_disclosure: true,
            })
        }
    }
}

/// Decrypt the derived text that a chunk points into.
fn read_chunk_derived(vault: &Vault, chunk_id: &str) -> Result<String, DisclosureError> {
    let blob_hash: String = vault
        .conn()
        .query_row(
            "SELECT dt.blob_hash FROM chunks ch
             JOIN derived_text dt ON dt.id = ch.derived_text_id
             WHERE ch.id = ?1",
            [chunk_id],
            |r| r.get(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => DisclosureError::BadChunk(chunk_id.to_owned()),
            other => DisclosureError::Database(other),
        })?;
    let bytes = vault.blobs().get(vault.dek()?, &BlobHash(blob_hash))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::lens::LensPolicy;
    use crate::space::{self, SpaceId};
    use crate::{chunk, extract, inbox, summary};

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    /// Longest common substring — the property #22 caps at 20 for summary mode.
    fn lcs(a: &str, b: &str) -> usize {
        let a: Vec<char> = a.chars().collect();
        let b: Vec<char> = b.chars().collect();
        let mut prev = vec![0usize; b.len() + 1];
        let mut best = 0;
        for i in 1..=a.len() {
            let mut cur = vec![0usize; b.len() + 1];
            for j in 1..=b.len() {
                if a[i - 1] == b[j - 1] {
                    cur[j] = prev[j - 1] + 1;
                    best = best.max(cur[j]);
                }
            }
            prev = cur;
        }
        best
    }

    /// Ingest one doc, extract, chunk, summarize. Returns a SearchResult for
    /// the first chunk plus the decrypted derived text.
    fn fixture(body: &str) -> (tempfile::TempDir, Vault, SearchResult, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("create vault");
        let space: SpaceId = space::create(&vault, "Docs", None).expect("space");
        let path = dir.path().join("doc.md");
        std::fs::write(&path, body).expect("write");
        inbox::add(&vault, std::slice::from_ref(&path)).expect("add");
        let report = inbox::process(&vault, &space).expect("process");
        let artifact = report.ingested[0].1.clone();
        let derived = extract::extract_text(&vault, &artifact)
            .expect("extract")
            .expect("text");
        let chunks = chunk::chunk_derived_text(&vault, &derived, &chunk::ChunkParams::default())
            .expect("chunk");
        summary::generate(&vault, &artifact, false).expect("summary");

        let first = &chunks[0];
        let result = SearchResult {
            artifact_id: artifact,
            artifact_title: "doc.md".into(),
            chunk_id: first.id.clone(),
            relevance_score: 1.0,
            byte_range: (first.byte_offset_start, first.byte_offset_end),
        };
        let derived_text = extract::read_derived_text(&vault, &derived).expect("read");
        (dir, vault, result, derived_text)
    }

    fn lens(mode: DisclosureMode, max_quote_chars: Option<u32>) -> LensPolicy {
        let mut l = LensPolicy::new("t", vec![SpaceId("space_A".into())]);
        l.disclosure_mode = mode;
        l.max_quote_chars = max_quote_chars;
        l
    }

    #[test]
    fn summary_mode_discloses_no_long_verbatim_span() {
        let (_dir, vault, result, source) = fixture(
            "Fire safety requirements for corridor walls demand a two hour rating. \
                     Corridor fire doors resist fire for the rated period.",
        );
        let rendered =
            render(&vault, &result, &lens(DisclosureMode::Summary, None), false).expect("render");

        assert_eq!(rendered.mode, DisclosureMode::Summary);
        assert_eq!(
            rendered.bytes_disclosed, 0,
            "summary discloses no source bytes"
        );
        assert_eq!(rendered.disclosed_range, None);
        assert_eq!(rendered.body, summary::summarize_text(&source));
        let leaked = lcs(&rendered.body, &source);
        assert!(
            leaked <= 20,
            "summary leaked a {leaked}-char span: {}",
            rendered.body
        );
    }

    #[test]
    fn excerpt_truncation_is_utf8_safe_and_records_exact_bytes() {
        // Multibyte content so byte length != char length.
        let body = "Fire 🔥 safety 🔥 corridor walls need rated protection.";
        let (_dir, vault, result, _source) = fixture(body);

        // 8 chars: "Fire 🔥 s" — must NOT split the emoji.
        let rendered = render(
            &vault,
            &result,
            &lens(DisclosureMode::Excerpt, Some(8)),
            false,
        )
        .expect("render");

        assert_eq!(rendered.mode, DisclosureMode::Excerpt);
        assert_eq!(
            rendered.body.chars().count(),
            8,
            "exactly max_quote_chars chars"
        );
        assert!(rendered.body.contains('🔥'), "emoji kept whole, not split");
        // Bytes disclosed is the UTF-8 byte length ("Fire " 5 + 🔥 4 + " s" 2).
        assert_eq!(rendered.bytes_disclosed, rendered.body.len() as u64);
        assert_eq!(rendered.bytes_disclosed, 11);
        let (start, end) = rendered.disclosed_range.expect("range");
        assert_eq!(start, result.byte_range.0, "starts at the chunk offset");
        assert_eq!(
            end - start,
            rendered.bytes_disclosed,
            "exact bytes recorded"
        );
        assert!(!rendered.full_disclosure);
    }

    #[test]
    fn excerpt_without_cap_returns_whole_chunk() {
        let body = "Short chunk body.";
        let (_dir, vault, result, _s) = fixture(body);
        let rendered =
            render(&vault, &result, &lens(DisclosureMode::Excerpt, None), false).expect("render");
        assert_eq!(rendered.body, body);
        assert_eq!(rendered.bytes_disclosed, body.len() as u64);
    }

    #[test]
    fn full_mode_is_disabled_by_default_and_downgrades() {
        let body = "Full disclosure body text for the artifact.";
        let (_dir, vault, result, _s) = fixture(body);

        // allow_full = false ⇒ a full lens is fail-closed to an excerpt.
        let downgraded =
            render(&vault, &result, &lens(DisclosureMode::Full, None), false).expect("render");
        assert_eq!(downgraded.mode, DisclosureMode::Excerpt, "full downgraded");
        assert!(!downgraded.full_disclosure);

        // allow_full = true ⇒ full text, flagged for the receipt.
        let full =
            render(&vault, &result, &lens(DisclosureMode::Full, None), true).expect("render");
        assert_eq!(full.mode, DisclosureMode::Full);
        assert!(full.full_disclosure, "full disclosure must be flagged");
        assert_eq!(full.body, body);
        assert_eq!(full.disclosed_range, Some((0, body.len() as u64)));
    }

    #[test]
    fn metadata_is_withheld_when_lens_forbids_it() {
        let (_dir, vault, result, _s) = fixture("Body with a summary.");
        let mut l = lens(DisclosureMode::Summary, None);
        l.allow_metadata = false;
        let rendered = render(&vault, &result, &l, false).expect("render");
        assert_eq!(rendered.title, None, "title withheld");

        l.allow_metadata = true;
        let rendered = render(&vault, &result, &l, false).expect("render");
        assert_eq!(rendered.title.as_deref(), Some("doc.md"));
    }
}
