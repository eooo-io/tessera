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

use crate::artifact::{self, ArtifactError, ArtifactId, ArtifactState};
use crate::blob::{BlobError, BlobHash};
use crate::lens::{DisclosureMode, LensPolicy};
use crate::search::SearchResult;
use crate::summary::{self, SummaryError};
use crate::vault::{Vault, VaultError};

/// Absolute byte ceiling for summary/excerpt text returned to an agent in one
/// evidence item. Full disclosure is a separately gated owner capability.
pub const MAX_AGENT_TEXT_BYTES: usize = 64 * 1024;

fn bounded_text(text: &str, max_chars: usize) -> String {
    let mut output = String::with_capacity(text.len().min(MAX_AGENT_TEXT_BYTES));
    for character in text.chars().take(max_chars) {
        if output.len() + character.len_utf8() > MAX_AGENT_TEXT_BYTES {
            break;
        }
        output.push(character);
    }
    output
}

#[derive(Error, Debug)]
pub enum DisclosureError {
    #[error("no summary available for {0} — generate one first")]
    NoSummary(String),
    #[error("chunk not found or byte range invalid: {0}")]
    BadChunk(String),
    #[error("artifact not found: {0}")]
    NotFound(String),
    #[error("the active lens does not permit artifact {0}")]
    NotPermitted(String),
    #[error("artifact has no extracted text: {0}")]
    NoText(String),
    #[error("summary error: {0}")]
    Summary(#[from] SummaryError),
    #[error("artifact error: {0}")]
    Artifact(#[from] ArtifactError),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("blob error: {0}")]
    Blob(#[from] BlobError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("transcript error: {0}")]
    Transcript(#[from] crate::transcript::TranscriptError),
}

/// Semantic type of disclosed evidence. Historical code and tool events are
/// data classifications only; they never authorize execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceContentKind {
    DocumentText,
    HistoricalMessage,
    HistoricalCode,
    HistoricalToolCall,
    HistoricalToolResult,
    TranscriptTurn,
}

impl EvidenceContentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DocumentText => "document_text",
            Self::HistoricalMessage => "historical_message",
            Self::HistoricalCode => "historical_code",
            Self::HistoricalToolCall => "historical_tool_call",
            Self::HistoricalToolResult => "historical_tool_result",
            Self::TranscriptTurn => "transcript_turn",
        }
    }
}

/// What an agent actually receives for one retrieval hit.
#[derive(Debug, Clone, PartialEq)]
pub struct RenderedContext {
    pub artifact_id: ArtifactId,
    pub content_kind: EvidenceContentKind,
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
    /// Source-media time covered by the disclosed transcript turns.
    pub timestamp_range: Option<crate::transcript::TimestampRange>,
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
            let body = bounded_text(&body, usize::MAX);
            Ok(RenderedContext {
                artifact_id: result.artifact_id.clone(),
                content_kind: EvidenceContentKind::DocumentText,
                title,
                mode,
                body,
                bytes_disclosed: 0,
                disclosed_range: None,
                timestamp_range: None,
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
            let excerpt = bounded_text(slice, max);
            let bytes = excerpt.len() as u64;
            let timestamp_range = crate::transcript::timestamp_range_for_chunk_range(
                vault,
                &result.chunk_id,
                start as u64,
                start as u64 + bytes,
            )?;
            Ok(RenderedContext {
                artifact_id: result.artifact_id.clone(),
                content_kind: if timestamp_range.is_some() {
                    EvidenceContentKind::TranscriptTurn
                } else {
                    EvidenceContentKind::DocumentText
                },
                title,
                mode,
                body: excerpt,
                bytes_disclosed: bytes,
                disclosed_range: Some((start as u64, start as u64 + bytes)),
                timestamp_range,
                full_disclosure: false,
            })
        }
        DisclosureMode::Full => {
            let derived = read_chunk_derived(vault, &result.chunk_id)?;
            let bytes = derived.len() as u64;
            let timestamp_range = crate::transcript::timestamp_range_for_chunk_range(
                vault,
                &result.chunk_id,
                0,
                bytes,
            )?;
            Ok(RenderedContext {
                artifact_id: result.artifact_id.clone(),
                content_kind: if timestamp_range.is_some() {
                    EvidenceContentKind::TranscriptTurn
                } else {
                    EvidenceContentKind::DocumentText
                },
                title,
                mode,
                body: derived,
                bytes_disclosed: bytes,
                disclosed_range: Some((0, bytes)),
                timestamp_range,
                full_disclosure: true,
            })
        }
    }
}

/// Whether the lens permits an agent to see a specific artifact — the
/// single-artifact analog of the retrieval filter, applied to `vault_get_item`
/// so a known id cannot bypass the lens. Mirrors the SQL constraints exactly:
/// live-only, space include/exclude, media types, sensitivity ceiling, and tag
/// include/exclude.
pub fn permits(
    vault: &Vault,
    lens: &LensPolicy,
    artifact_id: &ArtifactId,
) -> Result<bool, DisclosureError> {
    let a = match artifact::get(vault, artifact_id) {
        Ok(a) => a,
        Err(ArtifactError::NotFound(_)) => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    if a.state != ArtifactState::Live {
        return Ok(false);
    }
    let c = lens.to_constraints();
    if !c.space_ids.is_empty() && !c.space_ids.contains(&a.space_id) {
        return Ok(false);
    }
    if c.space_exclude_ids.contains(&a.space_id) {
        return Ok(false);
    }
    if !c.media_types.is_empty() && !c.media_types.contains(&a.media_type) {
        return Ok(false);
    }
    if a.sensitivity.rank() > c.sensitivity_ceiling.rank() {
        return Ok(false);
    }
    if !c.tag_include.is_empty() || !c.tag_exclude.is_empty() {
        let tags = artifact::tags_of(vault, artifact_id)?;
        if !c.tag_include.is_empty() && !c.tag_include.iter().any(|t| tags.contains(t)) {
            return Ok(false);
        }
        if c.tag_exclude.iter().any(|t| tags.contains(t)) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Render a whole artifact at the lens's disclosure mode (`vault_get_item`).
/// Refuses with `NotPermitted` if the lens does not admit the artifact — the
/// enforcement point that stops id-guessing from bypassing the lens.
pub fn render_item(
    vault: &Vault,
    lens: &LensPolicy,
    artifact_id: &ArtifactId,
    allow_full: bool,
) -> Result<RenderedContext, DisclosureError> {
    if !permits(vault, lens, artifact_id)? {
        return Err(DisclosureError::NotPermitted(artifact_id.0.clone()));
    }
    let art = artifact::get(vault, artifact_id)?;
    let title = lens.allow_metadata.then_some(art.filename);

    let mode = match lens.disclosure_mode {
        DisclosureMode::Full if !allow_full => DisclosureMode::Excerpt,
        other => other,
    };

    match mode {
        DisclosureMode::Summary => {
            let body = summary::get_summary_text(vault, artifact_id)?
                .ok_or_else(|| DisclosureError::NoSummary(artifact_id.0.clone()))?;
            let body = bounded_text(&body, usize::MAX);
            Ok(RenderedContext {
                artifact_id: artifact_id.clone(),
                content_kind: EvidenceContentKind::DocumentText,
                title,
                mode,
                body,
                bytes_disclosed: 0,
                disclosed_range: None,
                timestamp_range: None,
                full_disclosure: false,
            })
        }
        DisclosureMode::Excerpt => {
            let (derived_text_id, derived) = read_artifact_derived(vault, artifact_id)?;
            let max = lens.max_quote_chars.unwrap_or(u32::MAX) as usize;
            let excerpt = bounded_text(&derived, max);
            let bytes = excerpt.len() as u64;
            let timestamp_range = crate::transcript::timestamp_range_for_derived_range(
                vault,
                &derived_text_id,
                0,
                bytes,
            )?;
            Ok(RenderedContext {
                artifact_id: artifact_id.clone(),
                content_kind: if timestamp_range.is_some() {
                    EvidenceContentKind::TranscriptTurn
                } else {
                    EvidenceContentKind::DocumentText
                },
                title,
                mode,
                body: excerpt,
                bytes_disclosed: bytes,
                disclosed_range: Some((0, bytes)),
                timestamp_range,
                full_disclosure: false,
            })
        }
        DisclosureMode::Full => {
            let (derived_text_id, derived) = read_artifact_derived(vault, artifact_id)?;
            let bytes = derived.len() as u64;
            let timestamp_range = crate::transcript::timestamp_range_for_derived_range(
                vault,
                &derived_text_id,
                0,
                bytes,
            )?;
            Ok(RenderedContext {
                artifact_id: artifact_id.clone(),
                content_kind: if timestamp_range.is_some() {
                    EvidenceContentKind::TranscriptTurn
                } else {
                    EvidenceContentKind::DocumentText
                },
                title,
                mode,
                body: derived,
                bytes_disclosed: bytes,
                disclosed_range: Some((0, bytes)),
                timestamp_range,
                full_disclosure: true,
            })
        }
    }
}

/// Decrypt the latest derived text of an artifact (its most recent version's
/// most recent derivation).
fn read_artifact_derived(
    vault: &Vault,
    artifact_id: &ArtifactId,
) -> Result<(String, String), DisclosureError> {
    let (derived_text_id, blob_hash): (String, String) = vault
        .conn()
        .query_row(
            "SELECT dt.id, dt.blob_hash FROM derived_text dt
             JOIN artifact_versions av ON av.id = dt.artifact_version_id
             WHERE av.artifact_id = ?1
             ORDER BY av.version DESC, dt.created_at DESC LIMIT 1",
            [artifact_id.0.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => DisclosureError::NoText(artifact_id.0.clone()),
            other => DisclosureError::Database(other),
        })?;
    let bytes = vault.blobs().get(vault.dek()?, &BlobHash(blob_hash))?;
    Ok((
        derived_text_id,
        String::from_utf8_lossy(&bytes).into_owned(),
    ))
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
    use crate::artifact::{self, ArtifactState, Sensitivity};
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
        artifact::set_state(&vault, &artifact, ArtifactState::Live).expect("live");

        let first = &chunks[0];
        let result = SearchResult {
            artifact_id: artifact,
            artifact_title: "doc.md".into(),
            chunk_id: first.id.clone(),
            relevance_score: 1.0,
            byte_range: (first.byte_offset_start, first.byte_offset_end),
            timestamp_range: None,
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

    /// A lens with no space restriction (empty space_ids) and the highest
    /// ceiling — permits any live artifact, for `render_item` tests.
    fn permissive_lens(mode: DisclosureMode) -> LensPolicy {
        let mut l = LensPolicy::new("t", vec![]);
        l.disclosure_mode = mode;
        l.sensitivity_ceiling = Sensitivity::Restricted;
        l
    }

    #[test]
    fn permits_and_render_item_summary() {
        let (_dir, vault, result, source) = fixture("Fire safety for corridor walls and doors.");
        let art = &result.artifact_id;
        let lens = permissive_lens(DisclosureMode::Summary);
        assert!(permits(&vault, &lens, art).expect("permits"));
        let rc = render_item(&vault, &lens, art, false).expect("render_item");
        assert_eq!(rc.mode, DisclosureMode::Summary);
        assert_eq!(rc.bytes_disclosed, 0);
        assert_eq!(rc.body, summary::summarize_text(&source));
    }

    #[test]
    fn render_item_excerpt_truncates_whole_artifact() {
        let (_dir, vault, result, source) = fixture("The quick brown fox jumps over the lazy dog.");
        let art = &result.artifact_id;
        let mut lens = permissive_lens(DisclosureMode::Excerpt);
        lens.max_quote_chars = Some(9);
        let rc = render_item(&vault, &lens, art, false).expect("render_item");
        assert_eq!(rc.body.chars().count(), 9);
        assert!(
            source.starts_with(&rc.body),
            "excerpt is a prefix of the artifact"
        );
        assert_eq!(rc.bytes_disclosed, rc.body.len() as u64);
        assert_eq!(rc.disclosed_range, Some((0, rc.bytes_disclosed)));
    }

    #[test]
    fn agent_excerpt_has_a_utf8_safe_absolute_byte_ceiling() {
        let source = "🔥".repeat((MAX_AGENT_TEXT_BYTES / 4) + 100);
        let (_dir, vault, result, _) = fixture(&source);
        let lens = permissive_lens(DisclosureMode::Excerpt);
        let rendered = render_item(&vault, &lens, &result.artifact_id, false).expect("render");
        assert_eq!(rendered.body.len(), MAX_AGENT_TEXT_BYTES);
        assert!(rendered.body.is_char_boundary(rendered.body.len()));
        assert_eq!(rendered.bytes_disclosed, MAX_AGENT_TEXT_BYTES as u64);
        assert_eq!(
            rendered.disclosed_range,
            Some((0, MAX_AGENT_TEXT_BYTES as u64))
        );
    }

    #[test]
    fn render_item_refuses_out_of_scope_artifact() {
        let (_dir, vault, result, _s) = fixture("body text");
        let art = &result.artifact_id;
        // Scope the lens to a different space than the artifact lives in.
        let mut lens = permissive_lens(DisclosureMode::Summary);
        lens.space_ids = vec![SpaceId("space_OTHER".into())];
        assert!(!permits(&vault, &lens, art).expect("permits"));
        assert!(matches!(
            render_item(&vault, &lens, art, false),
            Err(DisclosureError::NotPermitted(_))
        ));
    }

    #[test]
    fn render_item_refuses_over_ceiling() {
        let (_dir, vault, result, _s) = fixture("secret body");
        let art = &result.artifact_id;
        artifact::set_sensitivity(&vault, art, Sensitivity::Restricted).expect("sens");
        let mut lens = permissive_lens(DisclosureMode::Summary);
        lens.sensitivity_ceiling = Sensitivity::Internal;
        assert!(!permits(&vault, &lens, art).expect("permits"));
    }

    #[test]
    fn permits_refuses_quarantined_artifact() {
        let (_dir, vault, result, _s) = fixture("pending body");
        let art = &result.artifact_id;
        artifact::set_state(&vault, art, ArtifactState::Archived).expect("archive");
        let lens = permissive_lens(DisclosureMode::Summary);
        assert!(
            !permits(&vault, &lens, art).expect("permits"),
            "non-live is never permitted"
        );
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
