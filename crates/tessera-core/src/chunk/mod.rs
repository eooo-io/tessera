//! Sentence-aware chunking — ~512-token target, ~64-token overlap.
//!
//! Chunks are byte ranges into a derivation's text (offsets always on UTF-8
//! char boundaries) — the text itself stays in the encrypted derived blob
//! and is sliced on demand. Token counts are the chars/4 estimate in v1.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::extract::DerivedText;
use crate::vault::{Vault, VaultError};

#[derive(Error, Debug)]
pub enum ChunkError {
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("extract error: {0}")]
    Extract(#[from] crate::extract::ExtractError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("transcript error: {0}")]
    Transcript(#[from] crate::transcript::TranscriptError),
    #[error("invalid transcript turn coordinates: {0}")]
    InvalidTranscriptTurns(String),
}

/// Chunking parameters (estimated tokens).
#[derive(Debug, Clone, Copy)]
pub struct ChunkParams {
    pub target_tokens: usize,
    pub overlap_tokens: usize,
}

impl Default for ChunkParams {
    fn default() -> Self {
        Self {
            target_tokens: 512,
            overlap_tokens: 64,
        }
    }
}

/// A chunk of extracted text, sized for embedding and retrieval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    pub id: String,
    pub derived_text_id: String,
    pub chunk_index: u32,
    pub byte_offset_start: u64,
    pub byte_offset_end: u64,
    pub token_count: u32,
    pub section_heading: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Estimated token count for a text (chars/4 heuristic, minimum 1 for
/// non-empty text).
pub fn estimate_tokens(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }
    (text.chars().count()).div_ceil(4)
}

/// Split text into sentence-ish segments as byte ranges. Boundaries fall
/// after sentence terminators (. ! ?) followed by whitespace, and at
/// paragraph breaks. Every byte of input is covered; offsets are always on
/// char boundaries.
pub fn split_sentences(text: &str) -> Vec<(usize, usize)> {
    if text.is_empty() {
        return Vec::new();
    }

    let mut segments = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();

    while let Some((idx, ch)) = chars.next() {
        let is_terminator = matches!(ch, '.' | '!' | '?');
        let is_para_break = ch == '\n' && matches!(chars.peek(), Some((_, '\n')));

        if is_terminator {
            // Consume the whitespace run following the terminator; the
            // segment ends after it, so the next segment starts at text.
            let mut end = idx + ch.len_utf8();
            while let Some(&(nidx, nch)) = chars.peek() {
                if nch.is_whitespace() {
                    end = nidx + nch.len_utf8();
                    chars.next();
                } else {
                    break;
                }
            }
            if chars.peek().is_some() {
                segments.push((start, end));
                start = end;
            }
        } else if is_para_break {
            // Consume the newline run; break the segment after it.
            let mut end = idx + 1;
            while let Some(&(nidx, nch)) = chars.peek() {
                if nch == '\n' {
                    end = nidx + 1;
                    chars.next();
                } else {
                    break;
                }
            }
            if chars.peek().is_some() {
                segments.push((start, end));
                start = end;
            }
        }
    }
    if start < text.len() {
        segments.push((start, text.len()));
    }
    segments
}

/// Pure chunking: pack sentence segments into chunks near the target size
/// with back-overlap. Returns byte ranges into `text`.
pub fn chunk_ranges(text: &str, params: &ChunkParams) -> Vec<(usize, usize)> {
    let segments = split_sentences(text);
    pack_segments(text, &segments, params)
}

/// Pack whole transcript turns into chunks. No speaker turn is split merely
/// to satisfy the target size; an unusually large turn remains one chunk.
pub fn turn_chunk_ranges(
    text: &str,
    turns: &[crate::transcript::TranscriptTurn],
    params: &ChunkParams,
) -> Result<Vec<(usize, usize)>, ChunkError> {
    let segments: Vec<(usize, usize)> = turns
        .iter()
        .map(|turn| {
            (
                turn.byte_offset_start as usize,
                turn.byte_offset_end as usize,
            )
        })
        .collect();
    let mut expected_start = 0;
    for (start, end) in &segments {
        if *start != expected_start
            || *start >= *end
            || *end > text.len()
            || !text.is_char_boundary(*start)
            || !text.is_char_boundary(*end)
        {
            return Err(ChunkError::InvalidTranscriptTurns(format!(
                "expected contiguous UTF-8 range at {expected_start}, found {start}..{end}"
            )));
        }
        expected_start = *end;
    }
    if expected_start != text.len() {
        return Err(ChunkError::InvalidTranscriptTurns(format!(
            "turns end at {expected_start}, derived text ends at {}",
            text.len()
        )));
    }
    Ok(pack_segments(text, &segments, params))
}

fn pack_segments(
    text: &str,
    segments: &[(usize, usize)],
    params: &ChunkParams,
) -> Vec<(usize, usize)> {
    if segments.is_empty() {
        return Vec::new();
    }
    let seg_tokens: Vec<usize> = segments
        .iter()
        .map(|&(s, e)| estimate_tokens(&text[s..e]))
        .collect();

    let mut chunks = Vec::new();
    // Chunks tracked as segment-index ranges [seg_start, seg_end).
    let mut seg_start = 0usize;
    let mut prev_end = 0usize;

    loop {
        // Extend until the token budget is spent — but always past the
        // previous chunk's end so ranges advance.
        let mut end = seg_start;
        let mut tokens = 0usize;
        while end < segments.len() && (tokens < params.target_tokens || end < prev_end + 1) {
            tokens += seg_tokens[end];
            end += 1;
            if tokens >= params.target_tokens && end > prev_end {
                break;
            }
        }
        chunks.push((segments[seg_start].0, segments[end - 1].1));

        if end == segments.len() {
            break;
        }

        // Back-overlap: start the next chunk a few segments early, staying
        // strictly after this chunk's first segment.
        let mut k = end;
        let mut overlap = 0usize;
        while k > seg_start + 1 && overlap < params.overlap_tokens {
            k -= 1;
            overlap += seg_tokens[k];
        }
        prev_end = end;
        seg_start = k;
    }
    chunks
}

/// Chunk a derivation and persist chunk rows. Skips (returning existing
/// chunks) when the derivation is already chunked.
pub fn chunk_derived_text(
    vault: &Vault,
    derived: &DerivedText,
    params: &ChunkParams,
) -> Result<Vec<Chunk>, ChunkError> {
    let existing = chunks_of(vault, &derived.id)?;
    if !existing.is_empty() {
        return Ok(existing);
    }

    let text = crate::extract::read_derived_text(vault, derived)?;
    let turns = crate::transcript::turns_for_derived(vault, &derived.id)?;
    let ranges = if turns.is_empty() {
        chunk_ranges(&text, params)
    } else {
        turn_chunk_ranges(&text, &turns, params)?
    };
    let now = chrono::Utc::now();
    let mut chunks = Vec::new();
    for (index, (start, end)) in ranges.into_iter().enumerate() {
        let slice = &text[start..end];
        let chunk = Chunk {
            id: format!("chunk_{}", ulid::Ulid::new()),
            derived_text_id: derived.id.clone(),
            chunk_index: index as u32,
            byte_offset_start: start as u64,
            byte_offset_end: end as u64,
            token_count: estimate_tokens(slice) as u32,
            section_heading: None,
            created_at: now,
        };
        vault.conn().execute(
            "INSERT INTO chunks (id, derived_text_id, chunk_index, byte_offset_start,
                                 byte_offset_end, token_count, content_hash, section_heading, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                chunk.id,
                chunk.derived_text_id,
                chunk.chunk_index,
                chunk.byte_offset_start as i64,
                chunk.byte_offset_end as i64,
                chunk.token_count,
                blake3::hash(slice.as_bytes()).to_hex().to_string(),
                chunk.section_heading,
                now.to_rfc3339()
            ],
        )?;
        chunks.push(chunk);
    }
    Ok(chunks)
}

/// Load the chunks of a derivation, in order.
pub fn chunks_of(vault: &Vault, derived_text_id: &str) -> Result<Vec<Chunk>, ChunkError> {
    let mut stmt = vault.conn().prepare(
        "SELECT id, derived_text_id, chunk_index, byte_offset_start, byte_offset_end,
                token_count, section_heading, created_at
         FROM chunks WHERE derived_text_id = ?1 ORDER BY chunk_index",
    )?;
    let chunks = stmt
        .query_map([derived_text_id], |row| {
            Ok(Chunk {
                id: row.get(0)?,
                derived_text_id: row.get(1)?,
                chunk_index: row.get(2)?,
                byte_offset_start: row.get::<_, i64>(3)? as u64,
                byte_offset_end: row.get::<_, i64>(4)? as u64,
                token_count: row.get(5)?,
                section_heading: row.get(6)?,
                created_at: row
                    .get::<_, String>(7)?
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap_or_default(),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::space::SpaceId;
    use crate::{extract, inbox, space};
    use std::path::Path;

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

    fn ingest_and_extract(
        vault: &Vault,
        space: &SpaceId,
        dir: &Path,
        name: &str,
        content: &str,
    ) -> DerivedText {
        let path = dir.join(name);
        std::fs::write(&path, content).expect("write");
        inbox::add(vault, std::slice::from_ref(&path)).expect("add");
        let report = inbox::process(vault, space).expect("process");
        extract::extract_text(vault, &report.ingested[0].1)
            .expect("extract")
            .expect("has text")
    }

    #[test]
    fn sentences_cover_all_bytes_in_order() {
        let text = "First sentence. Second one! Third?\n\nNew paragraph here.";
        let segs = split_sentences(text);

        assert_eq!(segs.first().expect("nonempty").0, 0);
        assert_eq!(segs.last().expect("nonempty").1, text.len());
        for pair in segs.windows(2) {
            assert_eq!(pair[0].1, pair[1].0, "segments must be contiguous");
        }
        assert!(segs.len() >= 4, "expected ≥4 segments, got {segs:?}");
    }

    #[test]
    fn small_text_is_one_chunk() {
        let text = "Just a short note.";
        let ranges = chunk_ranges(text, &ChunkParams::default());
        assert_eq!(ranges, vec![(0, text.len())]);
    }

    #[test]
    fn long_text_chunks_respect_sentences_and_overlap() {
        // ~200 sentences of ~10 estimated tokens each.
        let text: String = (0..200)
            .map(|i| format!("This is sentence number {i} with several words in it. "))
            .collect();
        let params = ChunkParams {
            target_tokens: 100,
            overlap_tokens: 20,
        };
        let ranges = chunk_ranges(&text, &params);

        assert!(ranges.len() > 1, "long text must split");
        assert_eq!(ranges[0].0, 0);
        assert_eq!(ranges.last().expect("nonempty").1, text.len());
        for pair in ranges.windows(2) {
            let (prev, next) = (pair[0], pair[1]);
            assert!(next.0 < prev.1, "consecutive chunks must overlap");
            assert!(next.0 > prev.0, "chunks must advance");
            // Chunk boundaries respect sentence starts: the byte before a
            // chunk start (skipping whitespace) ends a sentence.
            let before = text[..next.0].trim_end();
            assert!(
                before.ends_with(['.', '!', '?']),
                "chunk start {} not at a sentence boundary",
                next.0
            );
        }
    }

    #[test]
    fn persisted_chunks_slice_back_to_original_text() {
        let (dir, vault, space) = vault_with_space();
        let body: String = (0..80)
            .map(|i| format!("Persisted sentence {i} goes right here. "))
            .collect();
        let derived = ingest_and_extract(&vault, &space, dir.path(), "long.txt", &body);

        let params = ChunkParams {
            target_tokens: 64,
            overlap_tokens: 8,
        };
        let chunks = chunk_derived_text(&vault, &derived, &params).expect("chunk");
        assert!(chunks.len() > 1);

        let full = extract::read_derived_text(&vault, &derived).expect("read");
        for chunk in &chunks {
            let slice = &full[chunk.byte_offset_start as usize..chunk.byte_offset_end as usize];
            assert_eq!(
                blake3::hash(slice.as_bytes()).to_hex().to_string(),
                vault
                    .conn()
                    .query_row(
                        "SELECT content_hash FROM chunks WHERE id = ?1",
                        [chunk.id.as_str()],
                        |r| r.get::<_, String>(0),
                    )
                    .expect("hash row"),
                "content hash must match the slice"
            );
        }
    }

    #[test]
    fn rechunking_is_skipped() {
        let (dir, vault, space) = vault_with_space();
        let derived = ingest_and_extract(
            &vault,
            &space,
            dir.path(),
            "n.md",
            "One sentence here. Another one there.",
        );

        let first = chunk_derived_text(&vault, &derived, &ChunkParams::default()).expect("1st");
        let second = chunk_derived_text(&vault, &derived, &ChunkParams::default()).expect("2nd");
        assert_eq!(
            first.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            second.iter().map(|c| c.id.as_str()).collect::<Vec<_>>()
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        /// Invariants hold for arbitrary unicode text: coverage from 0 to
        /// len, ordered advancing starts, char-boundary offsets, and no
        /// gaps between consecutive chunks.
        #[test]
        fn prop_chunk_invariants(text in "\\PC{0,2000}", target in 16usize..256) {
            let params = ChunkParams { target_tokens: target, overlap_tokens: target / 8 };
            let ranges = chunk_ranges(&text, &params);

            if text.is_empty() {
                proptest::prop_assert!(ranges.is_empty());
            } else {
                proptest::prop_assert_eq!(ranges[0].0, 0);
                proptest::prop_assert_eq!(ranges.last().expect("nonempty").1, text.len());
                for &(s, e) in &ranges {
                    proptest::prop_assert!(s < e);
                    proptest::prop_assert!(text.is_char_boundary(s));
                    proptest::prop_assert!(text.is_char_boundary(e));
                }
                for pair in ranges.windows(2) {
                    proptest::prop_assert!(pair[1].0 > pair[0].0, "starts must advance");
                    proptest::prop_assert!(pair[1].0 <= pair[0].1, "no gaps between chunks");
                }
            }
        }
    }
}
