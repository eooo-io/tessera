//! Transcript parsing and timestamp-aware source coordinates.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vault::Vault;

#[derive(Error, Debug)]
pub enum TranscriptError {
    #[error("invalid transcript: {0}")]
    Invalid(String),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampRange {
    pub start_ms: u64,
    pub end_ms: u64,
}

impl TimestampRange {
    pub fn start_label(self) -> String {
        format_timestamp(self.start_ms)
    }

    pub fn end_label(self) -> String {
        format_timestamp(self.end_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptTurn {
    pub turn_index: u32,
    pub byte_offset_start: u64,
    pub byte_offset_end: u64,
    pub speaker: Option<String>,
    pub timestamp: Option<TimestampRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTranscript {
    pub text: String,
    pub turns: Vec<TranscriptTurn>,
}

#[derive(Debug)]
struct Cue {
    start_ms: Option<u64>,
    end_ms: Option<u64>,
    speaker: Option<String>,
    body: String,
}

/// Parse VTT/SRT, or recognize a plain speaker transcript. Ordinary plaintext
/// returns `None` and stays on the passthrough extraction path.
pub fn parse(media_type: &str, input: &str) -> Result<Option<ParsedTranscript>, TranscriptError> {
    let normalized = input.trim_start_matches('\u{feff}').replace("\r\n", "\n");
    let cues = match media_type {
        "text/vtt" => parse_vtt(&normalized)?,
        "application/x-subrip" => parse_srt(&normalized)?,
        "text/plain" => {
            let cues = parse_plain(&normalized)?;
            if cues.len() < 2 {
                return Ok(None);
            }
            cues
        }
        _ => return Ok(None),
    };
    if cues.is_empty() {
        return Err(TranscriptError::Invalid("no transcript cues found".into()));
    }
    Ok(Some(normalize(cues)?))
}

fn parse_vtt(input: &str) -> Result<Vec<Cue>, TranscriptError> {
    let mut lines = input.lines().peekable();
    let first = lines
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| TranscriptError::Invalid("empty VTT".into()))?;
    if !first.trim().starts_with("WEBVTT") {
        return Err(TranscriptError::Invalid(
            "VTT must start with WEBVTT".into(),
        ));
    }
    let remaining = lines.collect::<Vec<_>>().join("\n");
    parse_timed_blocks(&remaining, false)
}

fn parse_srt(input: &str) -> Result<Vec<Cue>, TranscriptError> {
    parse_timed_blocks(input, true)
}

fn parse_timed_blocks(input: &str, numeric_ids: bool) -> Result<Vec<Cue>, TranscriptError> {
    let mut cues = Vec::new();
    for block in input.split("\n\n") {
        let lines: Vec<&str> = block
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        if lines.is_empty() {
            continue;
        }
        if lines[0].trim_start().starts_with("NOTE")
            || lines[0].trim_start().starts_with("STYLE")
            || lines[0].trim_start().starts_with("REGION")
        {
            continue;
        }
        let Some(timing_index) = lines.iter().position(|line| line.contains("-->")) else {
            if numeric_ids {
                return Err(TranscriptError::Invalid(format!(
                    "cue has no timing line: {}",
                    lines[0]
                )));
            }
            // WebVTT permits header metadata before the first blank line.
            continue;
        };
        let cue_id = if timing_index > 0 {
            Some(lines[timing_index - 1].trim().to_owned())
        } else {
            None
        };
        if numeric_ids
            && timing_index > 0
            && cue_id
                .as_deref()
                .and_then(|id| id.parse::<u64>().ok())
                .is_none()
        {
            return Err(TranscriptError::Invalid(
                "SRT cue id must be numeric".into(),
            ));
        }
        let (start_ms, end_ms) = parse_timing_line(lines[timing_index])?;
        let body = lines[timing_index + 1..].join(" ");
        if body.trim().is_empty() {
            return Err(TranscriptError::Invalid("cue body is empty".into()));
        }
        let (speaker, body) = parse_speaker(&body);
        cues.push(Cue {
            start_ms: Some(start_ms),
            end_ms: Some(end_ms),
            speaker,
            body: strip_tags(&body),
        });
    }
    Ok(cues)
}

fn parse_plain(input: &str) -> Result<Vec<Cue>, TranscriptError> {
    let mut cues: Vec<Cue> = Vec::new();
    for (line_number, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (timestamp, remainder) = if let Some(rest) = line.strip_prefix('[') {
            let close = rest.find(']').ok_or_else(|| {
                TranscriptError::Invalid(format!(
                    "plain transcript line {} has an unclosed timestamp",
                    line_number + 1
                ))
            })?;
            let timing = &rest[..close];
            let remainder = rest[close + 1..].trim();
            if timing.contains("-->") {
                let (start, end) = parse_timing_line(timing)?;
                (
                    Some(TimestampRange {
                        start_ms: start,
                        end_ms: end,
                    }),
                    remainder,
                )
            } else {
                let start = parse_timestamp(timing)?;
                (
                    Some(TimestampRange {
                        start_ms: start,
                        end_ms: start,
                    }),
                    remainder,
                )
            }
        } else {
            (None, line)
        };
        let (speaker, body) = parse_speaker(remainder);
        if speaker.is_none() {
            if let Some(previous) = cues.last_mut() {
                previous.body.push(' ');
                previous.body.push_str(remainder);
            }
            continue;
        }
        cues.push(Cue {
            start_ms: timestamp.map(|range| range.start_ms),
            end_ms: timestamp.map(|range| range.end_ms),
            speaker,
            body,
        });
    }
    // A single-time marker extends to the next turn when possible.
    for index in 0..cues.len().saturating_sub(1) {
        if cues[index].start_ms == cues[index].end_ms {
            cues[index].end_ms = cues[index + 1].start_ms;
        }
    }
    Ok(cues)
}

fn parse_timing_line(line: &str) -> Result<(u64, u64), TranscriptError> {
    let (start, rest) = line
        .split_once("-->")
        .ok_or_else(|| TranscriptError::Invalid(format!("bad timing line: {line}")))?;
    let end = rest
        .split_whitespace()
        .next()
        .ok_or_else(|| TranscriptError::Invalid(format!("missing cue end: {line}")))?;
    let start = parse_timestamp(start.trim())?;
    let end = parse_timestamp(end.trim())?;
    if end < start {
        return Err(TranscriptError::Invalid(format!(
            "cue ends before it starts: {line}"
        )));
    }
    Ok((start, end))
}

fn parse_timestamp(input: &str) -> Result<u64, TranscriptError> {
    let input = input.replace(',', ".");
    let parts: Vec<&str> = input.split(':').collect();
    if !(2..=3).contains(&parts.len()) {
        return Err(TranscriptError::Invalid(format!("bad timestamp: {input}")));
    }
    let (hours, minutes, seconds) = if parts.len() == 3 {
        (parts[0], parts[1], parts[2])
    } else {
        ("0", parts[0], parts[1])
    };
    let (whole_seconds, millis) = seconds.split_once('.').unwrap_or((seconds, "0"));
    let hours: u64 = hours
        .parse()
        .map_err(|_| TranscriptError::Invalid(format!("bad timestamp: {input}")))?;
    let minutes: u64 = minutes
        .parse()
        .map_err(|_| TranscriptError::Invalid(format!("bad timestamp: {input}")))?;
    let seconds: u64 = whole_seconds
        .parse()
        .map_err(|_| TranscriptError::Invalid(format!("bad timestamp: {input}")))?;
    if minutes >= 60
        || seconds >= 60
        || millis.is_empty()
        || millis.len() > 3
        || !millis.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(TranscriptError::Invalid(format!("bad timestamp: {input}")));
    }
    let millis: u64 = format!("{millis:0<3}")
        .parse()
        .map_err(|_| TranscriptError::Invalid(format!("bad timestamp: {input}")))?;
    Ok(((hours * 60 + minutes) * 60 + seconds) * 1000 + millis)
}

fn parse_speaker(body: &str) -> (Option<String>, String) {
    let trimmed = body.trim();
    if let Some(rest) = trimmed.strip_prefix("<v ") {
        if let Some(close) = rest.find('>') {
            let speaker = rest[..close].trim();
            if !speaker.is_empty() {
                return (Some(speaker.to_owned()), strip_tags(&rest[close + 1..]));
            }
        }
    }
    if let Some((speaker, text)) = trimmed.split_once(':') {
        let speaker = speaker.trim();
        if !speaker.is_empty() && speaker.chars().count() <= 100 && !text.trim().is_empty() {
            return (Some(speaker.to_owned()), strip_tags(text));
        }
    }
    (None, strip_tags(trimmed))
}

fn strip_tags(input: &str) -> String {
    let mut output = String::new();
    let mut in_tag = false;
    for character in input.chars() {
        match character {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            _ if !in_tag => output.push(character),
            _ => {}
        }
    }
    output.trim().to_owned()
}

fn normalize(cues: Vec<Cue>) -> Result<ParsedTranscript, TranscriptError> {
    let mut text = String::new();
    let mut turns = Vec::with_capacity(cues.len());
    for (index, cue) in cues.into_iter().enumerate() {
        let start = text.len();
        if let (Some(timestamp_start), Some(timestamp_end)) = (cue.start_ms, cue.end_ms) {
            text.push_str(&format!(
                "[{} --> {}] ",
                format_timestamp(timestamp_start),
                format_timestamp(timestamp_end)
            ));
        }
        if let Some(speaker) = &cue.speaker {
            text.push_str(speaker);
            text.push_str(": ");
        }
        text.push_str(cue.body.trim());
        text.push_str("\n\n");
        let end = text.len();
        turns.push(TranscriptTurn {
            turn_index: index as u32,
            byte_offset_start: start as u64,
            byte_offset_end: end as u64,
            speaker: cue.speaker,
            timestamp: match (cue.start_ms, cue.end_ms) {
                (Some(start_ms), Some(end_ms)) => Some(TimestampRange { start_ms, end_ms }),
                _ => None,
            },
        });
    }
    Ok(ParsedTranscript { text, turns })
}

pub fn format_timestamp(milliseconds: u64) -> String {
    let hours = milliseconds / 3_600_000;
    let minutes = (milliseconds / 60_000) % 60;
    let seconds = (milliseconds / 1_000) % 60;
    let millis = milliseconds % 1_000;
    format!("{hours:02}:{minutes:02}:{seconds:02}.{millis:03}")
}

pub(crate) fn persist_turns(
    vault: &Vault,
    derived_text_id: &str,
    turns: &[TranscriptTurn],
) -> Result<(), TranscriptError> {
    for turn in turns {
        vault.conn().execute(
            "INSERT INTO transcript_turns
             (id, derived_text_id, turn_index, byte_offset_start, byte_offset_end,
              timestamp_start_ms, timestamp_end_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                format!("turn_{}", ulid::Ulid::new()),
                derived_text_id,
                turn.turn_index,
                turn.byte_offset_start as i64,
                turn.byte_offset_end as i64,
                turn.timestamp.map(|range| range.start_ms as i64),
                turn.timestamp.map(|range| range.end_ms as i64),
            ],
        )?;
    }
    Ok(())
}

pub fn turns_for_derived(
    vault: &Vault,
    derived_text_id: &str,
) -> Result<Vec<TranscriptTurn>, TranscriptError> {
    let mut statement = vault.conn().prepare(
        "SELECT turn_index, byte_offset_start, byte_offset_end,
                timestamp_start_ms, timestamp_end_ms
         FROM transcript_turns WHERE derived_text_id = ?1 ORDER BY turn_index",
    )?;
    let turns = statement
        .query_map([derived_text_id], |row| {
            let start: Option<i64> = row.get(3)?;
            let end: Option<i64> = row.get(4)?;
            Ok(TranscriptTurn {
                turn_index: row.get(0)?,
                byte_offset_start: row.get::<_, i64>(1)? as u64,
                byte_offset_end: row.get::<_, i64>(2)? as u64,
                // Speaker and source cue identifiers remain inside the
                // encrypted normalized text, not plaintext metadata.
                speaker: None,
                timestamp: start.zip(end).map(|(start_ms, end_ms)| TimestampRange {
                    start_ms: start_ms as u64,
                    end_ms: end_ms as u64,
                }),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(turns)
}

pub fn timestamp_range_for_derived_range(
    vault: &Vault,
    derived_text_id: &str,
    start: u64,
    end: u64,
) -> Result<Option<TimestampRange>, TranscriptError> {
    let range = vault.conn().query_row(
        "SELECT MIN(timestamp_start_ms), MAX(timestamp_end_ms)
         FROM transcript_turns
         WHERE derived_text_id = ?1
           AND byte_offset_end > ?2 AND byte_offset_start < ?3
           AND timestamp_start_ms IS NOT NULL AND timestamp_end_ms IS NOT NULL",
        rusqlite::params![derived_text_id, start as i64, end as i64],
        |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
    )?;
    Ok(range
        .0
        .zip(range.1)
        .map(|(start_ms, end_ms)| TimestampRange {
            start_ms: start_ms as u64,
            end_ms: end_ms as u64,
        }))
}

pub fn timestamp_range_for_chunk_range(
    vault: &Vault,
    chunk_id: &str,
    start: u64,
    end: u64,
) -> Result<Option<TimestampRange>, TranscriptError> {
    let derived_text_id: String = vault.conn().query_row(
        "SELECT derived_text_id FROM chunks WHERE id = ?1",
        [chunk_id],
        |row| row.get(0),
    )?;
    timestamp_range_for_derived_range(vault, &derived_text_id, start, end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactState;
    use crate::chunk::{self, ChunkParams};
    use crate::crypto::KdfParams;
    use crate::lens::{DisclosureMode, LensPolicy};
    use crate::{artifact, disclosure, extract, inbox, space, Vault};

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn vtt_preserves_voice_and_timestamp_ranges() {
        let parsed = parse(
            "text/vtt",
            "WEBVTT\n\nintro\n00:00:01.000 --> 00:00:03.250 align:start\n<v Alice>Hello there</v>\n\n00:00:04.000 --> 00:00:06.000\nBob: General Kenobi\n",
        )
        .expect("parse")
        .expect("transcript");
        assert_eq!(parsed.turns.len(), 2);
        assert_eq!(parsed.turns[0].speaker.as_deref(), Some("Alice"));
        assert_eq!(
            parsed.turns[0].timestamp,
            Some(TimestampRange {
                start_ms: 1000,
                end_ms: 3250
            })
        );
        assert!(parsed.text.contains("Alice: Hello there"));
        assert_eq!(
            &parsed.text[parsed.turns[1].byte_offset_start as usize
                ..parsed.turns[1].byte_offset_end as usize],
            "[00:00:04.000 --> 00:00:06.000] Bob: General Kenobi\n\n"
        );
    }

    #[test]
    fn srt_accepts_comma_milliseconds_and_rejects_reverse_time() {
        let parsed = parse(
            "application/x-subrip",
            "1\n00:00:10,500 --> 00:00:12,000\nAda: First\n\n2\n00:00:12,100 --> 00:00:13,000\nLin: Second\n",
        )
        .expect("parse")
        .expect("transcript");
        assert_eq!(parsed.turns[0].timestamp.unwrap().start_ms, 10_500);
        assert!(parse(
            "application/x-subrip",
            "1\n00:00:02,000 --> 00:00:01,000\nNope\n"
        )
        .is_err());
    }

    #[test]
    fn plain_requires_multiple_speaker_turns_and_keeps_optional_timing() {
        assert!(
            parse("text/plain", "ordinary notes\nwithout speaker structure")
                .expect("ordinary")
                .is_none()
        );
        let parsed = parse(
            "text/plain",
            "[00:01.000 --> 00:02.500] Alice: One\n[00:02.500 --> 00:04.000] Bob: Two\n",
        )
        .expect("parse")
        .expect("transcript");
        assert_eq!(parsed.turns.len(), 2);
        assert_eq!(parsed.turns[1].speaker.as_deref(), Some("Bob"));
        assert_eq!(parsed.turns[1].timestamp.unwrap().end_ms, 4_000);
    }

    #[test]
    fn vtt_and_srt_fixtures_import_chunk_on_turns_and_cite_media_time() {
        for (filename, body, expected_start, expected_end) in [
            (
                "fixture.vtt",
                include_str!("../../../tests/fixtures/transcript.vtt"),
                1_000,
                6_250,
            ),
            (
                "fixture.srt",
                include_str!("../../../tests/fixtures/transcript.srt"),
                10_000,
                15_750,
            ),
        ] {
            let directory = tempfile::tempdir().expect("tempdir");
            let vault = Vault::create_with_params(
                &directory.path().join("Transcript.tessera"),
                "pass",
                &TEST_PARAMS,
            )
            .expect("vault");
            let space_id = space::create(&vault, "Transcripts", None).expect("space");
            let source = directory.path().join(filename);
            std::fs::write(&source, body).expect("fixture");
            inbox::add(&vault, std::slice::from_ref(&source)).expect("add");
            let artifact_id = inbox::process(&vault, &space_id).expect("process").ingested[0]
                .1
                .clone();
            let derived = extract::extract_text(&vault, &artifact_id)
                .expect("extract")
                .expect("transcript text");
            let turns = turns_for_derived(&vault, &derived.id).expect("turns");
            assert_eq!(turns.len(), 2);
            let normalized = extract::read_derived_text(&vault, &derived).expect("normalized");
            assert!(normalized.contains("Alice:") || normalized.contains("Ada:"));
            assert!(normalized.contains("Bob:") || normalized.contains("Lin:"));

            let chunks = chunk::chunk_derived_text(
                &vault,
                &derived,
                &ChunkParams {
                    target_tokens: 1,
                    overlap_tokens: 0,
                },
            )
            .expect("turn chunks");
            assert_eq!(chunks.len(), 2);
            assert_eq!(chunks[0].byte_offset_start, turns[0].byte_offset_start);
            assert_eq!(chunks[0].byte_offset_end, turns[0].byte_offset_end);

            artifact::set_state(&vault, &artifact_id, ArtifactState::Live).expect("live");
            let mut lens = LensPolicy::new("Transcript lens", vec![space_id]);
            lens.disclosure_mode = DisclosureMode::Excerpt;
            lens.max_quote_chars = Some(10_000);
            let rendered = disclosure::render_item(&vault, &lens, &artifact_id, false)
                .expect("render transcript");
            assert_eq!(
                rendered.timestamp_range,
                Some(TimestampRange {
                    start_ms: expected_start,
                    end_ms: expected_end,
                })
            );
            assert_eq!(
                rendered.content_kind,
                disclosure::EvidenceContentKind::TranscriptTurn
            );
        }
    }
}
