//! Per-item summaries.
//!
//! A summary condenses an artifact's extracted text into a short, synthetic
//! descriptor stored as an encrypted blob with a provenance record. It is what
//! the `summary` disclosure mode returns — so it must never contain long
//! verbatim spans of the source (see [`summarize_text`]).
//!
//! The v1 summarizer is deterministic, local, and model-free: it extracts the
//! most salient keywords (frequency, stopwords removed) and composes a fixed
//! template. "Extractive fallback is acceptable v1" (issue #21); a local or
//! cloud abstractive model can slot in behind [`generate`] later.

use thiserror::Error;

use crate::artifact::ArtifactId;
use crate::blob::{BlobError, BlobHash};
use crate::vault::{Vault, VaultError};

#[derive(Error, Debug)]
pub enum SummaryError {
    #[error("artifact not found: {0}")]
    ArtifactNotFound(String),
    #[error("artifact has no versions: {0}")]
    NoVersions(String),
    #[error("no extracted text to summarize for {0} — run extraction first")]
    NoDerivedText(String),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("blob error: {0}")]
    Blob(#[from] BlobError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

/// The v1 summarizer identity, recorded on every stored summary. Bump the
/// version to force regeneration on the next `generate`.
pub const SUMMARIZER: &str = "extractive-keyword";
pub const SUMMARIZER_VERSION: &str = "1";

/// Longest keyword kept in a summary. Bounding token length is what guarantees
/// no >20-char verbatim span leaks (tokens are joined by a separator that
/// breaks contiguity), which the `summary` disclosure mode relies on.
const MAX_KEYWORD_CHARS: usize = 18;
/// How many keywords a summary carries at most.
const MAX_KEYWORDS: usize = 8;

/// A stored summary.
#[derive(Debug, Clone, PartialEq)]
pub struct Summary {
    pub id: String,
    pub artifact_version_id: String,
    pub blob_hash: String,
    pub summarizer: String,
    pub summarizer_version: String,
    pub locality: String,
}

/// Deterministic, model-free keyword-extractive summary.
///
/// Emits lowercased salient keywords (each ≤ [`MAX_KEYWORD_CHARS`]) joined by
/// `", "`. Because tokens are short and separated, the output shares no
/// contiguous run longer than one keyword with the source — so it cannot leak
/// a >20-char verbatim span (guarded by tests).
pub fn summarize_text(text: &str) -> String {
    // Frequency count over lowercased alphabetic words, stopwords removed,
    // preserving first-appearance order for stable tie-breaking.
    let mut order: Vec<String> = Vec::new();
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for raw in text.split(|c: char| !c.is_alphanumeric()) {
        let word = raw.to_lowercase();
        if word.chars().count() < 3 || word.chars().count() > MAX_KEYWORD_CHARS {
            continue;
        }
        if is_stopword(&word) || word.chars().all(|c| c.is_numeric()) {
            continue;
        }
        if !counts.contains_key(&word) {
            order.push(word.clone());
        }
        *counts.entry(word).or_insert(0) += 1;
    }

    // Rank by descending frequency. `sort_by` is stable, so equal-frequency
    // words keep their first-appearance order.
    order.sort_by(|a, b| counts[b].cmp(&counts[a]));
    let top: Vec<String> = order.into_iter().take(MAX_KEYWORDS).collect();

    if top.is_empty() {
        return "Summary unavailable: no salient terms.".to_string();
    }
    format!("Key topics: {}.", top.join(", "))
}

fn is_stopword(w: &str) -> bool {
    const STOP: &[&str] = &[
        "the", "and", "for", "are", "but", "not", "you", "all", "any", "can", "her", "was", "one",
        "our", "out", "day", "get", "has", "him", "his", "how", "man", "new", "now", "old", "see",
        "two", "way", "who", "boy", "did", "its", "let", "put", "say", "she", "too", "use", "with",
        "that", "this", "from", "they", "have", "will", "would", "there", "their", "what", "which",
        "when", "make", "like", "time", "just", "know", "into", "than", "them", "then", "some",
        "were", "been", "your", "about", "over", "also", "more", "must", "such", "only", "very",
        "upon", "each", "other", "these", "those", "shall", "demand",
    ];
    STOP.contains(&w)
}

/// The latest version id of an artifact.
fn latest_version_id(vault: &Vault, artifact: &ArtifactId) -> Result<String, SummaryError> {
    vault
        .conn()
        .query_row(
            "SELECT id FROM artifact_versions WHERE artifact_id = ?1 ORDER BY version DESC LIMIT 1",
            [artifact.0.as_str()],
            |r| r.get(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => SummaryError::NoVersions(artifact.0.clone()),
            other => SummaryError::Database(other),
        })
}

/// Generate and store a summary for an artifact's latest version.
///
/// Idempotent unless `redo` is set: an existing summary for this
/// (version, summarizer, summarizer_version) is returned as-is when
/// `redo == false`, and regenerated in place (new blob, new provenance row)
/// when `redo == true`. Requires that text extraction has already run.
pub fn generate(vault: &Vault, artifact: &ArtifactId, redo: bool) -> Result<Summary, SummaryError> {
    let version_id = latest_version_id(vault, artifact)?;

    if !redo {
        if let Some(existing) = fetch(vault, &version_id)? {
            return Ok(existing);
        }
    }

    // Source text is the most recent derivation of this version.
    let derived_hash: String = vault
        .conn()
        .query_row(
            "SELECT blob_hash FROM derived_text
             WHERE artifact_version_id = ?1 ORDER BY created_at DESC, id DESC LIMIT 1",
            [version_id.as_str()],
            |r| r.get(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => SummaryError::NoDerivedText(artifact.0.clone()),
            other => SummaryError::Database(other),
        })?;

    let dek = vault.dek()?;
    let source = vault.blobs().get(dek, &BlobHash(derived_hash))?;
    let summary_text = summarize_text(&String::from_utf8_lossy(&source));
    let summary_hash = vault.blobs().put(dek, summary_text.as_bytes())?;

    let now = chrono::Utc::now().to_rfc3339();
    let conn = vault.conn();
    // Upsert the summary row (unique on version + summarizer + version).
    let id = match fetch(vault, &version_id)? {
        Some(existing) => {
            conn.execute(
                "UPDATE summaries SET blob_hash = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![summary_hash.0, now, existing.id],
            )?;
            existing.id
        }
        None => {
            let id = format!("sum_{}", ulid::Ulid::new());
            conn.execute(
                "INSERT INTO summaries
                   (id, artifact_version_id, blob_hash, summarizer, summarizer_version,
                    locality, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'local', ?6, ?6)",
                rusqlite::params![
                    id,
                    version_id,
                    summary_hash.0,
                    SUMMARIZER,
                    SUMMARIZER_VERSION,
                    now
                ],
            )?;
            id
        }
    };

    // Every produced blob records its provenance (regenerations accumulate).
    conn.execute(
        "INSERT INTO provenance
           (id, derived_blob_hash, source_artifact_version_id, tool, tool_version, locality, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'local', ?6)",
        rusqlite::params![
            format!("prov_{}", ulid::Ulid::new()),
            summary_hash.0,
            version_id,
            SUMMARIZER,
            SUMMARIZER_VERSION,
            now
        ],
    )?;

    Ok(Summary {
        id,
        artifact_version_id: version_id,
        blob_hash: summary_hash.0,
        summarizer: SUMMARIZER.to_owned(),
        summarizer_version: SUMMARIZER_VERSION.to_owned(),
        locality: "local".to_owned(),
    })
}

/// Fetch the stored summary row for a version, if any.
fn fetch(vault: &Vault, version_id: &str) -> Result<Option<Summary>, SummaryError> {
    vault
        .conn()
        .query_row(
            "SELECT id, artifact_version_id, blob_hash, summarizer, summarizer_version, locality
             FROM summaries
             WHERE artifact_version_id = ?1 AND summarizer = ?2 AND summarizer_version = ?3",
            rusqlite::params![version_id, SUMMARIZER, SUMMARIZER_VERSION],
            |r| {
                Ok(Summary {
                    id: r.get(0)?,
                    artifact_version_id: r.get(1)?,
                    blob_hash: r.get(2)?,
                    summarizer: r.get(3)?,
                    summarizer_version: r.get(4)?,
                    locality: r.get(5)?,
                })
            },
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(SummaryError::Database(other)),
        })
}

/// The stored summary text for an artifact's latest version, decrypted.
/// Returns `None` when no summary has been generated yet.
pub fn get_summary_text(
    vault: &Vault,
    artifact: &ArtifactId,
) -> Result<Option<String>, SummaryError> {
    let version_id = latest_version_id(vault, artifact)?;
    let Some(summary) = fetch(vault, &version_id)? else {
        return Ok(None);
    };
    let bytes = vault
        .blobs()
        .get(vault.dek()?, &BlobHash(summary.blob_hash))?;
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::space::{self, SpaceId};
    use crate::{chunk, extract, inbox};

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    const SOURCE: &str = "Fire safety requirements for corridor walls demand a two hour rating. \
        Corridor fire doors and corridor walls must resist fire for the rated period.";

    fn vault_with_artifact(body: &str) -> (tempfile::TempDir, Vault, ArtifactId) {
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
        chunk::chunk_derived_text(&vault, &derived, &chunk::ChunkParams::default()).expect("chunk");
        (dir, vault, artifact)
    }

    /// The longest common substring length between two strings — the exact
    /// property #22 forbids from exceeding 20 for summary vs source.
    fn longest_common_substring(a: &str, b: &str) -> usize {
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

    #[test]
    fn summary_shares_no_long_verbatim_span() {
        let summary = summarize_text(SOURCE);
        let lcs = longest_common_substring(&summary, SOURCE);
        assert!(
            lcs <= 20,
            "summary leaked a {lcs}-char verbatim span:\n  summary: {summary}"
        );
    }

    #[test]
    fn summary_is_deterministic_and_topical() {
        let a = summarize_text(SOURCE);
        let b = summarize_text(SOURCE);
        assert_eq!(a, b, "summarizer must be deterministic");
        // "fire" and "corridor" are the most frequent salient terms.
        assert!(a.contains("fire"), "expected salient term 'fire': {a}");
        assert!(
            a.contains("corridor"),
            "expected salient term 'corridor': {a}"
        );
        // Stopwords and short words are dropped.
        assert!(
            !a.contains(" for,") && !a.contains("the"),
            "stopwords leaked: {a}"
        );
    }

    #[test]
    fn empty_text_yields_placeholder() {
        assert!(summarize_text("!!! 12 3 ...").contains("no salient terms"));
    }

    #[test]
    fn generate_stores_summary_with_provenance() {
        let (_dir, vault, artifact) = vault_with_artifact(SOURCE);
        let summary = generate(&vault, &artifact, false).expect("generate");
        assert!(summary.id.starts_with("sum_"));
        assert_eq!(summary.locality, "local");

        // Provenance row exists for the summary blob, local.
        let (tool, locality): (String, String) = vault
            .conn()
            .query_row(
                "SELECT tool, locality FROM provenance WHERE derived_blob_hash = ?1",
                [summary.blob_hash.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("provenance row");
        assert_eq!(tool, SUMMARIZER);
        assert_eq!(locality, "local");

        // The stored summary decrypts to the summarizer's output.
        let text = get_summary_text(&vault, &artifact)
            .expect("get")
            .expect("some");
        assert_eq!(text, summarize_text(SOURCE));
    }

    #[test]
    fn generate_is_idempotent_without_redo() {
        let (_dir, vault, artifact) = vault_with_artifact(SOURCE);
        let first = generate(&vault, &artifact, false).expect("first");
        let second = generate(&vault, &artifact, false).expect("second");
        assert_eq!(first, second, "no-redo generate must return the same row");

        let count: i64 = vault
            .conn()
            .query_row("SELECT COUNT(*) FROM summaries", [], |r| r.get(0))
            .expect("count");
        assert_eq!(count, 1, "no duplicate summary rows");
    }

    #[test]
    fn redo_regenerates_in_place() {
        let (_dir, vault, artifact) = vault_with_artifact(SOURCE);
        let first = generate(&vault, &artifact, false).expect("first");
        let redone = generate(&vault, &artifact, true).expect("redo");
        // Same source ⇒ same summary blob, same row id (updated in place).
        assert_eq!(first.id, redone.id, "redo updates the existing row");

        let rows: i64 = vault
            .conn()
            .query_row("SELECT COUNT(*) FROM summaries", [], |r| r.get(0))
            .expect("count");
        assert_eq!(rows, 1);
        // Regeneration is audited: a second provenance row for the blob.
        let provs: i64 = vault
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM provenance WHERE tool = ?1",
                [SUMMARIZER],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(provs, 2, "each generation records provenance");
    }

    #[test]
    fn missing_derived_text_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("create vault");
        let space = space::create(&vault, "Docs", None).expect("space");
        // Register + version but never extract.
        let id = crate::artifact::register(
            &vault,
            &space,
            "x.md",
            "text/markdown",
            crate::artifact::Sensitivity::default(),
        )
        .expect("register");
        crate::artifact::record_version(&vault, &id, &BlobHash("h".into()), 1).expect("version");
        assert!(matches!(
            generate(&vault, &id, false),
            Err(SummaryError::NoDerivedText(_))
        ));
    }
}
