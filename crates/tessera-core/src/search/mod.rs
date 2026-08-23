//! Policy-filtered semantic retrieval.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::artifact::Sensitivity;
use crate::embed::{EmbedError, EmbeddingProvider};
use crate::index::{IndexError, RetrievalConstraints, SqliteVecIndex, VectorIndex};
use crate::vault::{Vault, VaultError};

#[derive(Error, Debug)]
pub enum SearchError {
    #[error("embedding error: {0}")]
    Embed(#[from] EmbedError),
    #[error("index error: {0}")]
    Index(#[from] IndexError),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("transcript error: {0}")]
    Transcript(#[from] crate::transcript::TranscriptError),
    #[error("web provenance error: {0}")]
    Web(#[from] crate::web::WebError),
    #[error("no relevance calibration for embedding model {0}; refusing disclosure")]
    UncalibratedModel(String),
}

/// A single search result with citation metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub artifact_id: crate::artifact::ArtifactId,
    pub artifact_title: String,
    pub chunk_id: String,
    pub relevance_score: f32,
    pub byte_range: (u64, u64),
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_range: Option<crate::transcript::TimestampRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchDiagnostics {
    pub relevance_threshold: f32,
    pub candidates_considered: u32,
    pub rejected_below_threshold: u32,
    pub best_candidate_score: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdedSearch {
    pub results: Vec<SearchResult>,
    pub diagnostics: SearchDiagnostics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReindexProgress {
    pub model_version: String,
    pub status: String,
    pub processed_chunks: usize,
    pub total_chunks: usize,
}

/// Return durable shadow-index progress, if a reindex has ever started.
pub fn reindex_progress(vault: &Vault) -> Result<Option<ReindexProgress>, SearchError> {
    let state = vault.conn().query_row(
        "SELECT model_version, status, total_chunks FROM reindex_state WHERE singleton = 1",
        [],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        },
    );
    let (model_version, status, total) = match state {
        Ok(value) => value,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let processed: i64 =
        vault
            .conn()
            .query_row("SELECT COUNT(*) FROM reindex_embeddings_map", [], |r| {
                r.get(0)
            })?;
    Ok(Some(ReindexProgress {
        model_version,
        status,
        processed_chunks: processed as usize,
        total_chunks: total as usize,
    }))
}

/// Request cooperative cancellation. A running reindex checks this durable
/// flag between chunks; the active index is unaffected.
pub fn cancel_reindex(vault: &Vault) -> Result<bool, SearchError> {
    let changed = vault.conn().execute(
        "UPDATE reindex_state SET status = 'cancel_requested', updated_at = ?1
         WHERE singleton = 1 AND status = 'running'",
        [chrono::Utc::now().to_rfc3339()],
    )?;
    Ok(changed == 1)
}

/// Build a complete shadow index, resuming any compatible partial run. Each
/// chunk is committed independently. Only a complete shadow replaces the
/// active index, in one rollback-safe database transaction.
///
/// `max_chunks` is an operational pause hook useful for bounded maintenance;
/// `None` runs until complete or cooperatively cancelled.
pub fn reindex(
    vault: &Vault,
    embedder: &dyn EmbeddingProvider,
    max_chunks: Option<usize>,
) -> Result<ReindexProgress, SearchError> {
    if embedder.dimensions() != crate::index::sqlite_vec::DIMENSIONS {
        return Err(IndexError::DimensionMismatch {
            expected: crate::index::sqlite_vec::DIMENSIONS,
            found: embedder.dimensions(),
        }
        .into());
    }
    let total: i64 = vault
        .conn()
        .query_row("SELECT COUNT(*) FROM chunks", [], |r| r.get(0))?;
    let now = chrono::Utc::now().to_rfc3339();
    if let Some(existing) = reindex_progress(vault)? {
        if existing.status != "complete" && existing.model_version != embedder.model_version() {
            return Err(IndexError::UnknownModel(format!(
                "partial reindex uses '{}' but requested '{}'; resume it or explicitly complete/cancel before changing models",
                existing.model_version,
                embedder.model_version()
            ))
            .into());
        }
        if existing.status == "complete" {
            vault
                .conn()
                .execute("DELETE FROM reindex_embeddings_map", [])?;
            vault
                .conn()
                .execute("DELETE FROM reindex_chunk_embeddings", [])?;
        }
    }
    vault.conn().execute(
        "INSERT INTO reindex_state (singleton, model_version, status, total_chunks, started_at, updated_at)
         VALUES (1, ?1, 'running', ?2, ?3, ?3)
         ON CONFLICT(singleton) DO UPDATE SET
           model_version = excluded.model_version,
           status = 'running', total_chunks = excluded.total_chunks,
           updated_at = excluded.updated_at",
        rusqlite::params![embedder.model_version(), total, now],
    )?;

    let pending: Vec<(String, String, u64, u64)> = {
        let mut stmt = vault.conn().prepare(
            "SELECT ch.id, dt.blob_hash, ch.byte_offset_start, ch.byte_offset_end
             FROM chunks ch
             JOIN derived_text dt ON dt.id = ch.derived_text_id
             LEFT JOIN reindex_embeddings_map rem ON rem.chunk_id = ch.id
             WHERE rem.chunk_id IS NULL
             ORDER BY ch.created_at, ch.id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get::<_, i64>(2)? as u64,
                r.get::<_, i64>(3)? as u64,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let dek = vault.dek()?;
    let limit = max_chunks.unwrap_or(usize::MAX);
    for (chunk_id, blob_hash, start, end) in pending.into_iter().take(limit) {
        let status: String = vault.conn().query_row(
            "SELECT status FROM reindex_state WHERE singleton = 1",
            [],
            |r| r.get(0),
        )?;
        if status == "cancel_requested" {
            return Ok(reindex_progress(vault)?.expect("state exists"));
        }
        let text_bytes = vault
            .blobs()
            .get(dek, &crate::blob::BlobHash(blob_hash))
            .map_err(VaultError::Blob)?;
        let full = String::from_utf8_lossy(&text_bytes);
        let slice = full.get(start as usize..end as usize).unwrap_or(&full);
        let vector = embedder.embed(slice)?;
        if vector.len() != crate::index::sqlite_vec::DIMENSIONS {
            return Err(IndexError::DimensionMismatch {
                expected: crate::index::sqlite_vec::DIMENSIONS,
                found: vector.len(),
            }
            .into());
        }
        let blob: Vec<u8> = vector.iter().flat_map(|f| f.to_le_bytes()).collect();
        vault.conn().execute_batch("BEGIN IMMEDIATE")?;
        let inserted = (|| -> Result<(), rusqlite::Error> {
            vault.conn().execute(
                "INSERT INTO reindex_chunk_embeddings (embedding) VALUES (?1)",
                rusqlite::params![blob],
            )?;
            let rowid = vault.conn().last_insert_rowid();
            vault.conn().execute(
                "INSERT INTO reindex_embeddings_map (chunk_id, vec_rowid, model_version, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![chunk_id, rowid, embedder.model_version(), chrono::Utc::now().to_rfc3339()],
            )?;
            vault.conn().execute(
                "UPDATE reindex_state SET updated_at = ?1 WHERE singleton = 1",
                [chrono::Utc::now().to_rfc3339()],
            )?;
            Ok(())
        })();
        match inserted {
            Ok(()) => vault.conn().execute_batch("COMMIT")?,
            Err(error) => {
                let _ = vault.conn().execute_batch("ROLLBACK");
                return Err(error.into());
            }
        }
    }

    let progress = reindex_progress(vault)?.expect("state exists");
    if progress.processed_chunks == progress.total_chunks {
        // An ingest may have committed while the shadow was building. Recheck
        // at the activation boundary; a later invocation will add those new
        // chunks rather than publishing a knowingly incomplete shadow.
        let current_total: i64 =
            vault
                .conn()
                .query_row("SELECT COUNT(*) FROM chunks", [], |r| r.get(0))?;
        if current_total as usize != progress.total_chunks {
            vault.conn().execute(
                "UPDATE reindex_state SET total_chunks = ?1, updated_at = ?2 WHERE singleton = 1",
                rusqlite::params![current_total, chrono::Utc::now().to_rfc3339()],
            )?;
            return Ok(reindex_progress(vault)?.expect("state exists"));
        }
        let activated = (|| -> Result<(), rusqlite::Error> {
            vault.conn().execute_batch("BEGIN IMMEDIATE")?;
            vault.conn().execute("DELETE FROM embeddings_map", [])?;
            vault.conn().execute("DELETE FROM chunk_embeddings", [])?;
            vault.conn().execute(
                "INSERT INTO chunk_embeddings (rowid, embedding)
                 SELECT rowid, embedding FROM reindex_chunk_embeddings",
                [],
            )?;
            vault.conn().execute(
                "INSERT INTO embeddings_map (chunk_id, vec_rowid, model_version, created_at)
                 SELECT chunk_id, vec_rowid, model_version, created_at FROM reindex_embeddings_map",
                [],
            )?;
            vault.conn().execute(
                "UPDATE reindex_state SET status = 'complete', updated_at = ?1 WHERE singleton = 1",
                [chrono::Utc::now().to_rfc3339()],
            )?;
            vault.conn().execute_batch("COMMIT")?;
            Ok(())
        })();
        if let Err(error) = activated {
            let _ = vault.conn().execute_batch("ROLLBACK");
            return Err(error.into());
        }
    }
    Ok(reindex_progress(vault)?.expect("state exists"))
}

/// Owner-facing constraints: everything the owner may see (full sensitivity
/// ceiling, all spaces). The live-only rule still applies — it always does.
pub fn owner_constraints() -> RetrievalConstraints {
    RetrievalConstraints {
        sensitivity_ceiling: Sensitivity::Restricted,
        ..Default::default()
    }
}

/// Embed every chunk that has no vector yet. Returns how many were embedded.
pub fn embed_missing(
    vault: &Vault,
    embedder: &dyn EmbeddingProvider,
) -> Result<usize, SearchError> {
    // Collect (chunk_id, text) for chunks without vectors.
    let pending: Vec<(String, String, u64, u64)> = {
        let mut stmt = vault.conn().prepare(
            "SELECT ch.id, dt.blob_hash, ch.byte_offset_start, ch.byte_offset_end
             FROM chunks ch
             JOIN derived_text dt ON dt.id = ch.derived_text_id
             LEFT JOIN embeddings_map em ON em.chunk_id = ch.id
             WHERE em.chunk_id IS NULL
             ORDER BY ch.created_at, ch.id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)? as u64,
                    r.get::<_, i64>(3)? as u64,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    if pending.is_empty() {
        return Ok(0);
    }

    let dek = vault.dek()?;
    let mut index = SqliteVecIndex::new(vault, embedder.model_version());
    let mut count = 0;
    for (chunk_id, blob_hash, start, end) in pending {
        let text_bytes = vault
            .blobs()
            .get(dek, &crate::blob::BlobHash(blob_hash))
            .map_err(VaultError::Blob)?;
        let full = String::from_utf8_lossy(&text_bytes);
        let slice = full
            .get(start as usize..end as usize)
            .unwrap_or(&full)
            .to_owned();
        let vector = embedder.embed(&slice)?;
        index.insert(&chunk_id, &vector)?;
        count += 1;
    }

    // Record the model inside protected vault metadata so a fresh guardian on
    // another machine knows what produced these vectors after unlock.
    let version = embedder.model_version();
    if !vault
        .embedding_models()?
        .iter()
        .any(|m| m.version == version)
    {
        vault.register_embedding_model(crate::vault::EmbeddingModelEntry {
            name: version.split('@').next().unwrap_or(version).to_owned(),
            version: version.to_owned(),
            dimensions: embedder.dimensions() as u32,
        })?;
    }
    Ok(count)
}

/// Semantic search: embed the query, run the policy-filtered KNN, hydrate
/// results with artifact titles and citation byte ranges.
fn query_candidates(
    vault: &Vault,
    embedder: &dyn EmbeddingProvider,
    text: &str,
    constraints: &RetrievalConstraints,
    top_k: usize,
) -> Result<Vec<SearchResult>, SearchError> {
    let query_vec = embedder.embed(text)?;
    let index = SqliteVecIndex::new(vault, embedder.model_version());
    let hits = index.search(&query_vec, constraints, top_k)?;

    let mut results = Vec::with_capacity(hits.len());
    for hit in hits {
        let (title, derived_text_id, start, end, source_url): (
            String,
            String,
            i64,
            i64,
            Option<String>,
        ) = vault.conn().query_row(
            "SELECT a.filename, ch.derived_text_id, ch.byte_offset_start,
                        ch.byte_offset_end, ws.final_url
             FROM chunks ch
             JOIN derived_text dt ON dt.id = ch.derived_text_id
             JOIN artifact_versions av ON av.id = dt.artifact_version_id
             JOIN artifacts a ON a.id = av.artifact_id
             LEFT JOIN web_sources ws ON ws.artifact_version_id = av.id
             WHERE ch.id = ?1",
            [hit.chunk_id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        let timestamp_range = crate::transcript::timestamp_range_for_derived_range(
            vault,
            &derived_text_id,
            start as u64,
            end as u64,
        )?;
        results.push(SearchResult {
            artifact_id: hit.artifact_id,
            artifact_title: title,
            chunk_id: hit.chunk_id,
            // For unit vectors, L2² = 2 − 2·cos ⇒ cos = 1 − d²/2.
            relevance_score: 1.0 - (hit.distance * hit.distance) / 2.0,
            byte_range: (start as u64, end as u64),
            timestamp_range,
            source_url,
        });
    }
    Ok(results)
}

/// Semantic search under the model's calibrated system floor.
pub fn query(
    vault: &Vault,
    embedder: &dyn EmbeddingProvider,
    text: &str,
    constraints: &RetrievalConstraints,
    top_k: usize,
) -> Result<Vec<SearchResult>, SearchError> {
    Ok(query_evaluated(vault, embedder, text, constraints, top_k, None)?.results)
}

/// Semantic search with diagnostics and an optional stricter caller floor.
pub fn query_evaluated(
    vault: &Vault,
    embedder: &dyn EmbeddingProvider,
    text: &str,
    constraints: &RetrievalConstraints,
    top_k: usize,
    stricter_floor: Option<f32>,
) -> Result<ThresholdedSearch, SearchError> {
    let system_floor = embedder
        .calibrated_relevance_floor()
        .ok_or_else(|| SearchError::UncalibratedModel(embedder.model_version().to_owned()))?;
    let threshold = stricter_floor
        .map(|requested| requested.max(system_floor))
        .unwrap_or(system_floor);
    let mut candidates = query_candidates(vault, embedder, text, constraints, top_k)?;
    let best_candidate_score = candidates
        .first()
        .map(|candidate| candidate.relevance_score);
    let candidates_considered = candidates.len() as u32;
    candidates.retain(|candidate| candidate.relevance_score >= threshold);
    let rejected_below_threshold = candidates_considered - candidates.len() as u32;
    Ok(ThresholdedSearch {
        results: candidates,
        diagnostics: SearchDiagnostics {
            relevance_threshold: threshold,
            candidates_considered,
            rejected_below_threshold,
            best_candidate_score,
        },
    })
}

/// Policy-filtered semantic search under a lens (#19). Compiles the lens into
/// retrieval constraints and runs the identical single-query path used by the
/// owner view — so the CLI `query --lens` and the guardian exercise the same
/// code. The quarantine invariant is enforced by the index regardless of lens.
pub fn search_with_lens(
    vault: &Vault,
    embedder: &dyn EmbeddingProvider,
    lens: &crate::lens::LensPolicy,
    text: &str,
    top_k: usize,
) -> Result<Vec<SearchResult>, SearchError> {
    Ok(search_with_lens_evaluated(vault, embedder, lens, text, top_k)?.results)
}

/// Lens retrieval with a model-calibrated, fail-closed relevance floor.
pub fn search_with_lens_evaluated(
    vault: &Vault,
    embedder: &dyn EmbeddingProvider,
    lens: &crate::lens::LensPolicy,
    text: &str,
    top_k: usize,
) -> Result<ThresholdedSearch, SearchError> {
    query_evaluated(
        vault,
        embedder,
        text,
        &lens.to_constraints(),
        top_k,
        lens.min_relevance_score,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{self, ArtifactState};
    use crate::crypto::KdfParams;
    use crate::lens::LensPolicy;
    use crate::space::{self, SpaceId};
    use crate::{chunk, extract, inbox};
    use std::path::Path;

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    /// Deterministic, model-free embedder: character-trigram hashing into
    /// 384 dims, L2-normalized. Similar texts share trigrams → similar
    /// vectors. Good enough to test plumbing and ranking end-to-end.
    struct FakeEmbedder;

    impl EmbeddingProvider for FakeEmbedder {
        fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
            let mut v = vec![0.0f32; 384];
            let lower = text.to_lowercase();
            let bytes = lower.as_bytes();
            for w in bytes.windows(3) {
                let h = (w[0] as usize * 31 * 31 + w[1] as usize * 31 + w[2] as usize) % 384;
                v[h] += 1.0;
            }
            let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm > 0.0 {
                for x in &mut v {
                    *x /= norm;
                }
            }
            Ok(v)
        }

        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
            texts.iter().map(|t| self.embed(t)).collect()
        }

        fn model_version(&self) -> &str {
            "fake-trigram@1"
        }

        fn dimensions(&self) -> usize {
            384
        }

        fn calibrated_relevance_floor(&self) -> Option<f32> {
            Some(0.0)
        }
    }

    struct FloorEmbedder(f32);
    impl EmbeddingProvider for FloorEmbedder {
        fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
            FakeEmbedder.embed(text)
        }
        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
            FakeEmbedder.embed_batch(texts)
        }
        fn model_version(&self) -> &str {
            "fake-trigram@1"
        }
        fn dimensions(&self) -> usize {
            384
        }
        fn calibrated_relevance_floor(&self) -> Option<f32> {
            Some(self.0)
        }
    }

    fn ingest_live(vault: &Vault, space: &SpaceId, dir: &Path, name: &str, body: &str) {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("write");
        inbox::add(vault, std::slice::from_ref(&path)).expect("add");
        let report = inbox::process(vault, space).expect("process");
        let artifact = report.ingested[0].1.clone();
        let derived = extract::extract_text(vault, &artifact)
            .expect("extract")
            .expect("text");
        chunk::chunk_derived_text(vault, &derived, &chunk::ChunkParams::default()).expect("chunk");
        artifact::set_state(vault, &artifact, ArtifactState::Live).expect("live");
    }

    fn corpus() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("create");
        let space = space::create(&vault, "Docs", None).expect("space");

        ingest_live(
            &vault,
            &space,
            dir.path(),
            "fire.md",
            "Fire safety requirements for corridor walls demand a two hour rating.",
        );
        ingest_live(
            &vault,
            &space,
            dir.path(),
            "recipe.md",
            "A recipe for sourdough bread with rye flour and long fermentation.",
        );
        (dir, vault)
    }

    #[test]
    fn embed_missing_indexes_all_chunks_once() {
        let (_dir, vault) = corpus();

        let embedded = embed_missing(&vault, &FakeEmbedder).expect("embed");
        assert_eq!(embedded, 2, "one chunk per small doc");

        let again = embed_missing(&vault, &FakeEmbedder).expect("re-embed");
        assert_eq!(again, 0, "second run must be a no-op");
    }

    #[test]
    fn reindex_is_resumable_and_preserves_active_index_until_complete() {
        let (_dir, vault) = corpus();
        embed_missing(&vault, &FakeEmbedder).expect("initial active index");
        let active_before: i64 = vault
            .conn()
            .query_row("SELECT COUNT(*) FROM embeddings_map", [], |r| r.get(0))
            .expect("active count");

        let partial = reindex(&vault, &FakeEmbedder, Some(1)).expect("partial reindex");
        assert_eq!(partial.status, "running");
        assert_eq!(partial.processed_chunks, 1);
        assert_eq!(partial.total_chunks, 2);
        let active_during: i64 = vault
            .conn()
            .query_row("SELECT COUNT(*) FROM embeddings_map", [], |r| r.get(0))
            .expect("active count");
        assert_eq!(
            active_during, active_before,
            "partial shadow replaced active index"
        );
        assert!(!query(
            &vault,
            &FakeEmbedder,
            "fire rating corridor",
            &owner_constraints(),
            5
        )
        .expect("active query during reindex")
        .is_empty());

        assert!(cancel_reindex(&vault).expect("cancel"));
        assert_eq!(
            reindex_progress(&vault).expect("progress").unwrap().status,
            "cancel_requested"
        );
        let completed = reindex(&vault, &FakeEmbedder, None).expect("resume and activate");
        assert_eq!(completed.status, "complete");
        assert_eq!(completed.processed_chunks, 2);
        assert_eq!(completed.total_chunks, 2);
        let active_after: i64 = vault
            .conn()
            .query_row("SELECT COUNT(*) FROM embeddings_map", [], |r| r.get(0))
            .expect("active count");
        assert_eq!(active_after, active_before);
    }

    #[test]
    fn embed_missing_registers_model_in_protected_metadata() {
        let (_dir, vault) = corpus();
        embed_missing(&vault, &FakeEmbedder).expect("embed");

        let models = vault.embedding_models().expect("model registry");
        assert!(
            models
                .iter()
                .any(|m| m.version == "fake-trigram@1" && m.dimensions == 384),
            "model registry missing entry: {:?}",
            models
        );
    }

    #[test]
    fn search_with_lens_scopes_to_included_space() {
        let (_dir, vault) = corpus();
        embed_missing(&vault, &FakeEmbedder).expect("embed");
        let space = space::list(&vault).expect("list")[0].id.clone();

        // A lens including the docs space retrieves the topical doc.
        let mut lens = LensPolicy::new("Docs", vec![space.clone()]);
        lens.sensitivity_ceiling = Sensitivity::Restricted;
        let results = search_with_lens(
            &vault,
            &FakeEmbedder,
            &lens,
            "fire rating corridor walls",
            5,
        )
        .expect("query");
        assert!(!results.is_empty());
        assert_eq!(results[0].artifact_title, "fire.md");

        // A lens excluding that same space yields nothing (exclude wins).
        let mut blocked = LensPolicy::new("None", vec![space.clone()]);
        blocked.space_exclude_ids = vec![space];
        blocked.sensitivity_ceiling = Sensitivity::Restricted;
        let none =
            search_with_lens(&vault, &FakeEmbedder, &blocked, "fire rating", 5).expect("query");
        assert!(none.is_empty(), "excluded space must yield no results");
    }

    #[test]
    fn relevance_floor_is_inclusive_and_lens_can_only_raise_it() {
        let (_dir, vault) = corpus();
        embed_missing(&vault, &FakeEmbedder).expect("embed");
        let space = space::list(&vault).expect("list")[0].id.clone();
        let mut lens = LensPolicy::new("Docs", vec![space]);
        lens.sensitivity_ceiling = Sensitivity::Restricted;

        let raw = query_candidates(
            &vault,
            &FakeEmbedder,
            "fire rating corridor walls",
            &lens.to_constraints(),
            2,
        )
        .expect("raw query");
        let best = raw[0].relevance_score;

        lens.min_relevance_score = Some(best);
        let boundary = search_with_lens_evaluated(
            &vault,
            &FakeEmbedder,
            &lens,
            "fire rating corridor walls",
            2,
        )
        .expect("boundary query");
        assert_eq!(boundary.results.len(), 1, "score equal to floor must pass");
        assert_eq!(boundary.diagnostics.relevance_threshold, best);

        lens.min_relevance_score = Some(best + f32::EPSILON);
        let above = search_with_lens_evaluated(
            &vault,
            &FakeEmbedder,
            &lens,
            "fire rating corridor walls",
            2,
        )
        .expect("above-boundary query");
        assert!(
            above.results.is_empty(),
            "score below floor must be rejected"
        );
        assert_eq!(above.diagnostics.rejected_below_threshold, 2);

        lens.min_relevance_score = Some(-1.0);
        let cannot_lower = search_with_lens_evaluated(
            &vault,
            &FakeEmbedder,
            &lens,
            "fire rating corridor walls",
            2,
        )
        .expect("system-floor query");
        assert_eq!(cannot_lower.diagnostics.relevance_threshold, 0.0);
    }

    #[test]
    fn unrelated_query_below_floor_discloses_nothing() {
        let (_dir, vault) = corpus();
        embed_missing(&vault, &FakeEmbedder).expect("embed");
        let space = space::list(&vault).expect("list")[0].id.clone();
        let mut lens = LensPolicy::new("Docs", vec![space]);
        lens.sensitivity_ceiling = Sensitivity::Restricted;

        let evaluated = search_with_lens_evaluated(
            &vault,
            &FloorEmbedder(0.2),
            &lens,
            "quantum orbital spectroscopy",
            2,
        )
        .expect("query");
        assert!(evaluated.results.is_empty());
        assert_eq!(evaluated.diagnostics.relevance_threshold, 0.2);
        assert_eq!(evaluated.diagnostics.candidates_considered, 2);
        assert_eq!(evaluated.diagnostics.rejected_below_threshold, 2);
        assert!(evaluated.diagnostics.best_candidate_score.is_some());
    }

    #[test]
    fn model_without_calibration_fails_closed_before_index_access() {
        struct Uncalibrated;
        impl EmbeddingProvider for Uncalibrated {
            fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
                FakeEmbedder.embed(text)
            }
            fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
                FakeEmbedder.embed_batch(texts)
            }
            fn model_version(&self) -> &str {
                "uncalibrated@1"
            }
            fn dimensions(&self) -> usize {
                384
            }
        }

        let (_dir, vault) = corpus();
        let lens = LensPolicy::new("Docs", vec![]);
        let error = search_with_lens_evaluated(&vault, &Uncalibrated, &lens, "anything", 5)
            .expect_err("unknown calibration must refuse");
        assert!(
            matches!(error, SearchError::UncalibratedModel(model) if model == "uncalibrated@1")
        );
    }

    #[test]
    fn query_ranks_topically_and_cites() {
        let (_dir, vault) = corpus();
        embed_missing(&vault, &FakeEmbedder).expect("embed");

        let results = query(
            &vault,
            &FakeEmbedder,
            "fire rating requirements corridor walls",
            &owner_constraints(),
            2,
        )
        .expect("query");

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].artifact_title, "fire.md", "topical doc first");
        assert!(results[0].relevance_score > results[1].relevance_score);
        let (start, end) = results[0].byte_range;
        assert!(end > start, "citation byte range must be non-empty");
    }
}
