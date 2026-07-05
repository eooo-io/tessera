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
}

/// A single search result with citation metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub artifact_id: crate::artifact::ArtifactId,
    pub artifact_title: String,
    pub chunk_id: String,
    pub relevance_score: f32,
    pub byte_range: (u64, u64),
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

    // Record the model in the manifest registry so a fresh guardian on
    // another machine knows what produced these vectors.
    let manifest_path = vault.path().join("tessera.json");
    let mut manifest =
        crate::vault::VaultManifest::load(&manifest_path).map_err(VaultError::Manifest)?;
    let version = embedder.model_version();
    if !manifest
        .embedding_models
        .iter()
        .any(|m| m.version == version)
    {
        manifest
            .embedding_models
            .push(crate::vault::EmbeddingModelEntry {
                name: version.split('@').next().unwrap_or(version).to_owned(),
                version: version.to_owned(),
                dimensions: embedder.dimensions() as u32,
            });
        manifest
            .save(&manifest_path)
            .map_err(VaultError::Manifest)?;
    }
    Ok(count)
}

/// Semantic search: embed the query, run the policy-filtered KNN, hydrate
/// results with artifact titles and citation byte ranges.
pub fn query(
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
        let (title, start, end): (String, i64, i64) = vault.conn().query_row(
            "SELECT a.filename, ch.byte_offset_start, ch.byte_offset_end
             FROM chunks ch
             JOIN derived_text dt ON dt.id = ch.derived_text_id
             JOIN artifact_versions av ON av.id = dt.artifact_version_id
             JOIN artifacts a ON a.id = av.artifact_id
             WHERE ch.id = ?1",
            [hit.chunk_id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        results.push(SearchResult {
            artifact_id: hit.artifact_id,
            artifact_title: title,
            chunk_id: hit.chunk_id,
            // For unit vectors, L2² = 2 − 2·cos ⇒ cos = 1 − d²/2.
            relevance_score: 1.0 - (hit.distance * hit.distance) / 2.0,
            byte_range: (start as u64, end as u64),
        });
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{self, ArtifactState};
    use crate::crypto::KdfParams;
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
    fn embed_missing_registers_model_in_manifest() {
        let (_dir, vault) = corpus();
        embed_missing(&vault, &FakeEmbedder).expect("embed");

        let manifest =
            crate::vault::VaultManifest::load(&vault.path().join("tessera.json")).expect("load");
        assert!(
            manifest
                .embedding_models
                .iter()
                .any(|m| m.version == "fake-trigram@1" && m.dimensions == 384),
            "model registry missing entry: {:?}",
            manifest.embedding_models
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
