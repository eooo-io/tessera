//! sqlite-vec implementation of `VectorIndex`.
//!
//! Vectors live in the `chunk_embeddings` vec0 virtual table inside
//! vault.db; policy filtering happens in the same SQL statement as the KNN
//! scan. The quarantine invariant (`state = 'live'`) is hard-coded into the
//! query and cannot be disabled by any constraint combination.

use crate::artifact::{ArtifactId, Sensitivity};
use crate::vault::Vault;

use super::{ChunkRef, IndexError, RetrievalConstraints, VectorIndex};

pub const DIMENSIONS: usize = 384;
/// KNN over-fetch cap: one retry ladder step never exceeds this.
const MAX_KNN: usize = 4096;

/// sqlite-vec backed index bound to one vault and one embedding model.
pub struct SqliteVecIndex<'v> {
    vault: &'v Vault,
    model_version: String,
}

impl<'v> SqliteVecIndex<'v> {
    pub fn new(vault: &'v Vault, model_version: &str) -> Self {
        Self {
            vault,
            model_version: model_version.to_owned(),
        }
    }

    /// Refuse to operate when the map contains vectors from a different
    /// model version (actionable error instead of silently mixed spaces).
    fn ensure_single_model(&self) -> Result<(), IndexError> {
        let foreign: Option<String> = self
            .vault
            .conn()
            .query_row(
                "SELECT model_version FROM embeddings_map WHERE model_version != ?1 LIMIT 1",
                [self.model_version.as_str()],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(IndexError::Database(other.to_string())),
            })?;
        if let Some(found) = foreign {
            return Err(IndexError::UnknownModel(format!(
                "index contains vectors from '{found}' but this session uses \
                 '{}' — re-embed the vault before mixing models",
                self.model_version
            )));
        }
        Ok(())
    }

    fn encode(embedding: &[f32]) -> Result<Vec<u8>, IndexError> {
        if embedding.len() != DIMENSIONS {
            return Err(IndexError::DimensionMismatch {
                expected: DIMENSIONS,
                found: embedding.len(),
            });
        }
        Ok(embedding.iter().flat_map(|f| f.to_le_bytes()).collect())
    }
}

impl Sensitivity {
    /// Ordering rank for ceiling comparisons.
    pub fn rank(&self) -> u8 {
        match self {
            Sensitivity::Public => 0,
            Sensitivity::Internal => 1,
            Sensitivity::Confidential => 2,
            Sensitivity::Restricted => 3,
        }
    }
}

impl VectorIndex for SqliteVecIndex<'_> {
    fn insert(&mut self, chunk_id: &str, embedding: &[f32]) -> Result<(), IndexError> {
        self.ensure_single_model()?;
        let blob = Self::encode(embedding)?;
        let conn = self.vault.conn();
        let db = |e: rusqlite::Error| IndexError::Database(e.to_string());

        conn.execute(
            "INSERT INTO chunk_embeddings (embedding) VALUES (?1)",
            rusqlite::params![blob],
        )
        .map_err(db)?;
        let rowid = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO embeddings_map (chunk_id, vec_rowid, model_version, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                chunk_id,
                rowid,
                self.model_version,
                chrono::Utc::now().to_rfc3339()
            ],
        )
        .map_err(db)?;
        Ok(())
    }

    fn delete(&mut self, chunk_id: &str) -> Result<(), IndexError> {
        let conn = self.vault.conn();
        let db = |e: rusqlite::Error| IndexError::Database(e.to_string());

        let rowid: i64 = conn
            .query_row(
                "SELECT vec_rowid FROM embeddings_map WHERE chunk_id = ?1",
                [chunk_id],
                |r| r.get(0),
            )
            .map_err(db)?;
        conn.execute(
            "DELETE FROM chunk_embeddings WHERE rowid = ?1",
            rusqlite::params![rowid],
        )
        .map_err(db)?;
        conn.execute(
            "DELETE FROM embeddings_map WHERE chunk_id = ?1",
            rusqlite::params![chunk_id],
        )
        .map_err(db)?;
        Ok(())
    }

    fn search(
        &self,
        query: &[f32],
        constraints: &RetrievalConstraints,
        k: usize,
    ) -> Result<Vec<ChunkRef>, IndexError> {
        self.ensure_single_model()?;
        let blob = Self::encode(query)?;
        let total = self.len()?;
        if total == 0 || k == 0 {
            return Ok(Vec::new());
        }

        // Over-fetch ladder: start generous; widen only if the policy join
        // under-fills. Each attempt is still ONE SQL statement.
        let mut knn_k = (k * 4).clamp(64, MAX_KNN).min(total.max(1));
        loop {
            let hits = self.search_once(&blob, constraints, knn_k, k)?;
            if hits.len() >= k || knn_k >= total || knn_k >= MAX_KNN {
                return Ok(hits);
            }
            knn_k = (knn_k * 4).min(total).min(MAX_KNN);
        }
    }

    fn len(&self) -> Result<usize, IndexError> {
        let count: i64 = self
            .vault
            .conn()
            .query_row("SELECT COUNT(*) FROM embeddings_map", [], |r| r.get(0))
            .map_err(|e| IndexError::Database(e.to_string()))?;
        Ok(count as usize)
    }
}

impl SqliteVecIndex<'_> {
    /// One KNN + policy-join statement. The `a.state = 'live'` predicate is
    /// part of the fixed SQL text — no constraint can remove it.
    fn search_once(
        &self,
        query_blob: &[u8],
        c: &RetrievalConstraints,
        knn_k: usize,
        top_k: usize,
    ) -> Result<Vec<ChunkRef>, IndexError> {
        let mut sql = String::from(
            "SELECT ch.id, av.artifact_id, knn.distance
             FROM (SELECT rowid, distance FROM chunk_embeddings
                   WHERE embedding MATCH ?1 AND k = ?2) AS knn
             JOIN embeddings_map em ON em.vec_rowid = knn.rowid
             JOIN chunks ch ON ch.id = em.chunk_id
             JOIN derived_text dt ON dt.id = ch.derived_text_id
             JOIN artifact_versions av ON av.id = dt.artifact_version_id
             JOIN artifacts a ON a.id = av.artifact_id
             WHERE a.state = 'live'
               AND (CASE a.sensitivity
                      WHEN 'public' THEN 0 WHEN 'internal' THEN 1
                      WHEN 'confidential' THEN 2 ELSE 3 END) <= ?3",
        );
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![
            Box::new(query_blob.to_vec()),
            Box::new(knn_k as i64),
            Box::new(c.sensitivity_ceiling.rank() as i64),
        ];

        let mut add_in = |sql: &mut String, column: &str, values: &[String], negate: bool| {
            if values.is_empty() {
                return;
            }
            let placeholders: Vec<String> = values
                .iter()
                .map(|v| {
                    params.push(Box::new(v.clone()));
                    format!("?{}", params.len())
                })
                .collect();
            sql.push_str(&format!(
                " AND {column} {}IN ({})",
                if negate { "NOT " } else { "" },
                placeholders.join(", ")
            ));
        };

        let space_ids: Vec<String> = c.space_ids.iter().map(|s| s.0.clone()).collect();
        let space_excl: Vec<String> = c.space_exclude_ids.iter().map(|s| s.0.clone()).collect();
        add_in(&mut sql, "a.space_id", &space_ids, false);
        add_in(&mut sql, "a.space_id", &space_excl, true);
        add_in(&mut sql, "a.media_type", &c.media_types, false);

        if !c.tag_include.is_empty() {
            let placeholders: Vec<String> = c
                .tag_include
                .iter()
                .map(|t| {
                    params.push(Box::new(t.clone()));
                    format!("?{}", params.len())
                })
                .collect();
            sql.push_str(&format!(
                " AND EXISTS (SELECT 1 FROM artifact_tags at JOIN tags t ON t.id = at.tag_id
                              WHERE at.artifact_id = a.id AND t.name IN ({}))",
                placeholders.join(", ")
            ));
        }
        if !c.tag_exclude.is_empty() {
            let placeholders: Vec<String> = c
                .tag_exclude
                .iter()
                .map(|t| {
                    params.push(Box::new(t.clone()));
                    format!("?{}", params.len())
                })
                .collect();
            sql.push_str(&format!(
                " AND NOT EXISTS (SELECT 1 FROM artifact_tags at JOIN tags t ON t.id = at.tag_id
                                  WHERE at.artifact_id = a.id AND t.name IN ({}))",
                placeholders.join(", ")
            ));
        }

        params.push(Box::new(top_k as i64));
        sql.push_str(&format!(" ORDER BY knn.distance LIMIT ?{}", params.len()));

        let conn = self.vault.conn();
        let db = |e: rusqlite::Error| IndexError::Database(e.to_string());
        let mut stmt = conn.prepare(&sql).map_err(db)?;
        let refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let hits = stmt
            .query_map(refs.as_slice(), |row| {
                Ok(ChunkRef {
                    chunk_id: row.get(0)?,
                    artifact_id: ArtifactId(row.get(1)?),
                    distance: row.get(2)?,
                })
            })
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?;
        Ok(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{self, ArtifactId, ArtifactState};
    use crate::crypto::KdfParams;
    use crate::space::{self, SpaceId};
    use crate::{chunk, extract, inbox};
    use std::path::Path;

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    /// Deterministic synthetic embedding: three seed values in the first
    /// dims, L2-normalized. No model needed — runs everywhere.
    fn synth(a: f32, b: f32, c: f32) -> Vec<f32> {
        let mut v = vec![0.0f32; DIMENSIONS];
        v[0] = a;
        v[1] = b;
        v[2] = c;
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in &mut v {
                *x /= norm;
            }
        }
        v
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        vault: Vault,
        space_a: SpaceId,
        space_b: SpaceId,
        art_a: ArtifactId, // live, space A, tagged "spec", internal, md
        art_b: ArtifactId, // live, space B, tagged "journal", confidential, txt
        chunk_a: String,
        chunk_b: String,
    }

    fn ingest_one(
        vault: &Vault,
        space: &SpaceId,
        dir: &Path,
        name: &str,
        body: &str,
    ) -> (ArtifactId, String) {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("write");
        inbox::add(vault, std::slice::from_ref(&path)).expect("add");
        let report = inbox::process(vault, space).expect("process");
        let artifact = report.ingested[0].1.clone();
        let derived = extract::extract_text(vault, &artifact)
            .expect("extract")
            .expect("text");
        let chunks = chunk::chunk_derived_text(vault, &derived, &chunk::ChunkParams::default())
            .expect("chunk");
        (artifact, chunks[0].id.clone())
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("create vault");
        let space_a = space::create(&vault, "A", None).expect("space A");
        let space_b = space::create(&vault, "B", None).expect("space B");

        let (art_a, chunk_a) = ingest_one(&vault, &space_a, dir.path(), "a.md", "Alpha body text.");
        let (art_b, chunk_b) = ingest_one(&vault, &space_b, dir.path(), "b.txt", "Beta body text.");

        artifact::tag(&vault, &art_a, "spec").expect("tag a");
        artifact::tag(&vault, &art_b, "journal").expect("tag b");
        artifact::set_sensitivity(&vault, &art_b, Sensitivity::Confidential).expect("sens b");
        artifact::set_state(&vault, &art_a, ArtifactState::Live).expect("live a");
        artifact::set_state(&vault, &art_b, ArtifactState::Live).expect("live b");

        let mut index = SqliteVecIndex::new(&vault, "synth@1");
        index
            .insert(&chunk_a, &synth(1.0, 0.0, 0.0))
            .expect("ins a");
        index
            .insert(&chunk_b, &synth(0.0, 1.0, 0.0))
            .expect("ins b");

        Fixture {
            _dir: dir,
            vault,
            space_a,
            space_b,
            art_a,
            art_b,
            chunk_a,
            chunk_b,
        }
    }

    fn open_constraints() -> RetrievalConstraints {
        RetrievalConstraints {
            sensitivity_ceiling: Sensitivity::Restricted,
            ..Default::default()
        }
    }

    #[test]
    fn nearest_neighbor_ordering() {
        let f = fixture();
        let index = SqliteVecIndex::new(&f.vault, "synth@1");

        // Query close to B's vector.
        let hits = index
            .search(&synth(0.1, 1.0, 0.0), &open_constraints(), 2)
            .expect("search");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].chunk_id, f.chunk_b, "closest first");
        assert_eq!(hits[0].artifact_id, f.art_b);
        assert!(hits[0].distance < hits[1].distance);
    }

    #[test]
    fn quarantined_content_never_surfaces() {
        let f = fixture();
        // A pending artifact whose vector is nearly identical to the query.
        let dir = tempfile::tempdir().expect("tempdir");
        let (art_p, chunk_p) = ingest_one(
            &f.vault,
            &f.space_a,
            dir.path(),
            "pending.md",
            "Pending secret body.",
        );
        assert_eq!(
            artifact::get(&f.vault, &art_p).expect("get").state,
            ArtifactState::Pending
        );
        let mut index = SqliteVecIndex::new(&f.vault, "synth@1");
        index.insert(&chunk_p, &synth(0.09, 1.0, 0.0)).expect("ins");

        let hits = index
            .search(&synth(0.1, 1.0, 0.0), &open_constraints(), 10)
            .expect("search");
        assert!(
            hits.iter().all(|h| h.chunk_id != chunk_p),
            "pending chunk leaked into results"
        );
        assert!(hits.iter().any(|h| h.chunk_id == f.chunk_b));

        // Archived content is equally invisible.
        artifact::set_state(&f.vault, &art_p, ArtifactState::Archived).expect("archive");
        let hits = index
            .search(&synth(0.1, 1.0, 0.0), &open_constraints(), 10)
            .expect("search");
        assert!(hits.iter().all(|h| h.chunk_id != chunk_p));
    }

    #[test]
    fn space_include_and_exclude() {
        let f = fixture();
        let index = SqliteVecIndex::new(&f.vault, "synth@1");
        let query = synth(0.5, 0.5, 0.0);

        let only_a = RetrievalConstraints {
            space_ids: vec![f.space_a.clone()],
            sensitivity_ceiling: Sensitivity::Restricted,
            ..Default::default()
        };
        let hits = index.search(&query, &only_a, 10).expect("search");
        assert!(hits.iter().all(|h| h.artifact_id == f.art_a));
        assert!(!hits.is_empty());

        let exclude_b = RetrievalConstraints {
            space_exclude_ids: vec![f.space_b.clone()],
            sensitivity_ceiling: Sensitivity::Restricted,
            ..Default::default()
        };
        let hits = index.search(&query, &exclude_b, 10).expect("search");
        assert!(hits.iter().all(|h| h.artifact_id != f.art_b));

        // Exclude overrides include.
        let both = RetrievalConstraints {
            space_ids: vec![f.space_a.clone(), f.space_b.clone()],
            space_exclude_ids: vec![f.space_b.clone()],
            sensitivity_ceiling: Sensitivity::Restricted,
            ..Default::default()
        };
        let hits = index.search(&query, &both, 10).expect("search");
        assert!(hits.iter().all(|h| h.artifact_id != f.art_b));
    }

    #[test]
    fn sensitivity_ceiling_filters() {
        let f = fixture();
        let index = SqliteVecIndex::new(&f.vault, "synth@1");

        let internal_only = RetrievalConstraints {
            sensitivity_ceiling: Sensitivity::Internal,
            ..Default::default()
        };
        let hits = index
            .search(&synth(0.5, 0.5, 0.0), &internal_only, 10)
            .expect("search");
        assert!(
            hits.iter().all(|h| h.artifact_id != f.art_b),
            "confidential artifact leaked past internal ceiling"
        );
        assert!(hits.iter().any(|h| h.artifact_id == f.art_a));
    }

    #[test]
    fn tag_include_and_exclude() {
        let f = fixture();
        let index = SqliteVecIndex::new(&f.vault, "synth@1");
        let query = synth(0.5, 0.5, 0.0);

        let specs_only = RetrievalConstraints {
            tag_include: vec!["spec".into()],
            sensitivity_ceiling: Sensitivity::Restricted,
            ..Default::default()
        };
        let hits = index.search(&query, &specs_only, 10).expect("search");
        assert!(!hits.is_empty());
        assert!(hits.iter().all(|h| h.artifact_id == f.art_a));

        let no_journal = RetrievalConstraints {
            tag_exclude: vec!["journal".into()],
            sensitivity_ceiling: Sensitivity::Restricted,
            ..Default::default()
        };
        let hits = index.search(&query, &no_journal, 10).expect("search");
        assert!(hits.iter().all(|h| h.artifact_id != f.art_b));
    }

    #[test]
    fn media_type_filter() {
        let f = fixture();
        let index = SqliteVecIndex::new(&f.vault, "synth@1");

        let md_only = RetrievalConstraints {
            media_types: vec!["text/markdown".into()],
            sensitivity_ceiling: Sensitivity::Restricted,
            ..Default::default()
        };
        let hits = index
            .search(&synth(0.5, 0.5, 0.0), &md_only, 10)
            .expect("search");
        assert!(!hits.is_empty());
        assert!(hits.iter().all(|h| h.artifact_id == f.art_a));
    }

    #[test]
    fn delete_removes_from_results_and_len() {
        let f = fixture();
        let mut index = SqliteVecIndex::new(&f.vault, "synth@1");
        assert_eq!(index.len().expect("len"), 2);

        index.delete(&f.chunk_b).expect("delete");
        assert_eq!(index.len().expect("len"), 1);
        let hits = index
            .search(&synth(0.0, 1.0, 0.0), &open_constraints(), 10)
            .expect("search");
        assert!(hits.iter().all(|h| h.chunk_id != f.chunk_b));
    }

    #[test]
    fn reopened_vault_preserves_index() {
        let f = fixture();
        let path = f.vault.path().to_path_buf();
        let chunk_a = f.chunk_a.clone();
        // Close the vault handle but keep the temp directory alive.
        let Fixture { _dir, vault, .. } = f;
        drop(vault);

        let vault = Vault::open(&path, "pass").expect("reopen");
        let index = SqliteVecIndex::new(&vault, "synth@1");
        assert_eq!(index.len().expect("len"), 2);
        let hits = index
            .search(&synth(1.0, 0.0, 0.0), &open_constraints(), 1)
            .expect("search");
        assert_eq!(hits[0].chunk_id, chunk_a);
    }

    #[test]
    fn mixed_model_versions_are_refused() {
        let f = fixture();
        let mut other = SqliteVecIndex::new(&f.vault, "other-model@9");

        assert!(matches!(
            other.search(&synth(1.0, 0.0, 0.0), &open_constraints(), 1),
            Err(IndexError::UnknownModel(_))
        ));
        assert!(matches!(
            other.insert("chunk_x", &synth(1.0, 0.0, 0.0)),
            Err(IndexError::UnknownModel(_))
        ));
    }

    #[test]
    fn wrong_dimensions_are_rejected() {
        let f = fixture();
        let mut index = SqliteVecIndex::new(&f.vault, "synth@1");
        assert!(matches!(
            index.insert("chunk_y", &[1.0, 2.0]),
            Err(IndexError::DimensionMismatch { .. })
        ));
    }
}
