//! Golden-set retrieval evaluation — the instrument for the v0.0 gate.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::embed::EmbeddingProvider;
use crate::index::RetrievalConstraints;
use crate::search::{self, SearchError};
use crate::vault::Vault;

#[derive(Error, Debug)]
pub enum EvalError {
    #[error("golden set is empty")]
    EmptyGoldenSet,
    #[error("golden set parse error: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("search error: {0}")]
    Search(#[from] SearchError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// One golden question: the query and the filenames of artifacts that a
/// good retrieval should surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenItem {
    pub question: String,
    pub expected: Vec<String>,
}

/// Per-question outcome (for debugging poor retrieval).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionResult {
    pub question: String,
    pub recall_at_5: f64,
    pub recall_at_10: f64,
    /// Reciprocal rank of the first expected artifact (0 when absent).
    pub reciprocal_rank: f64,
}

/// Aggregate evaluation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalReport {
    pub questions: usize,
    pub recall_at_5: f64,
    pub recall_at_10: f64,
    pub mrr: f64,
    pub per_question: Vec<QuestionResult>,
}

/// Parse a golden set from JSON (array of GoldenItem).
pub fn parse_golden(json: &str) -> Result<Vec<GoldenItem>, EvalError> {
    let items: Vec<GoldenItem> = serde_json::from_str(json)?;
    if items.is_empty() {
        return Err(EvalError::EmptyGoldenSet);
    }
    Ok(items)
}

/// Run the golden set against the vault using owner-view retrieval.
pub fn run(
    vault: &Vault,
    embedder: &dyn EmbeddingProvider,
    golden: &[GoldenItem],
    constraints: &RetrievalConstraints,
) -> Result<EvalReport, EvalError> {
    if golden.is_empty() {
        return Err(EvalError::EmptyGoldenSet);
    }

    let mut per_question = Vec::with_capacity(golden.len());
    for item in golden {
        let results = search::query(vault, embedder, &item.question, constraints, 10)?;
        // Rank of unique artifacts (a doc may contribute several chunks).
        let mut ranked_titles: Vec<String> = Vec::new();
        for r in &results {
            if !ranked_titles.contains(&r.artifact_title) {
                ranked_titles.push(r.artifact_title.clone());
            }
        }

        let recall_at = |k: usize| -> f64 {
            if item.expected.is_empty() {
                return 1.0;
            }
            let top: &[String] = &ranked_titles[..ranked_titles.len().min(k)];
            let found = item.expected.iter().filter(|e| top.contains(e)).count();
            found as f64 / item.expected.len() as f64
        };
        let reciprocal_rank = ranked_titles
            .iter()
            .position(|t| item.expected.contains(t))
            .map(|idx| 1.0 / (idx as f64 + 1.0))
            .unwrap_or(0.0);

        per_question.push(QuestionResult {
            question: item.question.clone(),
            recall_at_5: recall_at(5),
            recall_at_10: recall_at(10),
            reciprocal_rank,
        });
    }

    let n = per_question.len() as f64;
    Ok(EvalReport {
        questions: per_question.len(),
        recall_at_5: per_question.iter().map(|q| q.recall_at_5).sum::<f64>() / n,
        recall_at_10: per_question.iter().map(|q| q.recall_at_10).sum::<f64>() / n,
        mrr: per_question.iter().map(|q| q.reciprocal_rank).sum::<f64>() / n,
        per_question,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reuse the search test fixtures via a local copy of the fake embedder
    // (kept deliberately identical to search::tests::FakeEmbedder).
    use crate::artifact::{self, ArtifactState};
    use crate::crypto::KdfParams;
    use crate::embed::EmbedError;
    use crate::space::{self, SpaceId};
    use crate::{chunk, extract, inbox};
    use std::path::Path;

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    struct FakeEmbedder;
    impl EmbeddingProvider for FakeEmbedder {
        fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
            let mut v = vec![0.0f32; 384];
            let lower = text.to_lowercase();
            for w in lower.as_bytes().windows(3) {
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
            Some(0.2)
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

    fn eval_vault() -> (tempfile::TempDir, Vault) {
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
            "bread.md",
            "Sourdough bread with rye flour needs a long slow fermentation.",
        );
        crate::search::embed_missing(&vault, &FakeEmbedder).expect("embed");
        (dir, vault)
    }

    #[test]
    fn perfect_retrieval_scores_one() {
        let (_dir, vault) = eval_vault();
        let golden = vec![GoldenItem {
            question: "fire rating requirements corridor walls".into(),
            expected: vec!["fire.md".into()],
        }];

        let report = run(
            &vault,
            &FakeEmbedder,
            &golden,
            &crate::search::owner_constraints(),
        )
        .expect("run");
        assert_eq!(report.questions, 1);
        assert!((report.recall_at_10 - 1.0).abs() < f64::EPSILON);
        assert!(
            (report.mrr - 1.0).abs() < f64::EPSILON,
            "fire.md must rank first"
        );
    }

    #[test]
    fn missing_expected_scores_zero() {
        let (_dir, vault) = eval_vault();
        let golden = vec![GoldenItem {
            question: "fire rating requirements".into(),
            expected: vec!["does-not-exist.md".into()],
        }];

        let report = run(
            &vault,
            &FakeEmbedder,
            &golden,
            &crate::search::owner_constraints(),
        )
        .expect("run");
        assert_eq!(report.recall_at_10, 0.0);
        assert_eq!(report.mrr, 0.0);
    }

    #[test]
    fn lens_filtering_preserves_recall_within_budget() {
        use crate::lens::LensPolicy;

        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("create");
        let work = space::create(&vault, "Work", None).expect("work");
        let personal = space::create(&vault, "Personal", None).expect("personal");

        // Relevant docs live in Work; distractors live in Personal.
        ingest_live(
            &vault,
            &work,
            dir.path(),
            "fire.md",
            "Fire safety requirements for corridor walls demand a two hour rating.",
        );
        ingest_live(
            &vault,
            &work,
            dir.path(),
            "egress.md",
            "Emergency egress routes and exit door widths depend on occupant load.",
        );
        ingest_live(
            &vault,
            &personal,
            dir.path(),
            "bread.md",
            "Sourdough bread with rye flour needs a long slow fermentation.",
        );
        ingest_live(
            &vault,
            &personal,
            dir.path(),
            "garden.md",
            "Tomato seedlings need hardening off before transplanting outdoors.",
        );
        crate::search::embed_missing(&vault, &FakeEmbedder).expect("embed");

        let golden = vec![
            GoldenItem {
                question: "fire rating requirements corridor walls".into(),
                expected: vec!["fire.md".into()],
            },
            GoldenItem {
                question: "emergency egress exit door widths".into(),
                expected: vec!["egress.md".into()],
            },
        ];

        let unfiltered = run(
            &vault,
            &FakeEmbedder,
            &golden,
            &crate::search::owner_constraints(),
        )
        .expect("unfiltered");

        let mut lens = LensPolicy::new("Work", vec![work]);
        lens.sensitivity_ceiling = crate::artifact::Sensitivity::Restricted;
        let filtered =
            run(&vault, &FakeEmbedder, &golden, &lens.to_constraints()).expect("filtered");

        assert!(
            unfiltered.recall_at_10 > 0.0,
            "unfiltered baseline must retrieve the expected docs"
        );
        // Acceptance (#19): policy filtering degrades Recall@10 by < 10%.
        assert!(
            filtered.recall_at_10 >= unfiltered.recall_at_10 * 0.9,
            "lens filtering degraded Recall@10 by >10%: unfiltered={:.3} filtered={:.3}",
            unfiltered.recall_at_10,
            filtered.recall_at_10
        );
    }

    #[test]
    fn golden_parsing_rejects_empty() {
        assert!(matches!(parse_golden("[]"), Err(EvalError::EmptyGoldenSet)));
        let items = parse_golden(r#"[{"question": "q", "expected": ["a.md"]}]"#).expect("parse");
        assert_eq!(items[0].expected, vec!["a.md"]);
    }
}
