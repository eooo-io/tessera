//! Local-only, receipt-backed private corpus evaluation for the v0.1 gate.

use std::collections::{BTreeSet, HashSet};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::EvalError;
use crate::artifact::ArtifactState;
use crate::embed::EmbeddingProvider;
use crate::lens::{self, DisclosureMode, LensId};
use crate::receipt::{self, AgentRef, QueryOutcome, Session};
use crate::vault::Vault;

const PLAN_SCHEMA: &str = include_str!("../../../../spec/private-eval-plan.schema.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateEvalPlan {
    pub schema_version: String,
    pub plan_id: String,
    pub reviewed_by: String,
    pub review_date: String,
    pub thresholds: PrivateThresholds,
    pub questions: Vec<PrivateQuestion>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivateThresholds {
    pub min_recall_at_10: f64,
    pub min_no_answer_precision: f64,
    pub min_no_answer_recall: f64,
    pub max_policy_leakage: u32,
    pub max_quarantine_leakage: u32,
    pub max_stale_retrieval_rate: f64,
    pub min_citation_reconstruction: f64,
    pub min_receipt_verification: f64,
}

pub const V01_THRESHOLDS: PrivateThresholds = PrivateThresholds {
    min_recall_at_10: 0.80,
    min_no_answer_precision: 0.80,
    min_no_answer_recall: 0.80,
    max_policy_leakage: 0,
    max_quarantine_leakage: 0,
    max_stale_retrieval_rate: 0.05,
    min_citation_reconstruction: 1.0,
    min_receipt_verification: 1.0,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateQuestion {
    pub id: String,
    pub query: String,
    pub lens_id: String,
    pub category: String,
    pub expected_disclosure_mode: DisclosureMode,
    pub severity: String,
    pub rationale: String,
    pub reviewed_at: String,
    pub expected_sources: Vec<ExpectedSource>,
    pub blocked_space_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExpectedSource {
    pub artifact_id: String,
    pub artifact_version_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateEvalReport {
    pub schema_version: String,
    pub plan_checksum: String,
    pub corpus_manifest_checksum: String,
    pub run_at: chrono::DateTime<chrono::Utc>,
    pub model_version: String,
    pub index_version: String,
    pub runtime_os: String,
    pub runtime_arch: String,
    pub corpus_artifacts: u64,
    pub corpus_versions: u64,
    pub corpus_chunks: u64,
    pub lens_count: u32,
    pub lens_set_checksum: String,
    pub questions: u32,
    pub answerable_questions: u32,
    pub no_answer_questions: u32,
    pub recall_at_5: f64,
    pub recall_at_10: f64,
    pub mrr: f64,
    pub no_answer_precision: f64,
    pub no_answer_recall: f64,
    pub policy_leakage_count: u32,
    pub quarantine_leakage_count: u32,
    pub failed_query_count: u32,
    pub disclosure_mismatch_count: u32,
    pub stale_retrieval_rate: f64,
    pub citation_reconstruction_rate: f64,
    pub receipt_verification_rate: f64,
    pub receipt_chain_verified: bool,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub thresholds: PrivateThresholds,
    pub failures: Vec<SafeFailure>,
    pub recommendation: Recommendation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeFailure {
    pub question_id: String,
    pub category: String,
    pub severity: String,
    pub failure_kinds: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Recommendation {
    Proceed,
    Iterate,
    Stop,
}

fn validator() -> Result<&'static jsonschema::Validator, EvalError> {
    static VALIDATOR: OnceLock<Result<jsonschema::Validator, String>> = OnceLock::new();
    VALIDATOR
        .get_or_init(|| {
            let schema: serde_json::Value =
                serde_json::from_str(PLAN_SCHEMA).map_err(|error| error.to_string())?;
            jsonschema::validator_for(&schema).map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| EvalError::InvalidPlan(format!("embedded schema is invalid: {error}")))
}

pub fn parse_plan(json: &str) -> Result<PrivateEvalPlan, EvalError> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    let mut errors = validator()?
        .iter_errors(&value)
        .map(|error| format!("{}: {error}", error.instance_path()))
        .collect::<Vec<_>>();
    if !errors.is_empty() {
        errors.sort();
        return Err(EvalError::InvalidPlan(errors.join("\n")));
    }
    let plan: PrivateEvalPlan = serde_json::from_value(value)?;
    if plan.thresholds != V01_THRESHOLDS {
        return Err(EvalError::InvalidPlan(
            "thresholds do not match the committed v0.1 gate".to_owned(),
        ));
    }
    let ids = plan
        .questions
        .iter()
        .map(|question| question.id.as_str())
        .collect::<HashSet<_>>();
    if ids.len() != plan.questions.len() {
        return Err(EvalError::InvalidPlan(
            "question ids must be unique".to_owned(),
        ));
    }
    if !plan.questions.iter().any(|q| q.expected_sources.is_empty()) {
        return Err(EvalError::InvalidPlan(
            "at least one reviewed no-answer question is required".to_owned(),
        ));
    }
    Ok(plan)
}

pub fn run(
    vault: &Vault,
    embedder: &dyn EmbeddingProvider,
    plan: &PrivateEvalPlan,
    plan_checksum: String,
) -> Result<PrivateEvalReport, EvalError> {
    let (corpus_artifacts, corpus_versions, corpus_chunks, corpus_manifest_checksum) =
        corpus_manifest(vault)?;
    let lens_ids = plan
        .questions
        .iter()
        .map(|question| question.lens_id.as_str())
        .collect::<BTreeSet<_>>();
    let lens_set_checksum = blake3::hash(
        lens_ids
            .iter()
            .copied()
            .collect::<Vec<_>>()
            .join("\n")
            .as_bytes(),
    )
    .to_hex()
    .to_string();
    let answerable = plan
        .questions
        .iter()
        .filter(|question| !question.expected_sources.is_empty())
        .count();
    let no_answer = plan.questions.len() - answerable;
    let mut recall_5 = 0.0;
    let mut recall_10 = 0.0;
    let mut reciprocal_rank = 0.0;
    let mut predicted_no_answer = 0usize;
    let mut correct_no_answer = 0usize;
    let mut policy_leakage = 0u32;
    let mut quarantine_leakage = 0u32;
    let mut failed_queries = 0u32;
    let mut disclosure_mismatches = 0u32;
    let mut stale_accesses = 0usize;
    let mut total_accesses = 0usize;
    let mut reconstructed = 0usize;
    let mut verified_receipts = 0usize;
    let mut latencies = Vec::with_capacity(plan.questions.len());
    let mut failures = Vec::new();

    for question in &plan.questions {
        let policy = lens::get(vault, &LensId(question.lens_id.clone()))?;
        let mut failure_kinds = BTreeSet::new();
        let mut session = Session::open(
            vault,
            AgentRef {
                agent_id: "private-eval".to_owned(),
                name: "private-eval-runner".to_owned(),
            },
            &policy,
            format!("private evaluation {}", question.id),
            false,
        )?;
        let started = Instant::now();
        let query_succeeded = session.query(embedder, &question.query, 10).is_ok();
        latencies.push(started.elapsed());
        let receipt = session.finalize()?;
        if !query_succeeded {
            failed_queries += 1;
            failure_kinds.insert("query_failed".to_owned());
        }
        if receipt::verify_disclosures(vault, &receipt).is_ok() {
            reconstructed += 1;
        } else {
            failure_kinds.insert("citation_reconstruction_failed".to_owned());
        }
        if receipt.self_hash.is_some() {
            verified_receipts += 1;
        } else {
            failure_kinds.insert("receipt_unfinalized".to_owned());
        }

        let query_record = receipt.queries.last();
        let accesses = query_record
            .map(|query| query.artifacts_accessed.as_slice())
            .unwrap_or_default();
        let is_no_result =
            query_record.is_some_and(|query| query.outcome == QueryOutcome::NoResult);
        predicted_no_answer += usize::from(is_no_result);
        if question.expected_sources.is_empty() && is_no_result {
            correct_no_answer += 1;
        }
        if question.expected_sources.is_empty() && !is_no_result {
            failure_kinds.insert("unexpected_answer".to_owned());
        }
        if !question.expected_sources.is_empty() && is_no_result {
            failure_kinds.insert("missed_expected_source".to_owned());
        }

        let expected = question
            .expected_sources
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        if !expected.is_empty() {
            let ranked = accesses
                .iter()
                .map(|access| ExpectedSource {
                    artifact_id: access.artifact_id.clone(),
                    artifact_version_id: access.artifact_version_id.clone(),
                })
                .collect::<Vec<_>>();
            recall_5 += source_recall(&ranked, &expected, 5);
            recall_10 += source_recall(&ranked, &expected, 10);
            reciprocal_rank += ranked
                .iter()
                .position(|source| expected.contains(source))
                .map(|rank| 1.0 / (rank as f64 + 1.0))
                .unwrap_or(0.0);
            if !expected.iter().all(|source| ranked.contains(source)) {
                failure_kinds.insert("missed_expected_source".to_owned());
            }
        }

        for access in accesses {
            total_accesses += 1;
            let (space_id, state): (String, String) = vault.conn().query_row(
                "SELECT space_id, state FROM artifacts WHERE id = ?1",
                [access.artifact_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if question.blocked_space_ids.contains(&space_id) {
                policy_leakage += 1;
                failure_kinds.insert("policy_leakage".to_owned());
            }
            if state != ArtifactState::Live.as_str() {
                quarantine_leakage += 1;
                failure_kinds.insert("quarantine_leakage".to_owned());
            }
            let latest: String = vault.conn().query_row(
                "SELECT id FROM artifact_versions
                 WHERE artifact_id = ?1 ORDER BY version DESC LIMIT 1",
                [access.artifact_id.as_str()],
                |row| row.get(0),
            )?;
            if access.artifact_version_id != latest {
                stale_accesses += 1;
                failure_kinds.insert("stale_or_superseded_source".to_owned());
            }
            if access.applied_disclosure_mode != question.expected_disclosure_mode.as_str() {
                disclosure_mismatches += 1;
                failure_kinds.insert("disclosure_mode_mismatch".to_owned());
            }
        }

        if !failure_kinds.is_empty() {
            failures.push(SafeFailure {
                question_id: question.id.clone(),
                category: question.category.clone(),
                severity: question.severity.clone(),
                failure_kinds: failure_kinds.into_iter().collect(),
            });
        }
    }

    let receipt_chain_verified = receipt::verify(vault).is_ok();
    if !receipt_chain_verified {
        failures.push(SafeFailure {
            question_id: "run".to_owned(),
            category: "receipt_chain".to_owned(),
            severity: "critical".to_owned(),
            failure_kinds: vec!["receipt_chain_verification_failed".to_owned()],
        });
    }
    latencies.sort();
    let report_questions = plan.questions.len();
    let mut report = PrivateEvalReport {
        schema_version: "private-eval-report-v1".to_owned(),
        plan_checksum,
        corpus_manifest_checksum,
        run_at: chrono::Utc::now(),
        model_version: embedder.model_version().to_owned(),
        index_version: "sqlite-vec@0.1.7".to_owned(),
        runtime_os: std::env::consts::OS.to_owned(),
        runtime_arch: std::env::consts::ARCH.to_owned(),
        corpus_artifacts,
        corpus_versions,
        corpus_chunks,
        lens_count: lens_ids.len() as u32,
        lens_set_checksum,
        questions: report_questions as u32,
        answerable_questions: answerable as u32,
        no_answer_questions: no_answer as u32,
        recall_at_5: divide(recall_5, answerable),
        recall_at_10: divide(recall_10, answerable),
        mrr: divide(reciprocal_rank, answerable),
        no_answer_precision: if predicted_no_answer == 0 {
            if no_answer == 0 {
                1.0
            } else {
                0.0
            }
        } else {
            correct_no_answer as f64 / predicted_no_answer as f64
        },
        no_answer_recall: divide(correct_no_answer as f64, no_answer),
        policy_leakage_count: policy_leakage,
        quarantine_leakage_count: quarantine_leakage,
        failed_query_count: failed_queries,
        disclosure_mismatch_count: disclosure_mismatches,
        stale_retrieval_rate: divide(stale_accesses as f64, total_accesses),
        citation_reconstruction_rate: divide(reconstructed as f64, report_questions),
        receipt_verification_rate: divide(verified_receipts as f64, report_questions),
        receipt_chain_verified,
        p50_latency_ms: percentile(&latencies, 0.50).as_secs_f64() * 1000.0,
        p95_latency_ms: percentile(&latencies, 0.95).as_secs_f64() * 1000.0,
        thresholds: plan.thresholds.clone(),
        failures,
        recommendation: Recommendation::Iterate,
    };
    report.recommendation = recommendation(&report);
    Ok(report)
}

fn source_recall(ranked: &[ExpectedSource], expected: &HashSet<ExpectedSource>, k: usize) -> f64 {
    let found = expected
        .iter()
        .filter(|source| ranked.iter().take(k).any(|ranked| ranked == *source))
        .count();
    found as f64 / expected.len() as f64
}

fn divide(numerator: f64, denominator: usize) -> f64 {
    if denominator == 0 {
        1.0
    } else {
        numerator / denominator as f64
    }
}

fn percentile(values: &[Duration], fraction: f64) -> Duration {
    if values.is_empty() {
        return Duration::ZERO;
    }
    values[((values.len() - 1) as f64 * fraction).ceil() as usize]
}

fn recommendation(report: &PrivateEvalReport) -> Recommendation {
    let safety_failed = report.policy_leakage_count > report.thresholds.max_policy_leakage
        || report.quarantine_leakage_count > report.thresholds.max_quarantine_leakage
        || report.failed_query_count > 0
        || report.disclosure_mismatch_count > 0
        || report.citation_reconstruction_rate < report.thresholds.min_citation_reconstruction
        || report.receipt_verification_rate < report.thresholds.min_receipt_verification
        || !report.receipt_chain_verified;
    if safety_failed {
        Recommendation::Stop
    } else if report.recall_at_10 >= report.thresholds.min_recall_at_10
        && report.no_answer_precision >= report.thresholds.min_no_answer_precision
        && report.no_answer_recall >= report.thresholds.min_no_answer_recall
        && report.stale_retrieval_rate <= report.thresholds.max_stale_retrieval_rate
    {
        Recommendation::Proceed
    } else {
        Recommendation::Iterate
    }
}

fn corpus_manifest(vault: &Vault) -> Result<(u64, u64, u64, String), EvalError> {
    let artifacts: i64 = vault
        .conn()
        .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row.get(0))?;
    let versions: i64 =
        vault
            .conn()
            .query_row("SELECT COUNT(*) FROM artifact_versions", [], |row| {
                row.get(0)
            })?;
    let chunks: i64 = vault
        .conn()
        .query_row("SELECT COUNT(*) FROM chunks", [], |row| row.get(0))?;
    let mut stmt = vault.conn().prepare(
        "SELECT a.id, av.id, av.version, av.blob_hash
         FROM artifacts a JOIN artifact_versions av ON av.artifact_id = a.id
         ORDER BY a.id, av.version",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(format!(
                "{}\0{}\0{}\0{}\n",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let checksum = blake3::hash(rows.concat().as_bytes()).to_hex().to_string();
    Ok((
        artifacts.max(0) as u64,
        versions.max(0) as u64,
        chunks.max(0) as u64,
        checksum,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{self, ArtifactId, Sensitivity};
    use crate::crypto::KdfParams;
    use crate::embed::EmbedError;
    use crate::lens::LensPolicy;
    use crate::space::{self, SpaceId};
    use crate::{chunk, extract, inbox, search};

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    struct FakeEmbedder;
    impl EmbeddingProvider for FakeEmbedder {
        fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
            let mut vector = vec![0.0f32; 384];
            for window in text.to_lowercase().as_bytes().windows(3) {
                let hash =
                    (window[0] as usize * 961 + window[1] as usize * 31 + window[2] as usize) % 384;
                vector[hash] += 1.0;
            }
            let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
            if norm > 0.0 {
                vector.iter_mut().for_each(|value| *value /= norm);
            }
            Ok(vector)
        }
        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
            texts.iter().map(|text| self.embed(text)).collect()
        }
        fn model_version(&self) -> &str {
            "fake-private-eval@1"
        }
        fn dimensions(&self) -> usize {
            384
        }
        fn calibrated_relevance_floor(&self) -> Option<f32> {
            Some(0.2)
        }
    }

    fn thresholds() -> PrivateThresholds {
        V01_THRESHOLDS
    }

    fn question(id: usize) -> PrivateQuestion {
        PrivateQuestion {
            id: format!("q-{id:02}"),
            query: "placeholder query".to_owned(),
            lens_id: "lens_placeholder".to_owned(),
            category: "semantic".to_owned(),
            expected_disclosure_mode: DisclosureMode::Excerpt,
            severity: "high".to_owned(),
            rationale: "reviewed test rationale".to_owned(),
            reviewed_at: "2026-07-12".to_owned(),
            expected_sources: Vec::new(),
            blocked_space_ids: Vec::new(),
        }
    }

    #[test]
    fn schema_requires_thirty_to_fifty_reviewed_questions() {
        let plan = PrivateEvalPlan {
            schema_version: "private-eval-v1".to_owned(),
            plan_id: "too-small".to_owned(),
            reviewed_by: "owner".to_owned(),
            review_date: "2026-07-12".to_owned(),
            thresholds: thresholds(),
            questions: (0..29).map(question).collect(),
        };
        let error = parse_plan(&serde_json::to_string(&plan).expect("serialize"))
            .expect_err("29 questions must fail");
        assert!(error.to_string().contains("30"));
    }

    fn ingest(
        vault: &Vault,
        dir: &std::path::Path,
        space: &SpaceId,
        name: &str,
        body: &str,
        live: bool,
    ) -> (ArtifactId, String) {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("write");
        inbox::add(vault, std::slice::from_ref(&path)).expect("add");
        let artifact = inbox::process(vault, space).expect("process").ingested[0]
            .1
            .clone();
        let derived = extract::extract_text(vault, &artifact)
            .expect("extract")
            .expect("text");
        chunk::chunk_derived_text(vault, &derived, &chunk::ChunkParams::default()).expect("chunk");
        if live {
            artifact::set_state(vault, &artifact, ArtifactState::Live).expect("live");
        }
        let version = vault
            .conn()
            .query_row(
                "SELECT id FROM artifact_versions WHERE artifact_id = ?1",
                [artifact.0.as_str()],
                |row| row.get(0),
            )
            .expect("version");
        (artifact, version)
    }

    #[test]
    fn receipt_backed_runner_emits_only_safe_aggregate_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault =
            Vault::create_with_params(&dir.path().join("Private.tessera"), "pass", &TEST_PARAMS)
                .expect("vault");
        let work = space::create(&vault, "Work", None).expect("work");
        let blocked = space::create(&vault, "Blocked", None).expect("blocked");
        let (artifact, version) = ingest(
            &vault,
            dir.path(),
            &work,
            "fire.md",
            "Fire corridor walls require a two hour resistance rating.",
            true,
        );
        ingest(
            &vault,
            dir.path(),
            &blocked,
            "private.md",
            "Fire corridor walls have a private restricted annex.",
            true,
        );
        ingest(
            &vault,
            dir.path(),
            &work,
            "pending.md",
            "Pending secret content must remain quarantined.",
            false,
        );
        search::embed_missing(&vault, &FakeEmbedder).expect("embed");

        let mut answer_lens = LensPolicy::new("Answer", vec![work.clone()]);
        answer_lens.disclosure_mode = DisclosureMode::Excerpt;
        answer_lens.max_quote_chars = Some(500);
        answer_lens.sensitivity_ceiling = Sensitivity::Restricted;
        answer_lens.min_relevance_score = Some(0.2);
        let answer_lens_id = lens::create(&vault, &answer_lens).expect("answer lens");
        let mut empty_lens = answer_lens.clone();
        empty_lens.id = LensId(format!("lens_{}", ulid::Ulid::new()));
        empty_lens.name = "No answer".to_owned();
        empty_lens.min_relevance_score = Some(1.0);
        let empty_lens_id = lens::create(&vault, &empty_lens).expect("empty lens");

        let mut questions = Vec::new();
        for id in 0..15 {
            let mut item = question(id);
            item.query = "fire corridor two hour resistance rating".to_owned();
            item.lens_id = answer_lens_id.0.clone();
            item.expected_sources = vec![ExpectedSource {
                artifact_id: artifact.0.clone(),
                artifact_version_id: version.clone(),
            }];
            item.blocked_space_ids = vec![blocked.0.clone()];
            questions.push(item);
        }
        for id in 15..30 {
            let mut item = question(id);
            item.query = "blue whale migration acoustics secret probe".to_owned();
            item.category = "unanswerable".to_owned();
            item.lens_id = empty_lens_id.0.clone();
            item.blocked_space_ids = vec![blocked.0.clone()];
            questions.push(item);
        }
        let plan = PrivateEvalPlan {
            schema_version: "private-eval-v1".to_owned(),
            plan_id: "synthetic-runner-test".to_owned(),
            reviewed_by: "test-owner".to_owned(),
            review_date: "2026-07-12".to_owned(),
            thresholds: thresholds(),
            questions,
        };
        let plan = parse_plan(&serde_json::to_string(&plan).expect("plan json"))
            .expect("valid private plan");
        let report =
            run(&vault, &FakeEmbedder, &plan, "plan-checksum".to_owned()).expect("private run");
        assert_eq!(report.questions, 30);
        assert_eq!(report.recall_at_10, 1.0);
        assert_eq!(report.no_answer_precision, 1.0);
        assert_eq!(report.no_answer_recall, 1.0);
        assert_eq!(report.policy_leakage_count, 0);
        assert_eq!(report.quarantine_leakage_count, 0);
        assert_eq!(report.failed_query_count, 0);
        assert_eq!(report.disclosure_mismatch_count, 0);
        assert_eq!(report.citation_reconstruction_rate, 1.0);
        assert_eq!(report.receipt_verification_rate, 1.0);
        assert!(report.receipt_chain_verified);
        assert_eq!(report.recommendation, Recommendation::Proceed);
        assert!(report.failures.is_empty());
        let safe_json = serde_json::to_string(&report).expect("report json");
        assert!(!safe_json.contains("blue whale"));
        assert!(!safe_json.contains("Fire corridor"));
        assert!(!safe_json.contains(&artifact.0));
    }
}
