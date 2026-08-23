//! Controlled, ignored performance evidence for protected metadata format v3.

use std::time::Instant;

use tessera_core::chunk::ChunkParams;
use tessera_core::crypto::KdfParams;
use tessera_core::embed::{EmbedError, EmbeddingProvider};
use tessera_core::{artifact, chunk, extract, recovery, search, space, Vault};

const TEST_PARAMS: KdfParams = KdfParams {
    m_cost_kib: 1024,
    t_cost: 1,
    p_cost: 1,
};

struct ControlledEmbedder;

impl EmbeddingProvider for ControlledEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        let mut vector = vec![0.0; 384];
        vector[(blake3::hash(text.as_bytes()).as_bytes()[0] as usize) % 384] = 1.0;
        Ok(vector)
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        texts.iter().map(|text| self.embed(text)).collect()
    }

    fn model_version(&self) -> &str {
        "metadata-performance-controlled@v1"
    }

    fn dimensions(&self) -> usize {
        384
    }

    fn calibrated_relevance_floor(&self) -> Option<f32> {
        Some(-1.0)
    }
}

fn tree_bytes(path: &std::path::Path) -> u64 {
    std::fs::read_dir(path)
        .expect("read directory")
        .map(|entry| entry.expect("entry").path())
        .map(|path| {
            if path.is_dir() {
                tree_bytes(&path)
            } else {
                std::fs::metadata(path).expect("metadata").len()
            }
        })
        .sum()
}

#[test]
#[ignore = "controlled metadata performance evidence; run explicitly for issue #50"]
fn protected_storage_query_backup_and_repair_measurements() {
    let directory = tempfile::tempdir().expect("tempdir");
    let vault_path = directory.path().join("Performance.tessera");
    let started = Instant::now();
    let vault = Vault::create_with_params(&vault_path, "performance-passphrase", &TEST_PARAMS)
        .expect("create");
    let create_ms = started.elapsed().as_millis();
    let space = space::create(&vault, "performance-space", None).expect("space");

    let ingest_started = Instant::now();
    for index in 0..100 {
        let body = format!(
            "Protected metadata performance document {index}. Deterministic retrieval fixture."
        );
        let (artifact_id, _) = artifact::register_encrypted_bytes(
            &vault,
            &space,
            &format!("document-{index:03}.md"),
            "text/markdown",
            artifact::Sensitivity::Internal,
            body.as_bytes(),
        )
        .expect("artifact");
        let derived = extract::extract_text(&vault, &artifact_id)
            .expect("extract")
            .expect("derived text");
        chunk::chunk_derived_text(&vault, &derived, &ChunkParams::default()).expect("chunk");
        artifact::set_state(&vault, &artifact_id, artifact::ArtifactState::Live)
            .expect("make live");
    }
    let ingest_ms = ingest_started.elapsed().as_millis();

    let embedder = ControlledEmbedder;
    search::embed_missing(&vault, &embedder).expect("embed");
    let query_started = Instant::now();
    let results = search::query(
        &vault,
        &embedder,
        "deterministic retrieval fixture",
        &search::owner_constraints(),
        10,
    )
    .expect("query");
    let query_us = query_started.elapsed().as_micros();
    assert_eq!(results.len(), 10);

    let diagnostics_started = Instant::now();
    let report = recovery::diagnose(&vault).expect("diagnose");
    let diagnostics_ms = diagnostics_started.elapsed().as_millis();
    assert!(!report.has_fatal());

    let repair_started = Instant::now();
    let repair = recovery::rebuild_derived(&vault).expect("repair no-op");
    let repair_ms = repair_started.elapsed().as_millis();
    assert_eq!(repair.failed, 0);

    let backup_path = directory.path().join("PerformanceBackup.tessera");
    let backup_started = Instant::now();
    recovery::backup(&vault, &backup_path).expect("backup");
    let backup_ms = backup_started.elapsed().as_millis();
    let storage_bytes = tree_bytes(&vault_path);
    let backup_bytes = tree_bytes(&backup_path);

    println!(
        "metadata_performance_v1 create_ms={create_ms} ingest_100_ms={ingest_ms} \
         query_top10_us={query_us} diagnostics_ms={diagnostics_ms} repair_ms={repair_ms} \
         backup_ms={backup_ms} storage_bytes={storage_bytes} backup_bytes={backup_bytes}"
    );
}
