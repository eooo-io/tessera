//! Cross-host format-v3 portability fixture for issue #50.
//!
//! Ordinary runs create and verify a disposable local bundle. CI sets the
//! export/import paths so the same synthetic backup crosses macOS to Ubuntu
//! and Ubuntu back to macOS as workflow artifacts.

use std::path::Path;

use tessera_core::chunk::ChunkParams;
use tessera_core::crypto::KdfParams;
use tessera_core::embed::{EmbedError, EmbeddingProvider};
use tessera_core::{artifact, chunk, extract, receipt, recovery, search, space, LensPolicy, Vault};

const PASSPHRASE: &str = "synthetic-portability-passphrase";
const SPACE_NAME: &str = "Synthetic cross-platform evidence";
const BODY: &[u8] = b"Synthetic portable metadata evidence with deterministic retrieval.";
const TEST_PARAMS: KdfParams = KdfParams {
    m_cost_kib: 1024,
    t_cost: 1,
    p_cost: 1,
};

struct PortabilityEmbedder;

impl EmbeddingProvider for PortabilityEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        let mut vector = vec![0.0; 384];
        vector[(blake3::hash(text.as_bytes()).as_bytes()[0] as usize) % 384] = 1.0;
        Ok(vector)
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        texts.iter().map(|text| self.embed(text)).collect()
    }

    fn model_version(&self) -> &str {
        "metadata-portability-controlled@v1"
    }

    fn dimensions(&self) -> usize {
        384
    }

    fn calibrated_relevance_floor(&self) -> Option<f32> {
        Some(-1.0)
    }
}

fn export_fixture(destination: &Path) {
    assert!(!destination.exists(), "export destination must not exist");
    let source_parent = tempfile::tempdir().expect("source parent");
    let source = source_parent.path().join("Source.tessera");
    let vault = Vault::create_with_params(&source, PASSPHRASE, &TEST_PARAMS).expect("create");
    let space = space::create(&vault, SPACE_NAME, None).expect("space");
    let (artifact_id, _) = artifact::register_encrypted_bytes(
        &vault,
        &space,
        "portable.md",
        "text/markdown",
        artifact::Sensitivity::Restricted,
        BODY,
    )
    .expect("artifact");
    let derived = extract::extract_text(&vault, &artifact_id)
        .expect("extract")
        .expect("derived");
    chunk::chunk_derived_text(&vault, &derived, &ChunkParams::default()).expect("chunk");
    artifact::set_state(&vault, &artifact_id, artifact::ArtifactState::Live).expect("live");
    search::embed_missing(&vault, &PortabilityEmbedder).expect("embed");
    receipt::Session::open(
        &vault,
        receipt::AgentRef {
            agent_id: "synthetic-portability-agent".into(),
            name: "Synthetic portability agent".into(),
        },
        &LensPolicy::new("cross-platform verification", vec![space]),
        "cross-platform backup verification",
        false,
    )
    .expect("receipt session")
    .finalize()
    .expect("receipt finalize");
    recovery::backup(&vault, destination).expect("portable backup");
}

fn verify_fixture(path: &Path) {
    let vault = Vault::open(path, PASSPHRASE).expect("cross-platform unlock");
    assert!(!recovery::diagnose(&vault).expect("diagnose").has_fatal());
    assert_eq!(receipt::verify(&vault).expect("receipt chain"), 1);
    assert_eq!(space::list(&vault).expect("spaces")[0].name, SPACE_NAME);
    let results = search::query(
        &vault,
        &PortabilityEmbedder,
        "deterministic retrieval",
        &search::owner_constraints(),
        5,
    )
    .expect("query");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].artifact_title, "portable.md");
    assert_eq!(results[0].byte_range, (0, BODY.len() as u64));
}

#[test]
fn export_portable_fixture() {
    if let Some(path) = std::env::var_os("TESSERA_PORTABILITY_EXPORT") {
        let path = std::path::PathBuf::from(path);
        export_fixture(&path);
        verify_fixture(&path);
    } else {
        let parent = tempfile::tempdir().expect("local export parent");
        let path = parent.path().join("Portable.tessera");
        export_fixture(&path);
        verify_fixture(&path);
    }
}

#[test]
fn import_portable_fixture() {
    if let Some(path) = std::env::var_os("TESSERA_PORTABILITY_IMPORT") {
        verify_fixture(Path::new(&path));
    } else {
        let parent = tempfile::tempdir().expect("local import parent");
        let path = parent.path().join("Portable.tessera");
        export_fixture(&path);
        verify_fixture(&path);
    }
}
