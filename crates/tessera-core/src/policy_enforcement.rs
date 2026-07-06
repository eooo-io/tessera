//! #20 — the policy-enforcement paranoia suite (test-only).
//!
//! These tests prove the negative: that no lens, however constructed, can ever
//! surface content it is not entitled to. They compile real [`LensPolicy`]
//! values into retrieval constraints (the same path `search_with_lens` uses)
//! and drive the sqlite-vec index directly with controlled vectors, so an
//! adversarially planted "perfect match" either surfaces or provably does not.
//!
//! Acceptance guarantees (issue #20):
//!   - proptest: for random policies + corpora, no result violates a constraint;
//!   - a blocked-space test where the blocked content is a perfect vector match.
//!
//! This also closes the lens-level half of the quarantine invariant (#11):
//! pending/archived content never appears under any lens.

use std::sync::atomic::{AtomicUsize, Ordering};

use proptest::prelude::*;

use crate::artifact::{self, ArtifactId, ArtifactState, Sensitivity};
use crate::blob::BlobHash;
use crate::crypto::KdfParams;
use crate::index::{ChunkRef, SqliteVecIndex, VectorIndex};
use crate::lens::LensPolicy;
use crate::space::{self, SpaceId};
use crate::vault::Vault;

const TEST_PARAMS: KdfParams = KdfParams {
    m_cost_kib: 1024,
    t_cost: 1,
    p_cost: 1,
};
const MODEL: &str = "synth@1";
const DIMS: usize = 384;

const SENS: [Sensitivity; 4] = [
    Sensitivity::Public,
    Sensitivity::Internal,
    Sensitivity::Confidential,
    Sensitivity::Restricted,
];
const STATE: [ArtifactState; 3] = [
    ArtifactState::Pending,
    ArtifactState::Live,
    ArtifactState::Archived,
];
const MEDIA: [&str; 3] = ["text/plain", "text/markdown", "application/pdf"];
const TAGS: [&str; 3] = ["red", "green", "blue"];

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn new_vault(dir: &std::path::Path) -> Vault {
    Vault::create_with_params(&dir.join("V.tessera"), "p", &TEST_PARAMS).expect("create vault")
}

/// A three-component seed lifted into a normalized 384-dim vector. An all-zero
/// seed becomes a valid unit vector (never a zero vector).
fn synth3(seed: (i8, i8, i8)) -> Vec<f32> {
    let mut v = vec![0.0f32; DIMS];
    v[0] = seed.0 as f32;
    v[1] = seed.1 as f32;
    v[2] = seed.2 as f32;
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm == 0.0 {
        v[0] = 1.0;
        return v;
    }
    for x in &mut v {
        *x /= norm;
    }
    v
}

fn mask_to_tags(mask: (bool, bool, bool)) -> Vec<&'static str> {
    let bits = [mask.0, mask.1, mask.2];
    TAGS.iter()
        .zip(bits)
        .filter_map(|(t, on)| on.then_some(*t))
        .collect()
}

fn mask_to_spaces(mask: (bool, bool, bool), spaces: &[SpaceId]) -> Vec<SpaceId> {
    let bits = [mask.0, mask.1, mask.2];
    spaces
        .iter()
        .zip(bits)
        .filter_map(|(s, on)| on.then_some(s.clone()))
        .collect()
}

fn mask_to_media(mask: (bool, bool, bool)) -> Vec<String> {
    let bits = [mask.0, mask.1, mask.2];
    MEDIA
        .iter()
        .zip(bits)
        .filter_map(|(m, on)| on.then_some((*m).to_string()))
        .collect()
}

/// Plant a fully-formed retrievable artifact (metadata + version + derived
/// text + one chunk + one vector) with total control over every field. The
/// derived-text/chunk rows are written directly so the vector is exactly what
/// the caller specifies — the whole point of the adversarial tests.
fn plant(
    vault: &Vault,
    space: &SpaceId,
    media_type: &str,
    sensitivity: Sensitivity,
    state: ArtifactState,
    tags: &[&str],
    vector: &[f32],
) -> ArtifactId {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let art = artifact::register(vault, space, "f.txt", media_type, sensitivity).expect("register");
    for t in tags {
        artifact::tag(vault, &art, t).expect("tag");
    }
    let ver = artifact::record_version(vault, &art, &BlobHash("bh".into()), 1).expect("version");

    let dt_id = format!("dt_{}", ulid::Ulid::new());
    let chunk_id = format!("chunk_{n}_{}", ulid::Ulid::new());
    let conn = vault.conn();
    conn.execute(
        "INSERT INTO derived_text
           (id, artifact_version_id, blob_hash, extractor, extractor_version, created_at)
         VALUES (?1, ?2, 'bh', 'test', '1', '2026-07-06T00:00:00Z')",
        rusqlite::params![dt_id, ver.id],
    )
    .expect("insert derived_text");
    conn.execute(
        "INSERT INTO chunks
           (id, derived_text_id, chunk_index, byte_offset_start, byte_offset_end,
            token_count, content_hash, created_at)
         VALUES (?1, ?2, 0, 0, 10, 3, 'ch', '2026-07-06T00:00:00Z')",
        rusqlite::params![chunk_id, dt_id],
    )
    .expect("insert chunk");

    SqliteVecIndex::new(vault, MODEL)
        .insert(&chunk_id, vector)
        .expect("insert vector");

    // register() starts artifacts at pending; only transition when needed.
    if !matches!(state, ArtifactState::Pending) {
        artifact::set_state(vault, &art, state).expect("set state");
    }
    art
}

fn search(vault: &Vault, query: &[f32], lens: &LensPolicy, k: usize) -> Vec<ChunkRef> {
    SqliteVecIndex::new(vault, MODEL)
        .search(query, &lens.to_constraints(), k)
        .expect("search")
}

/// The blocked-space test: content in an excluded space that is a *perfect*
/// vector match to the query and carries the most permissive attributes must
/// still never surface. Only the space rule can stop it — and it must.
#[test]
fn adversarial_blocked_space_never_surfaces() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = new_vault(dir.path());
    let allowed = space::create(&vault, "Allowed", None).expect("allowed");
    let blocked = space::create(&vault, "Blocked", None).expect("blocked");

    let query = synth3((100, 0, 0));
    // Perfect match, lives in the blocked space, nothing else to filter on.
    let evil = plant(
        &vault,
        &blocked,
        "text/markdown",
        Sensitivity::Public,
        ArtifactState::Live,
        &["red"],
        &query,
    );
    // A weaker match in the allowed space.
    let good = plant(
        &vault,
        &allowed,
        "text/markdown",
        Sensitivity::Public,
        ArtifactState::Live,
        &["red"],
        &synth3((0, 0, 100)),
    );

    // Include the allowed space only.
    let mut include_only = LensPolicy::new("allowed", vec![allowed.clone()]);
    include_only.sensitivity_ceiling = Sensitivity::Restricted;
    let hits = search(&vault, &query, &include_only, 10);
    assert!(
        hits.iter().all(|h| h.artifact_id != evil),
        "blocked perfect-match content surfaced under an include-only lens"
    );
    assert!(
        hits.iter().any(|h| h.artifact_id == good),
        "the allowed doc should still be retrievable"
    );

    // Include BOTH spaces but exclude the blocked one — exclusion must win.
    let mut exclude_wins = LensPolicy::new("both", vec![allowed.clone(), blocked.clone()]);
    exclude_wins.space_exclude_ids = vec![blocked.clone()];
    exclude_wins.sensitivity_ceiling = Sensitivity::Restricted;
    let hits = search(&vault, &query, &exclude_wins, 10);
    assert!(
        hits.iter().all(|h| h.artifact_id != evil),
        "exclusion did not override inclusion for the blocked space"
    );
}

/// Lens-level quarantine invariant (#11): pending and archived content, even
/// as a perfect vector match inside an included space, never surfaces.
#[test]
fn quarantined_content_never_surfaces_under_lens() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = new_vault(dir.path());
    let docs = space::create(&vault, "Docs", None).expect("docs");

    let query = synth3((100, 0, 0));
    let pending = plant(
        &vault,
        &docs,
        "text/markdown",
        Sensitivity::Public,
        ArtifactState::Pending,
        &[],
        &query,
    );
    let archived = plant(
        &vault,
        &docs,
        "text/markdown",
        Sensitivity::Public,
        ArtifactState::Archived,
        &[],
        &query,
    );
    let live = plant(
        &vault,
        &docs,
        "text/markdown",
        Sensitivity::Public,
        ArtifactState::Live,
        &[],
        &synth3((90, 10, 0)),
    );

    let mut lens = LensPolicy::new("docs", vec![docs.clone()]);
    lens.sensitivity_ceiling = Sensitivity::Restricted;
    let hits = search(&vault, &query, &lens, 10);

    assert!(
        hits.iter().all(|h| h.artifact_id != pending),
        "pending content surfaced under a lens"
    );
    assert!(
        hits.iter().all(|h| h.artifact_id != archived),
        "archived content surfaced under a lens"
    );
    assert!(
        hits.iter().any(|h| h.artifact_id == live),
        "the live doc should surface"
    );
}

/// "Empty lens discloses nothing": a lens that excludes its own included space
/// nets to zero and must return no results, even for a perfect match.
#[test]
fn self_excluding_lens_discloses_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = new_vault(dir.path());
    let space = space::create(&vault, "Only", None).expect("space");

    let query = synth3((100, 0, 0));
    plant(
        &vault,
        &space,
        "text/markdown",
        Sensitivity::Public,
        ArtifactState::Live,
        &[],
        &query,
    );

    let mut lens = LensPolicy::new("self", vec![space.clone()]);
    lens.space_exclude_ids = vec![space.clone()];
    lens.sensitivity_ceiling = Sensitivity::Restricted;
    let hits = search(&vault, &query, &lens, 10);
    assert!(
        hits.is_empty(),
        "a lens excluding its own space disclosed {} result(s)",
        hits.len()
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// For a random corpus (spaces, sensitivities, states, tags, media types,
    /// vectors) and a random lens, every returned hit must satisfy every
    /// compiled constraint. Soundness only — we assert nothing forbidden ever
    /// appears, which is the security-relevant direction.
    #[test]
    fn random_lens_never_violates_constraints(
        corpus in prop::collection::vec(
            (0usize..3, 0usize..4, 0usize..3, any::<(bool, bool, bool)>(),
             0usize..3, any::<(i8, i8, i8)>()),
            1..6),
        include_mask in any::<(bool, bool, bool)>(),
        exclude_mask in any::<(bool, bool, bool)>(),
        tag_inc_mask in any::<(bool, bool, bool)>(),
        tag_exc_mask in any::<(bool, bool, bool)>(),
        media_mask in any::<(bool, bool, bool)>(),
        ceiling_idx in 0usize..4,
        query_seed in any::<(i8, i8, i8)>(),
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = new_vault(dir.path());
        let spaces: Vec<SpaceId> = (0..3)
            .map(|i| space::create(&vault, &format!("S{i}"), None).expect("space"))
            .collect();

        for (si, sens_i, state_i, tmask, media_i, vseed) in &corpus {
            let tags = mask_to_tags(*tmask);
            let vector = synth3(*vseed);
            plant(&vault, &spaces[*si], MEDIA[*media_i], SENS[*sens_i], STATE[*state_i],
                  &tags, &vector);
        }

        let inc_spaces = mask_to_spaces(include_mask, &spaces);
        let exc_spaces = mask_to_spaces(exclude_mask, &spaces);
        let inc_tags = mask_to_tags(tag_inc_mask);
        let exc_tags = mask_to_tags(tag_exc_mask);
        let media = mask_to_media(media_mask);
        let ceiling = SENS[ceiling_idx];

        let mut lens = LensPolicy::new("t", inc_spaces.clone());
        lens.space_exclude_ids = exc_spaces.clone();
        lens.tag_include = inc_tags.iter().map(|s| s.to_string()).collect();
        lens.tag_exclude = exc_tags.iter().map(|s| s.to_string()).collect();
        lens.media_types = media.clone();
        lens.sensitivity_ceiling = ceiling;

        let query = synth3(query_seed);
        let hits = search(&vault, &query, &lens, corpus.len());

        for hit in hits {
            let a = artifact::get(&vault, &hit.artifact_id).expect("get");
            let atags = artifact::tags_of(&vault, &hit.artifact_id).expect("tags");

            prop_assert_eq!(a.state, ArtifactState::Live, "non-live content surfaced");
            if !inc_spaces.is_empty() {
                prop_assert!(inc_spaces.contains(&a.space_id), "space outside include set");
            }
            prop_assert!(!exc_spaces.contains(&a.space_id), "excluded space surfaced");
            for t in &exc_tags {
                prop_assert!(!atags.iter().any(|x| x == t), "excluded tag surfaced");
            }
            if !inc_tags.is_empty() {
                prop_assert!(
                    inc_tags.iter().any(|t| atags.iter().any(|x| x == t)),
                    "result lacks every required include tag"
                );
            }
            if !media.is_empty() {
                prop_assert!(media.contains(&a.media_type), "media type not permitted");
            }
            prop_assert!(
                a.sensitivity.rank() <= ceiling.rank(),
                "sensitivity above the lens ceiling"
            );
        }
    }
}
