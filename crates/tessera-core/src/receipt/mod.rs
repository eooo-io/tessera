//! Receipts — immutable, hash-chained records of what an agent accessed.
//!
//! A [`Session`] binds a vault + lens and is the ONLY path that produces
//! disclosed query results: every [`Session::query`] appends a query record
//! before returning, so no disclosed answer can escape without being recorded
//! (the enforcement lives here in core, not in any CLI). [`Session::finalize`]
//! writes `receipts/<id>.json` embedding a BLAKE3 hash of the previous
//! receipt; [`verify`] walks the chain and fails if any receipt was edited.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::artifact::ArtifactId;
use crate::disclosure::{self, DisclosureError, RenderedContext};
use crate::embed::EmbeddingProvider;
use crate::lens::LensPolicy;
use crate::search::{self, SearchError};
use crate::vault::{Vault, VaultError};

#[derive(Error, Debug)]
pub enum ReceiptError {
    #[error("receipt not found: {0}")]
    NotFound(String),
    #[error("receipt chain broken at seq {seq}: {reason}")]
    ChainBroken { seq: u64, reason: String },
    #[error("search error: {0}")]
    Search(#[from] SearchError),
    #[error("disclosure error: {0}")]
    Disclosure(#[from] DisclosureError),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
}

/// The agent a session acts for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRef {
    pub agent_id: String,
    pub name: String,
}

/// The lens a session is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LensRef {
    pub lens_id: String,
    pub name: String,
}

/// Record of one artifact disclosed during a query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactAccess {
    pub artifact_id: String,
    pub artifact_title: String,
    pub disclosure_mode: String,
    pub bytes_disclosed: u64,
}

/// A single query within a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryRecord {
    pub query_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub query_text: String,
    pub artifacts_accessed: Vec<ArtifactAccess>,
}

/// A recorded rate-limit rejection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub tool: String,
    pub detail: String,
}

/// Aggregate statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptSummary {
    pub total_queries: u32,
    pub unique_artifacts_accessed: u32,
    pub total_bytes_disclosed: u64,
    pub disclosure_modes_used: Vec<String>,
}

/// An immutable, hash-chained record of session activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub receipt_id: String,
    pub session_id: String,
    pub agent: AgentRef,
    pub lens: LensRef,
    pub purpose: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
    pub queries: Vec<QueryRecord>,
    pub summary: ReceiptSummary,
    /// Rate-limit rejections that occurred during the session (covered by the
    /// content hash, so they cannot be quietly stripped).
    #[serde(default)]
    pub rate_limit_events: Vec<RateLimitEvent>,
    /// Position in the vault's receipt chain (0 = genesis).
    pub seq: u64,
    /// BLAKE3 of the previous receipt's canonical content (`None` at seq 0).
    pub prev_receipt_hash: Option<String>,
    /// BLAKE3 of THIS receipt's canonical content (all fields except this one),
    /// set at finalize. Recomputed and checked by [`verify`].
    pub self_hash: Option<String>,
}

/// The receipts directory inside a vault bundle.
fn receipts_dir(vault: &Vault) -> std::path::PathBuf {
    vault.path().join("receipts")
}

/// Canonical content hash: BLAKE3 over the receipt with `self_hash` cleared.
/// Every other field (including `prev_receipt_hash`) is covered, so editing
/// any of them changes the hash.
fn content_hash(receipt: &Receipt) -> Result<String, ReceiptError> {
    let mut canonical = receipt.clone();
    canonical.self_hash = None;
    let bytes = serde_json::to_vec(&canonical)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn compute_summary(queries: &[QueryRecord]) -> ReceiptSummary {
    use std::collections::BTreeSet;
    let mut unique = BTreeSet::new();
    let mut modes = BTreeSet::new();
    let mut total_bytes = 0u64;
    for q in queries {
        for a in &q.artifacts_accessed {
            unique.insert(a.artifact_id.clone());
            modes.insert(a.disclosure_mode.clone());
            total_bytes += a.bytes_disclosed;
        }
    }
    ReceiptSummary {
        total_queries: queries.len() as u32,
        unique_artifacts_accessed: unique.len() as u32,
        total_bytes_disclosed: total_bytes,
        disclosure_modes_used: modes.into_iter().collect(),
    }
}

/// A recording session: a vault + lens whose every query is journaled into an
/// open receipt. The disclosed-answer operation exists only here.
pub struct Session<'v> {
    vault: &'v Vault,
    lens: LensPolicy,
    allow_full: bool,
    receipt: Receipt,
}

impl<'v> Session<'v> {
    /// Open a session, chaining onto the current head of the vault's receipt
    /// chain. `allow_full` decides whether a `full` lens is honored (else it
    /// fail-closes to excerpt in the disclosure renderer).
    pub fn open(
        vault: &'v Vault,
        agent: AgentRef,
        lens: &LensPolicy,
        purpose: impl Into<String>,
        allow_full: bool,
    ) -> Result<Self, ReceiptError> {
        let chain = load_all_sorted(vault)?;
        let seq = chain.len() as u64;
        let prev_receipt_hash = chain.last().and_then(|r| r.self_hash.clone());
        let now = chrono::Utc::now();
        let receipt = Receipt {
            receipt_id: format!("rcpt_{}", ulid::Ulid::new()),
            session_id: format!("sess_{}", ulid::Ulid::new()),
            agent,
            lens: LensRef {
                lens_id: lens.id.0.clone(),
                name: lens.name.clone(),
            },
            purpose: purpose.into(),
            started_at: now,
            ended_at: None,
            queries: Vec::new(),
            summary: ReceiptSummary::default(),
            rate_limit_events: Vec::new(),
            seq,
            prev_receipt_hash,
            self_hash: None,
        };
        Ok(Self {
            vault,
            lens: lens.clone(),
            allow_full,
            receipt,
        })
    }

    /// Run a policy-filtered query and render each hit under the lens,
    /// recording the query (text, artifacts, modes, bytes) into the receipt
    /// before returning. There is no variant that skips recording.
    pub fn query(
        &mut self,
        embedder: &dyn EmbeddingProvider,
        text: &str,
        top_k: usize,
    ) -> Result<Vec<RenderedContext>, ReceiptError> {
        let hits = search::search_with_lens(self.vault, embedder, &self.lens, text, top_k)?;
        let mut rendered = Vec::with_capacity(hits.len());
        let mut accesses = Vec::with_capacity(hits.len());
        for hit in &hits {
            let rc = disclosure::render(self.vault, hit, &self.lens, self.allow_full)?;
            accesses.push(ArtifactAccess {
                artifact_id: rc.artifact_id.0.clone(),
                artifact_title: hit.artifact_title.clone(),
                disclosure_mode: rc.mode.as_str().to_owned(),
                bytes_disclosed: rc.bytes_disclosed,
            });
            rendered.push(rc);
        }
        self.receipt.queries.push(QueryRecord {
            query_id: format!("qry_{}", ulid::Ulid::new()),
            timestamp: chrono::Utc::now(),
            query_text: text.to_owned(),
            artifacts_accessed: accesses,
        });
        Ok(rendered)
    }

    /// Fetch a single artifact at the lens's disclosure mode, recording the
    /// access. Refuses (via the disclosure layer) any artifact the lens does
    /// not admit, so a known id cannot bypass the policy.
    pub fn get_item(&mut self, artifact_id: &ArtifactId) -> Result<RenderedContext, ReceiptError> {
        let rc = disclosure::render_item(self.vault, &self.lens, artifact_id, self.allow_full)?;
        self.receipt.queries.push(QueryRecord {
            query_id: format!("qry_{}", ulid::Ulid::new()),
            timestamp: chrono::Utc::now(),
            query_text: format!("get_item {}", artifact_id.0),
            artifacts_accessed: vec![ArtifactAccess {
                artifact_id: rc.artifact_id.0.clone(),
                artifact_title: rc.title.clone().unwrap_or_default(),
                disclosure_mode: rc.mode.as_str().to_owned(),
                bytes_disclosed: rc.bytes_disclosed,
            }],
        });
        Ok(rc)
    }

    /// Record a rate-limit rejection into the receipt (the refused call itself
    /// is not counted as a query).
    pub fn record_rate_limit(&mut self, tool: &str, detail: &str) {
        self.receipt.rate_limit_events.push(RateLimitEvent {
            timestamp: chrono::Utc::now(),
            tool: tool.to_owned(),
            detail: detail.to_owned(),
        });
    }

    /// Number of queries recorded so far.
    pub fn query_count(&self) -> usize {
        self.receipt.queries.len()
    }

    /// Whether anything worth persisting happened (a query or a rate-limit
    /// event). Used to avoid finalizing empty receipts.
    pub fn has_activity(&self) -> bool {
        !self.receipt.queries.is_empty() || !self.receipt.rate_limit_events.is_empty()
    }

    /// Finalize: fill summary + `ended_at`, compute `self_hash`, and write
    /// `receipts/<id>.json`. Returns the finalized receipt.
    pub fn finalize(mut self) -> Result<Receipt, ReceiptError> {
        self.receipt.ended_at = Some(chrono::Utc::now());
        self.receipt.summary = compute_summary(&self.receipt.queries);
        self.receipt.self_hash = Some(content_hash(&self.receipt)?);

        let dir = receipts_dir(self.vault);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.json", self.receipt.receipt_id));
        std::fs::write(&path, serde_json::to_vec_pretty(&self.receipt)?)?;
        Ok(self.receipt)
    }
}

/// All finalized receipts in the vault, sorted by sequence.
fn load_all_sorted(vault: &Vault) -> Result<Vec<Receipt>, ReceiptError> {
    let dir = receipts_dir(vault);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut receipts = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(&path)?;
        receipts.push(serde_json::from_slice::<Receipt>(&bytes)?);
    }
    receipts.sort_by_key(|r| r.seq);
    Ok(receipts)
}

/// List all finalized receipts, oldest first.
pub fn list(vault: &Vault) -> Result<Vec<Receipt>, ReceiptError> {
    load_all_sorted(vault)
}

/// Load one receipt by id.
pub fn load(vault: &Vault, receipt_id: &str) -> Result<Receipt, ReceiptError> {
    let path = receipts_dir(vault).join(format!("{receipt_id}.json"));
    if !path.exists() {
        return Err(ReceiptError::NotFound(receipt_id.to_owned()));
    }
    Ok(serde_json::from_slice(&std::fs::read(&path)?)?)
}

/// Walk the receipt chain, verifying self-integrity and linkage. Returns the
/// number of receipts verified; any tamper (edited content, altered hash,
/// broken link, missing/duplicated sequence) is a [`ReceiptError::ChainBroken`].
pub fn verify(vault: &Vault) -> Result<usize, ReceiptError> {
    let receipts = load_all_sorted(vault)?;
    for (i, r) in receipts.iter().enumerate() {
        if r.seq != i as u64 {
            return Err(ReceiptError::ChainBroken {
                seq: r.seq,
                reason: format!("sequence gap: expected {i}, found {}", r.seq),
            });
        }
        let stored = r.self_hash.as_ref().ok_or(ReceiptError::ChainBroken {
            seq: r.seq,
            reason: "missing self_hash (never finalized)".into(),
        })?;
        let recomputed = content_hash(r)?;
        if &recomputed != stored {
            return Err(ReceiptError::ChainBroken {
                seq: r.seq,
                reason: "content hash mismatch — receipt was edited".into(),
            });
        }
        let expected_prev = if i == 0 {
            None
        } else {
            receipts[i - 1].self_hash.clone()
        };
        if r.prev_receipt_hash != expected_prev {
            return Err(ReceiptError::ChainBroken {
                seq: r.seq,
                reason: "prev-hash link does not match the previous receipt".into(),
            });
        }
    }
    Ok(receipts.len())
}

/// Render a receipt as a self-contained HTML document (inline CSS, no external
/// assets) suitable for archiving or sharing.
pub fn export_html(r: &Receipt) -> String {
    fn esc(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    let mut rows = String::new();
    for q in &r.queries {
        let arts = if q.artifacts_accessed.is_empty() {
            "<em>none</em>".to_string()
        } else {
            q.artifacts_accessed
                .iter()
                .map(|a| {
                    format!(
                        "<div>{} <span class=\"mode\">{}</span> <span class=\"bytes\">{} B</span></div>",
                        esc(&a.artifact_title),
                        esc(&a.disclosure_mode),
                        a.bytes_disclosed
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{arts}</td></tr>",
            esc(&q.timestamp.to_rfc3339()),
            esc(&q.query_text),
        ));
    }

    let ended = r
        .ended_at
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| "—".into());
    let prev = r.prev_receipt_hash.as_deref().unwrap_or("(genesis)");
    let self_hash = r.self_hash.as_deref().unwrap_or("(unfinalized)");

    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Tessera receipt {rid}</title>
<style>
  body {{ font: 15px/1.5 -apple-system, system-ui, sans-serif; max-width: 820px;
         margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }}
  h1 {{ font-size: 1.3rem; }}
  .meta {{ background: #f6f6f7; border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
  .meta div {{ margin: 0.15rem 0; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ text-align: left; vertical-align: top; padding: 0.5rem;
            border-bottom: 1px solid #e2e2e4; }}
  .mode {{ color: #6634e0; font-weight: 600; }}
  .bytes {{ color: #777; }}
  code {{ font-size: 12px; word-break: break-all; }}
  .stat {{ display: inline-block; margin-right: 1.5rem; }}
</style></head><body>
<h1>Tessera access receipt</h1>
<div class="meta">
  <div><strong>Receipt:</strong> <code>{rid}</code></div>
  <div><strong>Session:</strong> <code>{sid}</code></div>
  <div><strong>Agent:</strong> {agent} (<code>{agent_id}</code>)</div>
  <div><strong>Lens:</strong> {lens} (<code>{lens_id}</code>)</div>
  <div><strong>Purpose:</strong> {purpose}</div>
  <div><strong>Started:</strong> {started} &nbsp; <strong>Ended:</strong> {ended}</div>
</div>
<div>
  <span class="stat"><strong>{total_q}</strong> queries</span>
  <span class="stat"><strong>{uniq}</strong> unique artifacts</span>
  <span class="stat"><strong>{bytes}</strong> bytes disclosed</span>
  <span class="stat">modes: {modes}</span>
  <span class="stat"><strong>{rate_limits}</strong> rate-limit events</span>
</div>
<table>
  <thead><tr><th>Time</th><th>Query</th><th>Artifacts disclosed</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
<div class="meta">
  <div><strong>seq:</strong> {seq}</div>
  <div><strong>prev hash:</strong> <code>{prev}</code></div>
  <div><strong>self hash:</strong> <code>{self_hash}</code></div>
</div>
</body></html>"#,
        rid = esc(&r.receipt_id),
        sid = esc(&r.session_id),
        agent = esc(&r.agent.name),
        agent_id = esc(&r.agent.agent_id),
        lens = esc(&r.lens.name),
        lens_id = esc(&r.lens.lens_id),
        purpose = esc(&r.purpose),
        started = esc(&r.started_at.to_rfc3339()),
        ended = esc(&ended),
        total_q = r.summary.total_queries,
        uniq = r.summary.unique_artifacts_accessed,
        bytes = r.summary.total_bytes_disclosed,
        modes = esc(&r.summary.disclosure_modes_used.join(", ")),
        rate_limits = r.rate_limit_events.len(),
        seq = r.seq,
        prev = esc(prev),
        self_hash = esc(self_hash),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{self, ArtifactState};
    use crate::crypto::KdfParams;
    use crate::embed::{EmbedError, EmbeddingProvider};
    use crate::lens::{DisclosureMode, LensPolicy};
    use crate::space::{self, SpaceId};
    use crate::{chunk, extract, inbox, summary};
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
            for w in text.to_lowercase().as_bytes().windows(3) {
                let h = (w[0] as usize * 961 + w[1] as usize * 31 + w[2] as usize) % 384;
                v[h] += 1.0;
            }
            let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm > 0.0 {
                v.iter_mut().for_each(|x| *x /= norm);
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
        summary::generate(vault, &artifact, false).expect("summary");
        artifact::set_state(vault, &artifact, ArtifactState::Live).expect("live");
    }

    fn recorded_vault() -> (tempfile::TempDir, Vault, LensPolicy) {
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
        search::embed_missing(&vault, &FakeEmbedder).expect("embed");

        let mut lens = LensPolicy::new("reader", vec![space]);
        lens.disclosure_mode = DisclosureMode::Summary;
        lens.sensitivity_ceiling = crate::artifact::Sensitivity::Restricted;
        (dir, vault, lens)
    }

    fn agent() -> AgentRef {
        AgentRef {
            agent_id: "agent_test".into(),
            name: "Test Agent".into(),
        }
    }

    #[test]
    fn session_records_every_query() {
        let (_dir, vault, lens) = recorded_vault();
        let mut session =
            Session::open(&vault, agent(), &lens, "answer questions", false).expect("open");

        session
            .query(&FakeEmbedder, "fire rating corridor", 5)
            .expect("q1");
        session
            .query(&FakeEmbedder, "bread fermentation", 5)
            .expect("q2");
        assert_eq!(session.query_count(), 2);

        let receipt = session.finalize().expect("finalize");
        assert_eq!(receipt.queries.len(), 2, "every query recorded");
        assert_eq!(receipt.summary.total_queries, 2);
        assert!(
            receipt.summary.total_bytes_disclosed == 0,
            "summary mode discloses 0 bytes"
        );
        assert_eq!(
            receipt.summary.disclosure_modes_used,
            vec!["summary".to_string()]
        );
        assert!(receipt.self_hash.is_some(), "finalize sets self_hash");
        // The receipt file exists on disk.
        assert!(receipts_dir(&vault)
            .join(format!("{}.json", receipt.receipt_id))
            .exists());
    }

    #[test]
    fn chain_links_and_verifies() {
        let (_dir, vault, lens) = recorded_vault();

        let mut s1 = Session::open(&vault, agent(), &lens, "first", false).expect("open");
        s1.query(&FakeEmbedder, "fire", 5).expect("q");
        let r1 = s1.finalize().expect("finalize 1");

        let mut s2 = Session::open(&vault, agent(), &lens, "second", false).expect("open");
        s2.query(&FakeEmbedder, "bread", 5).expect("q");
        let r2 = s2.finalize().expect("finalize 2");

        assert_eq!(r1.seq, 0);
        assert_eq!(r1.prev_receipt_hash, None, "genesis has no prev");
        assert_eq!(r2.seq, 1);
        assert_eq!(
            r2.prev_receipt_hash, r1.self_hash,
            "second links to the first"
        );

        assert_eq!(verify(&vault).expect("verify"), 2);
    }

    #[test]
    fn editing_a_finalized_receipt_breaks_verification() {
        let (_dir, vault, lens) = recorded_vault();
        let mut s1 = Session::open(&vault, agent(), &lens, "first", false).expect("open");
        s1.query(&FakeEmbedder, "fire", 5).expect("q");
        let r1 = s1.finalize().expect("finalize");
        // A clean chain verifies.
        assert_eq!(verify(&vault).expect("clean"), 1);

        // Tamper: change the recorded query text in the stored JSON.
        let path = receipts_dir(&vault).join(format!("{}.json", r1.receipt_id));
        let text = std::fs::read_to_string(&path).expect("read");
        let tampered = text.replace("\"first\"", "\"forged-purpose\"");
        assert_ne!(tampered, text, "tamper actually changed the file");
        std::fs::write(&path, tampered).expect("write");

        assert!(
            matches!(verify(&vault), Err(ReceiptError::ChainBroken { .. })),
            "editing a finalized receipt must break verification"
        );
    }

    #[test]
    fn html_export_is_standalone_and_complete() {
        let (_dir, vault, lens) = recorded_vault();
        let mut s = Session::open(&vault, agent(), &lens, "reporting", false).expect("open");
        s.query(&FakeEmbedder, "fire rating", 5).expect("q");
        let r = s.finalize().expect("finalize");

        let html = export_html(&r);
        assert!(html.starts_with("<!doctype html>"), "standalone doc");
        assert!(
            !html.contains("http://") && !html.contains("https://"),
            "no external assets"
        );
        assert!(html.contains(&r.receipt_id));
        assert!(html.contains("reader"), "lens name shown");
        assert!(html.contains("reporting"), "purpose shown");
        assert!(
            html.contains(r.self_hash.as_deref().unwrap()),
            "self hash shown"
        );
    }
}
