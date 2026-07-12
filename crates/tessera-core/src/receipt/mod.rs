//! Receipts — versioned, hash-chained records of what an agent accessed.
//!
//! A [`Session`] binds a vault + lens and is the ONLY path that produces
//! disclosed query results: every [`Session::query`] appends a query record
//! before returning, so no disclosed answer can escape without being recorded
//! (the enforcement lives here in core, not in any CLI). [`Session::finalize`]
//! writes `receipts/<id>.json` embedding a BLAKE3 hash of the previous
//! receipt; [`verify`] walks the chain and fails if any receipt was edited.

use serde::{Deserialize, Serialize};
use std::io::Write;
use thiserror::Error;

use crate::artifact::ArtifactId;
use crate::blob::BlobHash;
use crate::disclosure::{self, DisclosureError, RenderedContext};
use crate::embed::EmbeddingProvider;
use crate::lens::{DisclosureMode, LensPolicy};
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
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("receipt finalization interrupted at {0}")]
    FinalizationInterrupted(&'static str),
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

fn receipt_v1() -> u32 {
    1
}

fn is_v1(version: &u32) -> bool {
    *version == 1
}

/// How a disclosure was selected. Legacy receipts did not distinguish this.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessKind {
    #[default]
    Legacy,
    SemanticQuery,
    DirectItem,
}

/// Exact byte range in the encrypted evidence blob that produced the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

/// Producer record needed to trace the disclosed derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRef {
    pub id: String,
    pub tool: String,
    pub tool_version: Option<String>,
    pub locality: String,
}

/// Embedding model that selected a semantic result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRef {
    pub name: String,
    pub version: String,
    pub dimensions: u32,
}

/// Ranking evidence for semantic retrieval. Direct item access has none.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalEvidence {
    pub rank: u32,
    pub score: f32,
    pub model: ModelRef,
}

/// Immutable effective policy captured when the receipt session opens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EffectiveLens {
    pub policy: LensPolicy,
    pub policy_hash: String,
}

/// Persisted Guardian identity to bind to a receipt session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBinding {
    pub session_id: String,
    pub pairing_id: Option<String>,
}

/// Record of one artifact disclosed during a query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactAccess {
    pub artifact_id: String,
    pub artifact_title: String,
    /// v1 compatibility alias for `applied_disclosure_mode`.
    pub disclosure_mode: String,
    pub bytes_disclosed: u64,
    #[serde(default)]
    pub access_kind: AccessKind,
    #[serde(default)]
    pub artifact_version_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_text_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_id: Option<String>,
    #[serde(default)]
    pub evidence_blob_hash: String,
    #[serde(default)]
    pub disclosed_range: Option<ByteRange>,
    #[serde(default)]
    pub disclosed_content_hash: String,
    #[serde(default)]
    pub returned_bytes: u64,
    #[serde(default)]
    pub requested_disclosure_mode: String,
    #[serde(default)]
    pub applied_disclosure_mode: String,
    #[serde(default)]
    pub metadata_allowed: bool,
    #[serde(default)]
    pub full_disclosure_allowed: bool,
    #[serde(default)]
    pub provenance: Vec<ProvenanceRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval: Option<RetrievalEvidence>,
}

/// A single query within a session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// A versioned, hash-chained record of session activity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    #[serde(default = "receipt_v1", skip_serializing_if = "is_v1")]
    pub schema_version: u32,
    pub receipt_id: String,
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_id: Option<String>,
    pub agent: AgentRef,
    pub lens: LensRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_lens: Option<EffectiveLens>,
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
    let bytes = if receipt.schema_version == 1 {
        #[derive(Serialize)]
        struct LegacyAccess<'a> {
            artifact_id: &'a str,
            artifact_title: &'a str,
            disclosure_mode: &'a str,
            bytes_disclosed: u64,
        }
        #[derive(Serialize)]
        struct LegacyQuery<'a> {
            query_id: &'a str,
            timestamp: &'a chrono::DateTime<chrono::Utc>,
            query_text: &'a str,
            artifacts_accessed: Vec<LegacyAccess<'a>>,
        }
        #[derive(Serialize)]
        struct LegacyReceipt<'a> {
            receipt_id: &'a str,
            session_id: &'a str,
            agent: &'a AgentRef,
            lens: &'a LensRef,
            purpose: &'a str,
            started_at: &'a chrono::DateTime<chrono::Utc>,
            ended_at: &'a Option<chrono::DateTime<chrono::Utc>>,
            queries: Vec<LegacyQuery<'a>>,
            summary: &'a ReceiptSummary,
            rate_limit_events: &'a [RateLimitEvent],
            seq: u64,
            prev_receipt_hash: &'a Option<String>,
            self_hash: Option<String>,
        }

        let queries = receipt
            .queries
            .iter()
            .map(|query| LegacyQuery {
                query_id: &query.query_id,
                timestamp: &query.timestamp,
                query_text: &query.query_text,
                artifacts_accessed: query
                    .artifacts_accessed
                    .iter()
                    .map(|access| LegacyAccess {
                        artifact_id: &access.artifact_id,
                        artifact_title: &access.artifact_title,
                        disclosure_mode: &access.disclosure_mode,
                        bytes_disclosed: access.bytes_disclosed,
                    })
                    .collect(),
            })
            .collect();
        serde_json::to_vec(&LegacyReceipt {
            receipt_id: &receipt.receipt_id,
            session_id: &receipt.session_id,
            agent: &receipt.agent,
            lens: &receipt.lens,
            purpose: &receipt.purpose,
            started_at: &receipt.started_at,
            ended_at: &receipt.ended_at,
            queries,
            summary: &receipt.summary,
            rate_limit_events: &receipt.rate_limit_events,
            seq: receipt.seq,
            prev_receipt_hash: &receipt.prev_receipt_hash,
            self_hash: None,
        })?
    } else {
        let mut canonical = receipt.clone();
        canonical.self_hash = None;
        serde_json::to_vec(&canonical)?
    };
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
            // v2 counts every byte actually returned, including derived
            // summaries. `bytes_disclosed` remains the v1 verbatim-source
            // count for compatibility and disclosure-mode diagnostics.
            total_bytes += a.returned_bytes;
        }
    }
    ReceiptSummary {
        total_queries: queries.len() as u32,
        unique_artifacts_accessed: unique.len() as u32,
        total_bytes_disclosed: total_bytes,
        disclosure_modes_used: modes.into_iter().collect(),
    }
}

type EvidenceOrigin = (String, Option<String>, Option<String>, String);

fn evidence_origin(
    vault: &Vault,
    artifact_id: &str,
    mode: DisclosureMode,
    chunk_id: Option<&str>,
) -> Result<EvidenceOrigin, ReceiptError> {
    if mode == DisclosureMode::Summary {
        return Ok(vault.conn().query_row(
            "SELECT av.id, s.id, s.blob_hash
             FROM summaries s
             JOIN artifact_versions av ON av.id = s.artifact_version_id
             WHERE av.artifact_id = ?1
             ORDER BY av.version DESC, s.updated_at DESC LIMIT 1",
            [artifact_id],
            |row| Ok((row.get(0)?, None, Some(row.get(1)?), row.get(2)?)),
        )?);
    }

    if let Some(chunk_id) = chunk_id {
        return Ok(vault.conn().query_row(
            "SELECT av.id, dt.id, dt.blob_hash
             FROM chunks ch
             JOIN derived_text dt ON dt.id = ch.derived_text_id
             JOIN artifact_versions av ON av.id = dt.artifact_version_id
             WHERE ch.id = ?1 AND av.artifact_id = ?2",
            rusqlite::params![chunk_id, artifact_id],
            |row| Ok((row.get(0)?, Some(row.get(1)?), None, row.get(2)?)),
        )?);
    }

    Ok(vault.conn().query_row(
        "SELECT av.id, dt.id, dt.blob_hash
         FROM derived_text dt
         JOIN artifact_versions av ON av.id = dt.artifact_version_id
         WHERE av.artifact_id = ?1
         ORDER BY av.version DESC, dt.created_at DESC LIMIT 1",
        [artifact_id],
        |row| Ok((row.get(0)?, Some(row.get(1)?), None, row.get(2)?)),
    )?)
}

fn provenance_for_blob(vault: &Vault, blob_hash: &str) -> Result<Vec<ProvenanceRef>, ReceiptError> {
    let mut stmt = vault.conn().prepare(
        "SELECT id, tool, tool_version, locality
         FROM provenance WHERE derived_blob_hash = ?1 ORDER BY created_at, id",
    )?;
    let records = stmt
        .query_map([blob_hash], |row| {
            Ok(ProvenanceRef {
                id: row.get(0)?,
                tool: row.get(1)?,
                tool_version: row.get(2)?,
                locality: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(records)
}

fn build_access(
    vault: &Vault,
    rendered: &RenderedContext,
    chunk_id: Option<&str>,
    access_kind: AccessKind,
    requested_mode: DisclosureMode,
    allow_full: bool,
    retrieval: Option<RetrievalEvidence>,
) -> Result<ArtifactAccess, ReceiptError> {
    let (artifact_version_id, derived_text_id, summary_id, evidence_blob_hash) =
        evidence_origin(vault, &rendered.artifact_id.0, rendered.mode, chunk_id)?;
    let returned_bytes = rendered.body.len() as u64;
    let disclosed_range = if rendered.mode == DisclosureMode::Summary {
        Some(ByteRange {
            start: 0,
            end: returned_bytes,
        })
    } else {
        rendered
            .disclosed_range
            .map(|(start, end)| ByteRange { start, end })
    };

    Ok(ArtifactAccess {
        artifact_id: rendered.artifact_id.0.clone(),
        artifact_title: rendered.title.clone().unwrap_or_default(),
        disclosure_mode: rendered.mode.as_str().to_owned(),
        bytes_disclosed: rendered.bytes_disclosed,
        access_kind,
        artifact_version_id,
        derived_text_id,
        chunk_id: chunk_id.map(str::to_owned),
        summary_id,
        evidence_blob_hash: evidence_blob_hash.clone(),
        disclosed_range,
        disclosed_content_hash: blake3::hash(rendered.body.as_bytes()).to_hex().to_string(),
        returned_bytes,
        requested_disclosure_mode: requested_mode.as_str().to_owned(),
        applied_disclosure_mode: rendered.mode.as_str().to_owned(),
        metadata_allowed: rendered.title.is_some(),
        full_disclosure_allowed: allow_full,
        provenance: provenance_for_blob(vault, &evidence_blob_hash)?,
        retrieval,
    })
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
    /// Open a session without reserving a receipt-chain position. The final
    /// sequence and predecessor are assigned atomically at finalization.
    /// `allow_full` decides whether a `full` lens is honored (else it
    /// fail-closes to excerpt in the disclosure renderer).
    pub fn open(
        vault: &'v Vault,
        agent: AgentRef,
        lens: &LensPolicy,
        purpose: impl Into<String>,
        allow_full: bool,
    ) -> Result<Self, ReceiptError> {
        Self::open_bound(
            vault,
            agent,
            lens,
            purpose,
            allow_full,
            SessionBinding {
                session_id: format!("sess_{}", ulid::Ulid::new()),
                pairing_id: None,
            },
        )
    }

    /// Open a receipt bound to an already-persisted Guardian live session.
    pub fn open_bound(
        vault: &'v Vault,
        agent: AgentRef,
        lens: &LensPolicy,
        purpose: impl Into<String>,
        allow_full: bool,
        binding: SessionBinding,
    ) -> Result<Self, ReceiptError> {
        let now = chrono::Utc::now();
        let policy_bytes = serde_json::to_vec(lens)?;
        let receipt = Receipt {
            schema_version: 2,
            receipt_id: format!("rcpt_{}", ulid::Ulid::new()),
            session_id: binding.session_id,
            pairing_id: binding.pairing_id,
            agent,
            lens: LensRef {
                lens_id: lens.id.0.clone(),
                name: lens.name.clone(),
            },
            effective_lens: Some(EffectiveLens {
                policy: lens.clone(),
                policy_hash: blake3::hash(&policy_bytes).to_hex().to_string(),
            }),
            purpose: purpose.into(),
            started_at: now,
            ended_at: None,
            queries: Vec::new(),
            summary: ReceiptSummary::default(),
            rate_limit_events: Vec::new(),
            // Placeholders only. `finalize_receipt` assigns both while holding
            // SQLite's brief chain-head write lock.
            seq: 0,
            prev_receipt_hash: None,
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
            let rank = accesses.len() as u32 + 1;
            accesses.push(build_access(
                self.vault,
                &rc,
                Some(&hit.chunk_id),
                AccessKind::SemanticQuery,
                self.lens.disclosure_mode,
                self.allow_full,
                Some(RetrievalEvidence {
                    rank,
                    score: hit.relevance_score,
                    model: ModelRef {
                        name: embedder
                            .model_version()
                            .split('@')
                            .next()
                            .unwrap_or(embedder.model_version())
                            .to_owned(),
                        version: embedder.model_version().to_owned(),
                        dimensions: embedder.dimensions() as u32,
                    },
                }),
            )?);
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
            artifacts_accessed: vec![build_access(
                self.vault,
                &rc,
                None,
                AccessKind::DirectItem,
                self.lens.disclosure_mode,
                self.allow_full,
                None,
            )?],
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

    /// Finalize under the vault's serialized chain-head commit.
    pub fn finalize(mut self) -> Result<Receipt, ReceiptError> {
        self.receipt.ended_at = Some(chrono::Utc::now());
        self.receipt.summary = compute_summary(&self.receipt.queries);
        finalize_receipt(self.vault, self.receipt, None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalizeFailpoint {
    BeforeCommit,
    AfterCommit,
}

fn prepared_path(vault: &Vault, receipt_id: &str) -> std::path::PathBuf {
    receipts_dir(vault).join(format!(".{receipt_id}.prepared"))
}

fn final_path(vault: &Vault, receipt_id: &str) -> std::path::PathBuf {
    receipts_dir(vault).join(format!("{receipt_id}.json"))
}

fn rollback(conn: &rusqlite::Connection) {
    let _ = conn.execute_batch("ROLLBACK");
}

fn sync_dir(path: &std::path::Path) -> Result<(), ReceiptError> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

/// Complete the filesystem half of any receipt whose index/head transaction
/// committed before the prepared file could be renamed into place.
fn recover_committed_files(vault: &Vault) -> Result<(), ReceiptError> {
    let dir = receipts_dir(vault);
    std::fs::create_dir_all(&dir)?;
    let mut stmt = vault
        .conn()
        .prepare("SELECT receipt_id, file_name FROM receipts_index ORDER BY seq")?;
    let indexed = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);

    for (receipt_id, file_name) in indexed {
        let expected_name = format!("{receipt_id}.json");
        if file_name != expected_name {
            return Err(ReceiptError::ChainBroken {
                seq: 0,
                reason: format!("unsafe or inconsistent indexed filename for {receipt_id}"),
            });
        }
        let final_file = dir.join(file_name);
        if final_file.exists() {
            continue;
        }
        let prepared = prepared_path(vault, &receipt_id);
        if !prepared.exists() {
            return Err(ReceiptError::ChainBroken {
                seq: 0,
                reason: format!(
                    "committed receipt {receipt_id} has neither final nor prepared file"
                ),
            });
        }
        if let Err(error) = std::fs::rename(&prepared, &final_file) {
            // Another process may have completed the same deterministic
            // recovery after our existence check.
            if !final_file.exists() {
                return Err(error.into());
            }
        }
        sync_dir(&dir)?;
    }
    Ok(())
}

fn verify_chain_records(vault: &Vault, receipts: &[Receipt]) -> Result<(), ReceiptError> {
    for (i, receipt) in receipts.iter().enumerate() {
        if receipt.seq != i as u64 {
            return Err(ReceiptError::ChainBroken {
                seq: receipt.seq,
                reason: format!("sequence gap: expected {i}, found {}", receipt.seq),
            });
        }
        let stored = receipt
            .self_hash
            .as_ref()
            .ok_or(ReceiptError::ChainBroken {
                seq: receipt.seq,
                reason: "missing self_hash (never finalized)".into(),
            })?;
        let recomputed = content_hash(receipt)?;
        if &recomputed != stored {
            return Err(ReceiptError::ChainBroken {
                seq: receipt.seq,
                reason: "content hash mismatch — receipt was edited".into(),
            });
        }
        let expected_prev = if i == 0 {
            None
        } else {
            receipts[i - 1].self_hash.clone()
        };
        if receipt.prev_receipt_hash != expected_prev {
            return Err(ReceiptError::ChainBroken {
                seq: receipt.seq,
                reason: "prev-hash link does not match the previous receipt".into(),
            });
        }
        verify_disclosures(vault, receipt)?;
    }
    Ok(())
}

/// Populate the durable index for a pre-0010 vault, but only after its file
/// chain verifies. Re-check under `BEGIN IMMEDIATE` so concurrent openers
/// cannot both backfill.
fn ensure_receipt_index(vault: &Vault) -> Result<(), ReceiptError> {
    let conn = vault.conn();
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> Result<(), ReceiptError> {
        let indexed: i64 =
            conn.query_row("SELECT COUNT(*) FROM receipts_index", [], |row| row.get(0))?;
        if indexed > 0 {
            conn.execute_batch("COMMIT")?;
            return Ok(());
        }

        let receipts = load_all_sorted(vault)?;
        verify_chain_records(vault, &receipts)?;
        for receipt in &receipts {
            let self_hash =
                receipt
                    .self_hash
                    .as_deref()
                    .ok_or_else(|| ReceiptError::ChainBroken {
                        seq: receipt.seq,
                        reason: "legacy backfill found an unfinalized receipt".into(),
                    })?;
            conn.execute(
                "INSERT INTO receipts_index
                   (receipt_id, seq, prev_receipt_hash, self_hash, file_name, committed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    receipt.receipt_id,
                    receipt.seq as i64,
                    receipt.prev_receipt_hash,
                    self_hash,
                    format!("{}.json", receipt.receipt_id),
                    receipt.ended_at.unwrap_or(receipt.started_at).to_rfc3339()
                ],
            )?;
        }
        let next_seq = receipts.len() as i64;
        let head_hash = receipts
            .last()
            .and_then(|receipt| receipt.self_hash.as_deref());
        conn.execute(
            "UPDATE receipt_chain_state
             SET next_seq = ?1, head_hash = ?2, updated_at = ?3
             WHERE singleton = 1",
            rusqlite::params![next_seq, head_hash, chrono::Utc::now().to_rfc3339()],
        )?;
        conn.execute_batch("COMMIT")?;
        Ok(())
    })();
    if result.is_err() {
        rollback(conn);
    }
    result
}

fn finalize_receipt(
    vault: &Vault,
    mut receipt: Receipt,
    failpoint: Option<FinalizeFailpoint>,
) -> Result<Receipt, ReceiptError> {
    recover_committed_files(vault)?;
    ensure_receipt_index(vault)?;

    let dir = receipts_dir(vault);
    std::fs::create_dir_all(&dir)?;
    let prepared = prepared_path(vault, &receipt.receipt_id);
    let final_file = final_path(vault, &receipt.receipt_id);
    if prepared.exists() || final_file.exists() {
        return Err(ReceiptError::ChainBroken {
            seq: receipt.seq,
            reason: format!("duplicate receipt id {}", receipt.receipt_id),
        });
    }

    let conn = vault.conn();
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let transaction_result = (|| -> Result<(), ReceiptError> {
        let (next_seq, head_hash): (i64, Option<String>) = conn.query_row(
            "SELECT next_seq, head_hash FROM receipt_chain_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let (indexed_count, indexed_head): (i64, Option<String>) = conn.query_row(
            "SELECT COUNT(*),
                    (SELECT self_hash FROM receipts_index ORDER BY seq DESC LIMIT 1)
             FROM receipts_index",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if next_seq != indexed_count || head_hash != indexed_head {
            return Err(ReceiptError::ChainBroken {
                seq: next_seq.max(0) as u64,
                reason: "durable receipt chain head and index disagree".into(),
            });
        }
        receipt.seq = next_seq as u64;
        receipt.prev_receipt_hash = head_hash;
        receipt.self_hash = Some(content_hash(&receipt)?);

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&prepared)?;
        file.write_all(&serde_json::to_vec_pretty(&receipt)?)?;
        file.sync_all()?;

        if failpoint == Some(FinalizeFailpoint::BeforeCommit) {
            return Err(ReceiptError::FinalizationInterrupted("before commit"));
        }

        let self_hash = receipt
            .self_hash
            .as_deref()
            .ok_or_else(|| ReceiptError::ChainBroken {
                seq: receipt.seq,
                reason: "finalization did not compute self hash".into(),
            })?;
        conn.execute(
            "INSERT INTO receipts_index
               (receipt_id, seq, prev_receipt_hash, self_hash, file_name, committed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                receipt.receipt_id,
                receipt.seq as i64,
                receipt.prev_receipt_hash,
                self_hash,
                format!("{}.json", receipt.receipt_id),
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
        conn.execute(
            "UPDATE receipt_chain_state
             SET next_seq = ?1, head_hash = ?2, updated_at = ?3
             WHERE singleton = 1",
            rusqlite::params![next_seq + 1, self_hash, chrono::Utc::now().to_rfc3339()],
        )?;
        conn.execute_batch("COMMIT")?;
        Ok(())
    })();

    if let Err(error) = transaction_result {
        rollback(conn);
        let _ = std::fs::remove_file(&prepared);
        return Err(error);
    }
    if failpoint == Some(FinalizeFailpoint::AfterCommit) {
        return Err(ReceiptError::FinalizationInterrupted("after commit"));
    }

    std::fs::rename(&prepared, &final_file)?;
    sync_dir(&dir)?;
    Ok(receipt)
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
    recover_committed_files(vault)?;
    ensure_receipt_index(vault)?;
    load_all_sorted(vault)
}

/// Load one receipt by id.
pub fn load(vault: &Vault, receipt_id: &str) -> Result<Receipt, ReceiptError> {
    recover_committed_files(vault)?;
    ensure_receipt_index(vault)?;
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
    recover_committed_files(vault)?;
    ensure_receipt_index(vault)?;
    let receipts = load_all_sorted(vault)?;
    verify_chain_records(vault, &receipts)?;

    let mut stmt = vault.conn().prepare(
        "SELECT receipt_id, seq, prev_receipt_hash, self_hash
         FROM receipts_index ORDER BY seq",
    )?;
    let indexed = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if indexed.len() != receipts.len() {
        return Err(ReceiptError::ChainBroken {
            seq: receipts.len() as u64,
            reason: format!(
                "receipt directory/index count mismatch: files={}, index={}",
                receipts.len(),
                indexed.len()
            ),
        });
    }
    for (receipt, (id, seq, prev, self_hash)) in receipts.iter().zip(indexed) {
        if receipt.receipt_id != id
            || receipt.seq != seq
            || receipt.prev_receipt_hash != prev
            || receipt.self_hash.as_deref() != Some(self_hash.as_str())
        {
            return Err(ReceiptError::ChainBroken {
                seq: receipt.seq,
                reason: "receipt directory and durable index disagree".into(),
            });
        }
    }
    let (next_seq, head_hash): (i64, Option<String>) = vault.conn().query_row(
        "SELECT next_seq, head_hash FROM receipt_chain_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let expected_head = receipts
        .last()
        .and_then(|receipt| receipt.self_hash.clone());
    if next_seq != receipts.len() as i64 || head_hash != expected_head {
        return Err(ReceiptError::ChainBroken {
            seq: next_seq.max(0) as u64,
            reason: "durable receipt chain head does not match verified files".into(),
        });
    }
    Ok(receipts.len())
}

/// Reconstruct and hash every v2 disclosure from its encrypted backing blob.
/// v1 receipts remain chain-verifiable but lack enough evidence for this check.
pub fn verify_disclosures(vault: &Vault, receipt: &Receipt) -> Result<(), ReceiptError> {
    if receipt.schema_version < 2 {
        return Ok(());
    }

    let effective_lens =
        receipt
            .effective_lens
            .as_ref()
            .ok_or_else(|| ReceiptError::ChainBroken {
                seq: receipt.seq,
                reason: "v2 receipt is missing its effective lens snapshot".into(),
            })?;
    let policy_hash = blake3::hash(&serde_json::to_vec(&effective_lens.policy)?)
        .to_hex()
        .to_string();
    if policy_hash != effective_lens.policy_hash {
        return Err(ReceiptError::ChainBroken {
            seq: receipt.seq,
            reason: "effective lens policy hash mismatch".into(),
        });
    }

    for query in &receipt.queries {
        for access in &query.artifacts_accessed {
            if access.access_kind == AccessKind::Legacy
                || access.artifact_version_id.is_empty()
                || access.evidence_blob_hash.is_empty()
                || access.disclosed_content_hash.is_empty()
            {
                return Err(ReceiptError::ChainBroken {
                    seq: receipt.seq,
                    reason: format!(
                        "v2 access for {} is missing exact disclosure evidence",
                        access.artifact_id
                    ),
                });
            }

            let relation_count: i64 = if let Some(summary_id) = &access.summary_id {
                vault.conn().query_row(
                    "SELECT COUNT(*) FROM summaries s
                     JOIN artifact_versions av ON av.id = s.artifact_version_id
                     WHERE s.id = ?1 AND av.id = ?2 AND av.artifact_id = ?3
                       AND s.blob_hash = ?4",
                    rusqlite::params![
                        summary_id,
                        access.artifact_version_id,
                        access.artifact_id,
                        access.evidence_blob_hash
                    ],
                    |row| row.get(0),
                )?
            } else if let Some(chunk_id) = &access.chunk_id {
                vault.conn().query_row(
                    "SELECT COUNT(*) FROM chunks ch
                     JOIN derived_text dt ON dt.id = ch.derived_text_id
                     JOIN artifact_versions av ON av.id = dt.artifact_version_id
                     WHERE ch.id = ?1 AND dt.id = ?2 AND av.id = ?3
                       AND av.artifact_id = ?4 AND dt.blob_hash = ?5",
                    rusqlite::params![
                        chunk_id,
                        access.derived_text_id,
                        access.artifact_version_id,
                        access.artifact_id,
                        access.evidence_blob_hash
                    ],
                    |row| row.get(0),
                )?
            } else {
                vault.conn().query_row(
                    "SELECT COUNT(*) FROM derived_text dt
                     JOIN artifact_versions av ON av.id = dt.artifact_version_id
                     WHERE dt.id = ?1 AND av.id = ?2 AND av.artifact_id = ?3
                       AND dt.blob_hash = ?4",
                    rusqlite::params![
                        access.derived_text_id,
                        access.artifact_version_id,
                        access.artifact_id,
                        access.evidence_blob_hash
                    ],
                    |row| row.get(0),
                )?
            };
            if relation_count != 1 {
                return Err(ReceiptError::ChainBroken {
                    seq: receipt.seq,
                    reason: format!(
                        "source references for {} do not identify one stored derivation",
                        access.artifact_id
                    ),
                });
            }

            for provenance in &access.provenance {
                let count: i64 = vault.conn().query_row(
                    "SELECT COUNT(*) FROM provenance
                     WHERE id = ?1 AND derived_blob_hash = ?2 AND tool = ?3
                       AND COALESCE(tool_version, '') = COALESCE(?4, '')
                       AND locality = ?5",
                    rusqlite::params![
                        provenance.id,
                        access.evidence_blob_hash,
                        provenance.tool,
                        provenance.tool_version,
                        provenance.locality
                    ],
                    |row| row.get(0),
                )?;
                if count != 1 {
                    return Err(ReceiptError::ChainBroken {
                        seq: receipt.seq,
                        reason: format!("provenance reference {} is invalid", provenance.id),
                    });
                }
            }

            if let Some(retrieval) = &access.retrieval {
                let chunk_id =
                    access
                        .chunk_id
                        .as_deref()
                        .ok_or_else(|| ReceiptError::ChainBroken {
                            seq: receipt.seq,
                            reason: "semantic access is missing its chunk id".into(),
                        })?;
                let stored_model: String = vault.conn().query_row(
                    "SELECT model_version FROM embeddings_map WHERE chunk_id = ?1",
                    [chunk_id],
                    |row| row.get(0),
                )?;
                if stored_model != retrieval.model.version {
                    return Err(ReceiptError::ChainBroken {
                        seq: receipt.seq,
                        reason: format!("embedding model mismatch for chunk {chunk_id}"),
                    });
                }
            }

            let bytes = vault
                .blobs()
                .get(vault.dek()?, &BlobHash(access.evidence_blob_hash.clone()))
                .map_err(VaultError::Blob)?;
            let range = access
                .disclosed_range
                .ok_or_else(|| ReceiptError::ChainBroken {
                    seq: receipt.seq,
                    reason: format!("missing disclosure range for {}", access.artifact_id),
                })?;
            let disclosed = bytes
                .get(range.start as usize..range.end as usize)
                .ok_or_else(|| ReceiptError::ChainBroken {
                    seq: receipt.seq,
                    reason: format!("invalid disclosure range for {}", access.artifact_id),
                })?;
            if disclosed.len() as u64 != access.returned_bytes
                || blake3::hash(disclosed).to_hex().as_str() != access.disclosed_content_hash
            {
                return Err(ReceiptError::ChainBroken {
                    seq: receipt.seq,
                    reason: format!("disclosed content hash mismatch for {}", access.artifact_id),
                });
            }
        }
    }
    Ok(())
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

    fn finalize_at(
        session: Session<'_>,
        failpoint: FinalizeFailpoint,
    ) -> Result<Receipt, ReceiptError> {
        let Session {
            vault, mut receipt, ..
        } = session;
        receipt.ended_at = Some(chrono::Utc::now());
        receipt.summary = compute_summary(&receipt.queries);
        finalize_receipt(vault, receipt, Some(failpoint))
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
            receipt.summary.total_bytes_disclosed > 0,
            "v2 summary counts the exact derived bytes returned"
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
    fn v2_receipt_binds_exact_disclosure_policy_model_and_live_session() {
        let (_dir, vault, mut lens) = recorded_vault();
        lens.disclosure_mode = DisclosureMode::Excerpt;
        lens.max_quote_chars = Some(24);
        let binding = SessionBinding {
            session_id: "sess_live_123".into(),
            pairing_id: Some("pair_123".into()),
        };
        let mut session =
            Session::open_bound(&vault, agent(), &lens, "verify evidence", false, binding)
                .expect("open bound");

        let disclosed = session
            .query(&FakeEmbedder, "fire rating corridor", 1)
            .expect("query");
        let returned = disclosed[0].body.clone();
        let receipt = session.finalize().expect("finalize");
        let access = &receipt.queries[0].artifacts_accessed[0];

        assert_eq!(receipt.schema_version, 2);
        assert_eq!(receipt.session_id, "sess_live_123");
        assert_eq!(receipt.pairing_id.as_deref(), Some("pair_123"));
        let effective_lens = receipt.effective_lens.as_ref().expect("lens snapshot");
        assert_eq!(effective_lens.policy.id, lens.id);
        assert_eq!(
            effective_lens.policy_hash,
            blake3::hash(&serde_json::to_vec(&lens).expect("lens json"))
                .to_hex()
                .to_string()
        );
        assert_eq!(access.access_kind, AccessKind::SemanticQuery);
        assert_eq!(access.requested_disclosure_mode, "excerpt");
        assert_eq!(access.applied_disclosure_mode, "excerpt");
        assert_eq!(
            access.disclosed_content_hash,
            blake3::hash(returned.as_bytes()).to_hex().to_string()
        );
        assert!(access.artifact_version_id.starts_with("artv_"));
        assert!(access
            .derived_text_id
            .as_deref()
            .is_some_and(|id| id.starts_with("dtx_")));
        assert!(access
            .chunk_id
            .as_deref()
            .is_some_and(|id| id.starts_with("chunk_")));
        assert!(access.disclosed_range.is_some());
        assert!(!access.provenance.is_empty());
        let retrieval = access.retrieval.as_ref().expect("retrieval evidence");
        assert_eq!(retrieval.rank, 1);
        assert_eq!(retrieval.model.version, "fake-trigram@1");
        assert_eq!(retrieval.model.dimensions, 384);
        verify_disclosures(&vault, &receipt).expect("exact disclosure verifies");
    }

    #[test]
    fn v1_receipt_json_remains_readable() {
        let (_dir, vault, lens) = recorded_vault();
        let mut session = Session::open(&vault, agent(), &lens, "legacy", false).expect("open");
        session.query(&FakeEmbedder, "fire", 1).expect("query");
        let receipt = session.finalize().expect("finalize");
        let mut json = serde_json::to_value(receipt).expect("json");
        let object = json.as_object_mut().expect("object");
        object.remove("schema_version");
        object.remove("pairing_id");
        object.remove("effective_lens");
        for access in object["queries"]
            .as_array_mut()
            .expect("queries")
            .iter_mut()
            .flat_map(|query| {
                query["artifacts_accessed"]
                    .as_array_mut()
                    .expect("accesses")
                    .iter_mut()
            })
        {
            let access = access.as_object_mut().expect("access");
            access.retain(|key, _| {
                matches!(
                    key.as_str(),
                    "artifact_id" | "artifact_title" | "disclosure_mode" | "bytes_disclosed"
                )
            });
        }

        let mut legacy: Receipt = serde_json::from_value(json).expect("v1 receipt parses");
        assert_eq!(legacy.schema_version, 1);
        assert!(legacy.effective_lens.is_none());
        assert_eq!(
            legacy.queries[0].artifacts_accessed[0].access_kind,
            AccessKind::Legacy
        );
        legacy.self_hash = Some(content_hash(&legacy).expect("legacy canonical hash"));
        std::fs::write(
            receipts_dir(&vault).join(format!("{}.json", legacy.receipt_id)),
            serde_json::to_vec_pretty(&legacy).expect("legacy json"),
        )
        .expect("write legacy receipt");
        // Model a vault created before migration 0010: the valid file chain
        // exists, but no durable receipt index has been populated yet.
        vault
            .conn()
            .execute_batch(
                "DELETE FROM receipts_index;
                 UPDATE receipt_chain_state
                 SET next_seq = 0, head_hash = NULL WHERE singleton = 1;",
            )
            .expect("clear index for legacy backfill");
        assert_eq!(verify(&vault).expect("v1 chain still verifies"), 1);
    }

    #[test]
    fn finalized_v2_receipt_satisfies_the_shipped_json_schema() {
        let (_dir, vault, mut lens) = recorded_vault();
        lens.disclosure_mode = DisclosureMode::Excerpt;
        let mut session = Session::open(&vault, agent(), &lens, "schema", false).expect("open");
        session.query(&FakeEmbedder, "fire", 1).expect("query");
        let receipt = session.finalize().expect("finalize");

        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../../spec/receipt.schema.json"))
                .expect("schema json");
        let validator = jsonschema::validator_for(&schema).expect("valid schema");
        let instance = serde_json::to_value(receipt).expect("receipt json");
        let errors = validator
            .iter_errors(&instance)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "schema errors: {errors:#?}");

        let mut incomplete = instance;
        incomplete["queries"][0]["artifacts_accessed"][0]
            .as_object_mut()
            .expect("access object")
            .remove("disclosed_content_hash");
        assert!(
            !validator.is_valid(&incomplete),
            "schema must reject incomplete v2 disclosure evidence"
        );
    }

    #[test]
    fn v2_covers_summary_direct_access_and_full_downgrade() {
        let (_dir, vault, mut lens) = recorded_vault();

        let mut summary_session =
            Session::open(&vault, agent(), &lens, "summary", false).expect("open summary");
        let summary_result = summary_session
            .query(&FakeEmbedder, "fire", 1)
            .expect("summary query");
        let summary_receipt = summary_session.finalize().expect("summary receipt");
        let summary_access = &summary_receipt.queries[0].artifacts_accessed[0];
        assert!(summary_access.summary_id.is_some());
        assert_eq!(
            summary_access.returned_bytes,
            summary_result[0].body.len() as u64
        );
        verify_disclosures(&vault, &summary_receipt).expect("summary evidence");

        lens.disclosure_mode = DisclosureMode::Full;
        let artifact = ArtifactId(summary_access.artifact_id.clone());
        let mut direct_session =
            Session::open(&vault, agent(), &lens, "direct", false).expect("open direct");
        direct_session.get_item(&artifact).expect("direct get");
        let direct_receipt = direct_session.finalize().expect("direct receipt");
        let direct_access = &direct_receipt.queries[0].artifacts_accessed[0];
        assert_eq!(direct_access.access_kind, AccessKind::DirectItem);
        assert_eq!(direct_access.requested_disclosure_mode, "full");
        assert_eq!(direct_access.applied_disclosure_mode, "excerpt");
        assert!(direct_access.retrieval.is_none());
        verify_disclosures(&vault, &direct_receipt).expect("direct evidence");
    }

    #[test]
    fn tampering_any_v2_binding_breaks_chain_verification() {
        let (_dir, vault, mut lens) = recorded_vault();
        lens.disclosure_mode = DisclosureMode::Excerpt;
        let mut session = Session::open(&vault, agent(), &lens, "tamper", false).expect("open");
        session.query(&FakeEmbedder, "fire", 1).expect("query");
        let receipt = session.finalize().expect("finalize");
        let path = receipts_dir(&vault).join(format!("{}.json", receipt.receipt_id));
        let original: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json");

        type Mutation = Box<dyn Fn(&mut serde_json::Value)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|v| v["session_id"] = "sess_forged".into()),
            Box::new(|v| v["effective_lens"]["policy"]["name"] = "forged".into()),
            Box::new(|v| {
                v["queries"][0]["artifacts_accessed"][0]["disclosed_range"]["end"] = 1.into()
            }),
            Box::new(|v| {
                v["queries"][0]["artifacts_accessed"][0]["disclosed_content_hash"] =
                    "0".repeat(64).into()
            }),
            Box::new(|v| v["queries"][0]["artifacts_accessed"][0]["retrieval"]["rank"] = 99.into()),
            Box::new(|v| v["queries"][0]["artifacts_accessed"][0]["retrieval"]["score"] = 0.into()),
            Box::new(|v| {
                v["queries"][0]["artifacts_accessed"][0]["retrieval"]["model"]["version"] =
                    "forged@9".into()
            }),
        ];

        for mutate in mutations {
            let mut tampered = original.clone();
            mutate(&mut tampered);
            std::fs::write(
                &path,
                serde_json::to_vec_pretty(&tampered).expect("serialize"),
            )
            .expect("write tamper");
            assert!(
                matches!(verify(&vault), Err(ReceiptError::ChainBroken { .. })),
                "every bound v2 field is covered by verification"
            );
        }
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&original).expect("serialize"),
        )
        .expect("restore");
        assert_eq!(verify(&vault).expect("restored"), 1);
    }

    #[test]
    fn two_sessions_open_together_finalize_in_completion_order() {
        let (_dir, vault, lens) = recorded_vault();
        let first = Session::open(&vault, agent(), &lens, "opened first", false).expect("open 1");
        let second = Session::open(&vault, agent(), &lens, "opened second", false).expect("open 2");

        let completed_first = second.finalize().expect("finalize second opener");
        let completed_second = first.finalize().expect("finalize first opener");
        assert_eq!(completed_first.seq, 0);
        assert_eq!(completed_second.seq, 1);
        assert_eq!(
            completed_second.prev_receipt_hash,
            completed_first.self_hash
        );
        assert_eq!(verify(&vault).expect("chain"), 2);
    }

    #[test]
    fn twenty_concurrent_finalizers_produce_one_contiguous_chain() {
        use std::sync::{Arc, Barrier};

        let (_dir, vault, lens) = recorded_vault();
        let path = vault.path().to_path_buf();
        drop(vault);
        let barrier = Arc::new(Barrier::new(20));
        let handles = (0..20)
            .map(|index| {
                let path = path.clone();
                let lens = lens.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let vault = Vault::open(&path, "pass").expect("thread vault");
                    let session =
                        Session::open(&vault, agent(), &lens, format!("worker {index}"), false)
                            .expect("thread session");
                    barrier.wait();
                    session.finalize().expect("thread finalize")
                })
            })
            .collect::<Vec<_>>();

        let mut finalized = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .collect::<Vec<_>>();
        finalized.sort_by_key(|receipt| receipt.seq);
        assert_eq!(
            finalized
                .iter()
                .map(|receipt| receipt.seq)
                .collect::<Vec<_>>(),
            (0..20).collect::<Vec<_>>()
        );
        let vault = Vault::open(&path, "pass").expect("reopen");
        assert_eq!(verify(&vault).expect("verify stress chain"), 20);
    }

    #[test]
    fn interrupted_finalization_recovers_only_committed_receipts() {
        let (_dir, vault, lens) = recorded_vault();

        let before = Session::open(&vault, agent(), &lens, "before", false).expect("open");
        assert!(matches!(
            finalize_at(before, FinalizeFailpoint::BeforeCommit),
            Err(ReceiptError::FinalizationInterrupted("before commit"))
        ));
        assert!(load_all_sorted(&vault).expect("files").is_empty());
        let indexed: i64 = vault
            .conn()
            .query_row("SELECT COUNT(*) FROM receipts_index", [], |row| row.get(0))
            .expect("index count");
        assert_eq!(indexed, 0, "pre-commit failure is not visible");

        let after = Session::open(&vault, agent(), &lens, "after", false).expect("open");
        assert!(matches!(
            finalize_at(after, FinalizeFailpoint::AfterCommit),
            Err(ReceiptError::FinalizationInterrupted("after commit"))
        ));
        assert!(load_all_sorted(&vault).expect("not renamed yet").is_empty());
        assert_eq!(
            verify(&vault).expect("verification recovers committed file"),
            1
        );
        assert_eq!(load_all_sorted(&vault).expect("recovered").len(), 1);
    }

    #[test]
    fn duplicate_id_and_directory_index_disagreement_fail_closed() {
        let (_dir, vault, lens) = recorded_vault();
        let original = Session::open(&vault, agent(), &lens, "original", false)
            .expect("open")
            .finalize()
            .expect("finalize");

        let mut duplicate =
            Session::open(&vault, agent(), &lens, "duplicate", false).expect("open duplicate");
        duplicate.receipt.receipt_id = original.receipt_id.clone();
        assert!(matches!(
            duplicate.finalize(),
            Err(ReceiptError::ChainBroken { .. })
        ));
        assert!(
            vault
                .conn()
                .execute(
                    "INSERT INTO receipts_index
                       (receipt_id, seq, self_hash, file_name, committed_at)
                     VALUES ('rcpt_other', 0, 'hash', 'rcpt_other.json', 'now')",
                    [],
                )
                .is_err(),
            "duplicate chain positions are rejected by the durable index"
        );

        vault
            .conn()
            .execute(
                "UPDATE receipt_chain_state SET head_hash = 'forged' WHERE singleton = 1",
                [],
            )
            .expect("corrupt head");
        let blocked = Session::open(&vault, agent(), &lens, "blocked", false).expect("open");
        assert!(matches!(
            blocked.finalize(),
            Err(ReceiptError::ChainBroken { .. })
        ));
        vault
            .conn()
            .execute(
                "UPDATE receipt_chain_state SET next_seq = 1, head_hash = ?1 WHERE singleton = 1",
                [original.self_hash.as_deref().expect("hash")],
            )
            .expect("restore head");

        std::fs::remove_file(final_path(&vault, &original.receipt_id)).expect("remove final file");
        assert!(matches!(
            verify(&vault),
            Err(ReceiptError::ChainBroken { .. })
        ));
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
