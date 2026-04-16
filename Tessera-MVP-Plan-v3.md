# TESSERA

## MVP Implementation Plan

**Version 3.0 — Strategic Revision | April 2026**

*The Trust Substrate for Agentic AI*
*Curate your context. Control your agents. Prove what happened.*

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Market Context and Timing](#market-context-and-timing)
3. [Product Principles](#product-principles)
4. [MVP Goal](#mvp-goal)
5. [Architecture](#architecture)
6. [Core Concepts](#core-concepts)
7. [Security and Encryption](#security-and-encryption)
8. [Lens Policy Schema](#lens-policy-schema)
9. [Disclosure Rendering and Receipts](#disclosure-rendering-and-receipts)
10. [Gateway API](#gateway-api)
11. [Performance Budgets](#performance-budgets)
12. [Iteration Plan](#iteration-plan)
13. [v0.1 Fast-Follow: Team Foundations](#v01-fast-follow-team-foundations)
14. [MVP Definition of Done](#mvp-definition-of-done)
15. [Strategic Positioning](#strategic-positioning)
16. [Future Enhancements](#future-enhancements)
17. [Appendix A: Suggested Rust Dependencies](#appendix-a-suggested-rust-dependencies)
18. [Appendix B: File Type Support](#appendix-b-file-type-support-v0)
19. [Appendix C: Sensitivity Levels](#appendix-c-sensitivity-levels)
20. [Appendix D: Glossary](#appendix-d-glossary)

---

## Executive Summary

Tessera is the trust substrate for agentic AI: a curated, user-owned personal context vault with granular disclosure controls and auditable receipts. Users curate what matters, then grant AI agents permission to only what they need, for a specific task, for a bounded duration.

The name draws from the Roman *tessera* — a physical token that proved specific access had been granted, for a specific purpose, by a specific authority. Tessera is that proof layer for the age of AI agents.

This document describes the v3 strategic revision of the Tessera MVP plan. It incorporates market signals from the emergence of Mythos-class frontier models and the broader shift toward constrained, policy-governed agent deployment. The core thesis has not changed — but the urgency, positioning, and roadmap sequencing have.

**What changed from v2:** Tessera is no longer positioned solely as a personal productivity vault. It is positioned as **agent control infrastructure** — with the personal vault as the entry wedge and the policy/audit layer as the durable product.

### The Strategic Shift

Frontier models are becoming more capable and more agentic simultaneously. Anthropic, OpenAI, and others are restricting access to the most powerful systems through structured programs rather than open release. Enterprise buyers are splitting into two tracks: cheap broad usage for low-risk tasks, and high-trust policy-governed agents for consequential work.

This means the moat is shifting from raw model access to operational control surfaces: permissioning, scoped memory, evidence trails, human approval workflows, and tenant isolation. Tessera sits precisely at this intersection.

The key insight: *the model itself may commoditize faster than the surrounding operational trust stack.* Tessera is that trust stack.

---

## Market Context and Timing

### Why Now

Several converging signals indicate that the market is arriving at Tessera's thesis from the demand side:

- **Capability without containment is a liability.** As frontier models grow more capable at autonomous execution, enterprises are asking not "can the model do this?" but "under what authority structure may it act?"
- **The wrapper tax is getting brutal.** Startups that merely wrap a model in optimism get crushed as providers absorb generic use cases. The survivors own proprietary context, enforcement, or policy layers.
- **Agent topology replaces prompt engineering.** The design questions becoming central — which agent gets which tools, what can it read, what is logged, what is reversible — are systems design problems, not prompt problems.
- **Open source matters most in the orchestration layer.** Frontier models get gated; the control plane around model use is where builders differentiate, self-host, and own their stack.
- **Cybersecurity is a forcing function.** Even non-security products must now account for agent sandboxing, secrets segregation, action-level approval gates, and signed audit trails.

### Where Tessera Fits

Tessera occupies the emerging "AI-safe infrastructure" category:

| Infrastructure Need | Tessera Primitive |
|---|---|
| Can the model safely act here? | Lens policies with default-deny |
| Under what policy? | Context Lenses: per agent, per task, per sensitivity |
| Against which data? | Spaces with hierarchical isolation |
| With what evidence? | Receipts: immutable session records |
| With what auditability? | Full audit trail: who, what, when, why |
| With what rollback? | Session revocation and token expiry |
| With what tenant separation? | Space isolation — no cross-boundary retrieval |

### Competitive Positioning

Tessera is not competing with chat apps, note apps, or wearable recorders. It complements all of them.

| Category | What They Do | Why Tessera Is Different |
|---|---|---|
| Always-on capture (Rewind, Limitless) | Record everything, search later | Curation-first: nothing enters without intent |
| App-specific memory (ChatGPT, Claude) | Vendor-locked, opaque retention | User-owned, portable, model-agnostic |
| Agent frameworks (LangChain, CrewAI) | Orchestrate model calls | Govern what agents can access, not just what they do |
| Enterprise AI platforms | Centralized model deployment | Decentralized trust: user controls context, not IT |

---

## Product Principles

Six hard rules that govern every design decision. These are non-negotiable.

1. **Nothing is collected automatically.** All data enters the vault by explicit user action. No ambient recording, no silent ingestion, no background capture.
2. **Default deny.** Agents see nothing unless a user grants a scoped lens. Access is opt-in, purpose-bound, and time-limited.
3. **Minimize disclosure.** Agents get the smallest slice required for the task: summary, excerpt, or full artifact only when explicitly needed.
4. **Prove what happened.** Every access is logged. Receipts record what was requested, what was granted, what was used, and by whom.
5. **User-owned and portable.** Exportable, inspectable, revocable. No vendor memory lock-in. Your vault survives model churn and tool changes.
6. **Open source foundation.** The core engine, policy layer, and gateway are open source. Trust requires inspectability.

---

## MVP Goal

Ship a Mac-first local vault that lets a user:

- Create Spaces and import artifacts (PDF, MD, TXT, images)
- Build Lens policies (scoped access rules with default-deny)
- Grant multiple desktop-native agents purpose-bound access via a local gateway
- Answer queries using Policy-RAG (HNSW semantic retrieval + SQLite metadata filters)
- Produce receipts that prove what was accessed, by which agent, for what purpose
- Support concurrent sessions for multiple agents with independent lenses

### Explicit Non-Goals for v0

- Cloud sync or remote hosting
- Always-on capture or recording of any kind
- Mobile apps
- Multi-user collaboration (v0.1 target)
- Training or fine-tuning models

### What Changed from v2

- **Multi-agent sessions are now a v0 requirement**, not a future enhancement. Each agent in an orchestrated pipeline gets its own session, lens, and receipt.
- **The gateway API is designed for agent topology**, not just single-agent access. Concurrent sessions, independent policy evaluation, and cross-session audit are first-class.
- **The CLI checkpoint is elevated to a strategic decision gate.** If retrieval quality and policy enforcement prove out, the full build proceeds. If not, iterate before UI investment.
- **Team/multi-user spaces are on the v0.1 fast track**, not the distant future. The B2B demand signal is too strong to defer.

---

## Architecture

### Components

| Component | Technology | Responsibility |
|---|---|---|
| **tessera-core** | Rust library | Vault storage, ingestion, extraction, chunking, embeddings, HNSW index, policy evaluation, disclosure rendering, receipts |
| **tessera-gateway** | Rust daemon | Localhost API, agent registry, multi-session management, purpose binding, query routing, activity stream, receipt finalization |
| **tessera-mac** | SwiftUI app | Spaces UI, import, tagging, lens builder, agent grant dialog, multi-session monitor, receipt viewer |
| **tessera-cli** | Rust binary | Command-line vault operations, evaluation harness, diagnostics (v0.0 validation gate) |

### Storage Foundations

| Layer | Technology | Contents |
|---|---|---|
| Metadata | SQLite (WAL mode) | Spaces, artifacts, versions, tags, chunks, embeddings map, lenses, sessions, agents, audit logs |
| Blobs | Encrypted file store (XChaCha20-Poly1305) | Original files, derived text, thumbnails |
| Vector index | HNSW (instant-distance or similar) | Chunk embeddings for semantic search |
| Receipts | JSON files + HTML export | Immutable session records with human-readable views |

### Directory Structure

```
Vault/
├── vault.db              # SQLite database
├── vault.key             # Encrypted DEK (actual key in Keychain)
├── blobs/
│   ├── ab/
│   │   └── ab3f2c...     # Content-addressed encrypted blobs
│   └── ...
├── index/
│   ├── hnsw.idx          # Vector index
│   └── hnsw.meta         # Index metadata
├── receipts/
│   ├── sess_abc123.json
│   └── sess_abc123.html  # Human-readable
└── exports/              # User-requested exports
```

### Multi-Agent Session Model

This is a key architectural differentiator. Tessera does not assume a single agent interacts with the vault at a time. The gateway supports concurrent sessions with fully independent policy evaluation:

- **Session isolation:** Each agent session has its own token, lens binding, purpose declaration, and TTL. No session can see another session's activity.
- **Independent policy paths:** Agent A querying under Lens X and Agent B querying under Lens Y are evaluated independently. Policy violations in one session do not affect the other.
- **Cross-session audit:** The receipt viewer can show all sessions for a time window, enabling the user to see the full picture of agent activity across their vault.
- **Orchestration-ready:** An orchestration layer (e.g., Orkestr or any pipeline coordinator) can request sessions for multiple specialist agents, each with appropriately scoped lenses, and the vault handles them as independent trust boundaries.

This design directly supports the "agent topology" pattern: multiple coordinated agents, each with the minimum context required for its role.

---

## Core Concepts

### Spaces

Hierarchical containers for organizing artifacts. Spaces enforce hard isolation boundaries — no query can cross a space boundary unless the active lens explicitly includes both spaces.

### Artifacts

Individual files or documents with metadata, tags, sensitivity labels, and version history. Content-addressed for deduplication.

### Chunks

Segments of extracted text, sized for embedding and retrieval. Each chunk maintains a link to its source artifact and precise byte offsets for citation.

### Lenses

Reusable access policies that define what an agent can see and how. A lens specifies included spaces, content types, tag filters, disclosure modes, sensitivity ceilings, and allowed operations. Lenses are the primary governance primitive.

### Sessions

Time-bounded, purpose-declared access grants. An agent requests a session with a specific lens and stated purpose; the gateway mints a scoped token; all queries within the session are logged to a receipt.

### Receipts

Immutable records of what was accessed during a session. The "prove what happened" primitive. Receipts record agent identity, lens used, purpose, every query, every artifact touched, disclosure mode applied, and timestamps. Named for the product's own etymology — each receipt is a tessera, proof that access was authorized.

---

## Security and Encryption

### Vault Key Derivation

- User provides a passphrase on vault creation
- Derive a 256-bit vault key using Argon2id (64 MB memory, 3 iterations, parallelism 4, random 16-byte salt)
- Vault key encrypts a randomly generated Data Encryption Key (DEK)
- DEK encrypts all blobs via XChaCha20-Poly1305 with unique 24-byte nonces
- macOS: DEK stored in Keychain, keyed by vault path; optional Touch ID unlock

### Threat Model (v0)

| Protected Against | Not Protected Against |
|---|---|
| Stolen laptop (disk at rest) | Malware with memory access |
| Disk access without passphrase | Keylogger during unlock |
| Casual snooping | Targeted forensic analysis |
| Unauthorized agent access (token enforcement) | Compromised gateway process |

### Agent Trust Model

Agents are "trusted on this device" after user-initiated pairing. No cryptographic attestation in v0.

- Agent registers with the gateway, receives a 6-character pairing code (expires in 5 minutes, single use)
- User verifies the code in the Mac app and clicks Approve
- Gateway issues a long-lived agent token (revocable)
- Sessions are separate from pairing: each session requires a lens, purpose, and TTL
- User can revoke any agent instantly from the Mac app

---

## Lens Policy Schema

The lens is the heart of Tessera's governance model. It is deliberately minimal but expressive.

| Field | Type | Description |
|---|---|---|
| `space_ids` | string[] | Spaces to include (required) |
| `space_exclude_ids` | string[] | Spaces to explicitly exclude (overrides include) |
| `tag_include` | string[] | Only include artifacts with these tags |
| `tag_exclude` | string[] | Exclude artifacts with these tags |
| `content_types` | string[] | Allowed file types: pdf, docx, md, txt, png, jpg |
| `disclosure_mode` | enum | `summary`, `excerpt`, or `full` |
| `max_quote_chars` | int | Max verbatim text per excerpt (only if mode = excerpt) |
| `allow_metadata` | bool | Include title, date, tags in response |
| `operations` | string[] | `answer`, `draft`, `extract`, `cite` |
| `sensitivity_ceiling` | enum | `public`, `internal`, `confidential`, `restricted` |
| `approval_rule` | enum | `never`, `always`, `on_sensitive` |
| `default_ttl_minutes` | int | Default session duration |

### Example Lens Policy

```json
{
  "id": "lens_3f2a",
  "name": "ClientA ProjectX Specs Only",
  "space_ids": ["space_clientA_projectX"],
  "space_exclude_ids": [],
  "tag_include": ["spec", "code"],
  "tag_exclude": ["personal", "journal"],
  "content_types": ["pdf", "docx", "md"],
  "disclosure_mode": "excerpt",
  "max_quote_chars": 800,
  "allow_metadata": true,
  "operations": ["answer", "draft", "cite"],
  "sensitivity_ceiling": "confidential",
  "approval_rule": "on_sensitive",
  "default_ttl_minutes": 60
}
```

### Policy Enforcement Strategy

For HNSW (which does not support pre-filtering):

1. Retrieve top-N candidates from vector index (N = 5 × K)
2. Join to chunk metadata in SQLite
3. Filter by lens constraints: space membership, tag include/exclude, content type, sensitivity ceiling
4. If fewer than K results, increase N and retry (up to max cap)
5. Return top K valid results with disclosure rendering applied

---

## Disclosure Rendering and Receipts

### Disclosure Modes

| Mode | Returns | Does Not Return |
|---|---|---|
| summary-only | Artifact title, type, date, tags, one-sentence summary | Any verbatim text from the artifact |
| excerpt-only | Artifact metadata + verbatim excerpts up to max_quote_chars with byte offsets | Full content beyond excerpt bounds |
| full | Complete artifact content (disabled by default in v0 UI) | Nothing withheld (prominently logged in receipt) |

### Receipt Structure

Every session produces a receipt. Receipts are the foundation of Tessera's trust story.

A receipt contains:

- **Session metadata:** agent identity, lens used, declared purpose, start/end timestamps
- **Query log:** each query with timestamp, retrieved artifacts, disclosure mode applied, bytes disclosed
- **Approval log:** user actions (auto-approve, manual approve, deny)
- **Summary statistics:** total queries, unique artifacts accessed, total bytes disclosed, disclosure modes used
- **Export formats:** JSON (machine-readable) and HTML (human-readable)

### Example Receipt (JSON)

```json
{
  "receipt_id": "rcpt_def456",
  "session_id": "sess_abc123",
  "agent": {
    "agent_id": "agent_abc123",
    "name": "Claude Desktop"
  },
  "lens": {
    "lens_id": "lens_3f2a",
    "name": "ClientA ProjectX Specs Only"
  },
  "purpose": "Draft RFI response for fire safety",
  "started_at": "2026-04-15T14:00:00Z",
  "ended_at": "2026-04-15T14:35:00Z",
  "queries": [
    {
      "query_id": "q_001",
      "timestamp": "2026-04-15T14:05:00Z",
      "query_text": "What are the fire rating requirements?",
      "artifacts_accessed": [
        {
          "artifact_id": "art_abc123",
          "artifact_title": "Fire Safety Spec v3",
          "disclosure_mode": "excerpt",
          "bytes_disclosed": 847
        }
      ]
    }
  ],
  "summary": {
    "total_queries": 3,
    "unique_artifacts_accessed": 5,
    "total_bytes_disclosed": 2341,
    "disclosure_modes_used": ["excerpt", "summary"]
  }
}
```

---

## Gateway API

The gateway binds to `127.0.0.1` only. All endpoints except `/agents/register` require a valid token. Rate limited at 100 queries per minute per session.

| Method | Path | Description |
|---|---|---|
| `POST` | `/agents/register` | Initiate agent pairing |
| `GET` | `/agents` | List registered agents |
| `DELETE` | `/agents/{id}` | Revoke agent |
| `POST` | `/sessions` | Request access session (lens + purpose + TTL) |
| `GET` | `/sessions` | List active sessions |
| `GET` | `/sessions/{id}` | Get session details |
| `DELETE` | `/sessions/{id}` | Revoke session immediately |
| `GET` | `/sessions/{id}/stream` | SSE activity stream (real-time) |
| `POST` | `/query` | Execute policy-filtered retrieval |
| `POST` | `/receipts/{session_id}/finalize` | Close session and finalize receipt |
| `GET` | `/receipts/{id}` | Get receipt |
| `GET` | `/receipts/{id}/export` | Export receipt as HTML or JSON |
| `GET` | `/audit/sessions` | Cross-session audit view (time range) |

### New in v3: Cross-Session Audit

The `/audit/sessions` endpoint enables the user to query all sessions within a time window, across all agents. This supports the scenario where multiple agents are working concurrently and the user wants a unified view of vault activity. This is the foundation for the "who touched what" question that enterprises will demand.

### Query Request

```json
{
  "session_token": "...",
  "query": "What are the fire rating requirements for corridor walls?",
  "top_k": 5,
  "disclosure_override": null
}
```

### Query Response

```json
{
  "session_id": "sess_abc123",
  "results": [
    {
      "artifact_id": "art_abc123",
      "artifact_title": "Fire Safety Spec v3",
      "disclosure_mode": "excerpt",
      "content": "The minimum fire rating for corridor walls...",
      "citation": {
        "chunk_id": "chunk_xyz789",
        "byte_range": [1024, 1156],
        "relevance_score": 0.87
      }
    }
  ],
  "receipt_id": "rcpt_def456",
  "tokens_used": 1247
}
```

### Error Responses

All endpoints return structured errors:

| Error | Code | Retry |
|---|---|---|
| Rate limited | `ERR_RATE_LIMIT` | Yes (after backoff) |
| Temporary unavailable | `ERR_UNAVAILABLE` | Yes |
| Session expired | `ERR_SESSION_EXPIRED` | No (request new) |
| Invalid token | `ERR_INVALID_TOKEN` | No |
| Policy violation | `ERR_POLICY_VIOLATION` | No |
| Not found | `ERR_NOT_FOUND` | No |

---

## Performance Budgets

### Ingest

| Operation | Target | Notes |
|---|---|---|
| PDF extraction | < 2s per MB | Text layer only in v0 |
| Text chunking | < 100ms per doc | Includes tokenization |
| Embedding (local) | < 50ms per chunk | On Apple Silicon (all-MiniLM-L6-v2) |
| Total ingest | < 5s per doc | Typical 10-page PDF |

### Query

| Operation | Target | Notes |
|---|---|---|
| HNSW search | < 50ms | For 100k vectors |
| Policy filtering | < 20ms | SQLite join + filter |
| Disclosure rendering | < 30ms | Per result |
| Total query latency | < 200ms (p95) | End-to-end |

### Startup

| Operation | Target |
|---|---|
| Vault unlock | < 500ms |
| Index load | < 1s (100k vectors) |
| UI ready | < 2s |

### Memory

| State | Budget |
|---|---|
| Idle | < 100 MB |
| During ingest | < 500 MB |
| During query | < 200 MB |

### Retrieval Quality Gates

| Metric | Definition | Target |
|---|---|---|
| Recall@5 | Fraction of expected artifacts in top 5 | > 0.70 |
| Recall@10 | Fraction of expected artifacts in top 10 | > 0.85 |
| MRR | Mean reciprocal rank of first relevant result | > 0.60 |
| Policy degradation | Recall@10 drop from unfiltered to lens-filtered | < 10% |

---

## Iteration Plan

The iteration plan preserves the proven structure from v2 with three key changes: multi-agent session support is woven into the gateway iteration, the CLI checkpoint is elevated as a strategic gate, and team/multi-user foundations are added as a v0.1 fast-follow.

### Dependency Diagram

```
Iteration 0 (scaffolding)
    │
    ▼
Iteration 1 (vault, spaces, artifacts)
    │
    ├─── Mac app: vault picker, spaces (parallel)
    ▼
Iteration 2 (extraction + chunking)
    ▼
Iteration 3 (embeddings + HNSW)
    ▼
Iteration 4 (lens policies + policy-filtered retrieval)
    │
    ├─── Mac app: lens builder (parallel)
    ▼
Iteration 5 (disclosure, citations, receipts)
    ▼
═══ v0.0 CHECKPOINT: CLI validation + decision gate ═══
    ▼
Iteration 6 (gateway + multi-agent sessions)
    ▼
Iteration 7 (Mac UI: grants, monitor, receipts)
    ▼
Iteration 8 (hardening, packaging, ship)
    ▼
═══ v0.1 FAST-FOLLOW: team spaces + multi-user ═══
```

---

### Iteration 0: Foundations and Repo Scaffolding

*Duration: 1 week*

**Deliverables**

- Monorepo structure: `/core` (Rust workspace), `/gateway` (Rust binary), `/cli` (Rust binary), `/mac` (SwiftUI app), `/spec` (OpenAPI, JSON schemas)
- Shared protocol definitions: `gateway-api.yaml` (OpenAPI 3.0), `lens-policy.schema.json`, `receipt.schema.json`
- CI pipeline: `cargo fmt --check`, `cargo clippy`, `cargo test`, macOS build + unit tests
- Basic vault directory initializer

**Exit Criteria**

- `cargo test` passes for core and gateway
- Mac app builds and creates an empty vault directory
- CI green on main branch

---

### Iteration 1: Vault Storage, Spaces, Artifacts

*Duration: 2 weeks*

**Scope**

- Vault initialization with encryption (Argon2id + XChaCha20-Poly1305)
- Spaces CRUD with hierarchical nesting
- Artifact ingest pipeline with content-addressed encrypted blob store
- Deduplication (same file imported twice points to same blob)

**Core API**

```rust
fn create_vault(path: &Path, passphrase: &str) -> Result<Vault>;
fn open_vault(path: &Path, passphrase: &str) -> Result<Vault>;
fn create_space(vault: &Vault, name: &str, parent: Option<SpaceId>) -> Result<SpaceId>;
fn list_spaces(vault: &Vault) -> Result<Vec<Space>>;
fn import_files(vault: &Vault, space_id: SpaceId, paths: &[PathBuf]) -> Result<Vec<ArtifactId>>;
fn list_artifacts(vault: &Vault, space_id: SpaceId, filters: &Filters) -> Result<Vec<Artifact>>;
```

**Schema v0**

```sql
CREATE TABLE spaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    parent_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES spaces(id)
);

CREATE TABLE artifacts (
    id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    sensitivity TEXT DEFAULT 'internal',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (space_id) REFERENCES spaces(id)
);

CREATE TABLE artifact_versions (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    blob_hash TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
);

CREATE TABLE tags (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE artifact_tags (
    artifact_id TEXT NOT NULL,
    tag_id TEXT NOT NULL,
    PRIMARY KEY (artifact_id, tag_id),
    FOREIGN KEY (artifact_id) REFERENCES artifacts(id),
    FOREIGN KEY (tag_id) REFERENCES tags(id)
);
```

**Exit Criteria**

- Import 1,000 files without corruption
- Dedup verified (same file imported twice → same blob)
- Artifact listing < 100ms for 10k artifacts
- Encryption verified: blobs unreadable without passphrase
- Mac app: vault picker, spaces sidebar, drag-drop import, artifact list

---

### Iteration 2: Extraction and Chunking

*Duration: 1.5 weeks*

**Scope**

- Text extraction: PDF (text layer), Markdown, plain text
- Sentence-aware chunking: 512-token target, 64-token overlap
- Chunk offsets and hashes stored for citation precision
- Derived text stored as encrypted blob

**API**

```rust
fn extract_text(vault: &Vault, version_id: ArtifactVersionId) -> Result<DerivedTextId>;
fn chunk_text(vault: &Vault, derived_text_id: DerivedTextId) -> Result<Vec<ChunkId>>;
fn get_chunks(vault: &Vault, artifact_id: ArtifactId) -> Result<Vec<Chunk>>;
```

**Schema Additions**

```sql
CREATE TABLE derived_text (
    id TEXT PRIMARY KEY,
    artifact_version_id TEXT NOT NULL,
    blob_hash TEXT NOT NULL,
    extractor_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (artifact_version_id) REFERENCES artifact_versions(id)
);

CREATE TABLE chunks (
    id TEXT PRIMARY KEY,
    derived_text_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    byte_offset_start INTEGER NOT NULL,
    byte_offset_end INTEGER NOT NULL,
    token_count INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    section_heading TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (derived_text_id) REFERENCES derived_text(id)
);
```

**Exit Criteria**

- Queryable chunk corpus for imported PDFs and MD/TXT
- Extraction is deterministic (same input produces same chunks)
- Chunk boundaries respect sentences
- Re-extraction skipped for unchanged artifacts

---

### Iteration 3: Embeddings and HNSW Index

*Duration: 2 weeks*

**Scope**

- Pluggable `EmbeddingProvider` trait (default: `all-MiniLM-L6-v2` via ONNX Runtime, 384 dimensions)
- `VectorIndex` trait: insert, search, delete, persist, load
- Vector ID ↔ chunk ID mapping with model version tracking
- Index persistence and reload across vault open/close

**Traits**

```rust
trait EmbeddingProvider {
    fn embed(&self, text: &str) -> Result<Vec<f32>>;
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>>;
    fn model_version(&self) -> &str;
    fn dimensions(&self) -> usize;
}

trait VectorIndex {
    fn insert(&mut self, vector_id: u64, embedding: &[f32]) -> Result<()>;
    fn search(&self, query: &[f32], top_n: usize) -> Result<Vec<(u64, f32)>>;
    fn delete(&mut self, vector_id: u64) -> Result<()>;
    fn persist(&self, path: &Path) -> Result<()>;
    fn load(path: &Path) -> Result<Self>;
    fn len(&self) -> usize;
}
```

**Schema Additions**

```sql
CREATE TABLE embeddings_map (
    chunk_id TEXT NOT NULL,
    vector_id INTEGER NOT NULL,
    embedding_model_version TEXT NOT NULL,
    deprecated INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    PRIMARY KEY (chunk_id, embedding_model_version),
    FOREIGN KEY (chunk_id) REFERENCES chunks(id)
);

CREATE INDEX idx_embeddings_vector ON embeddings_map(vector_id);
```

**Exit Criteria**

- 10k+ chunks indexed
- Query returns relevant chunks in < 100ms
- Recall@10 > 0.70 on golden set (30–50 question/answer pairs)
- Vault reopen preserves index and mappings
- Model version tracked; reindex possible on upgrade

---

### Iteration 4: Lens Policies and Policy-Filtered Retrieval

*Duration: 2 weeks*

**Scope**

- LensPolicy model, storage, CRUD
- Policy evaluation producing retrieval constraints
- Post-retrieval filtering with over-fetch strategy

**API**

```rust
fn create_lens(vault: &Vault, policy: &LensPolicy) -> Result<LensId>;
fn get_lens(vault: &Vault, lens_id: LensId) -> Result<LensPolicy>;
fn list_lenses(vault: &Vault) -> Result<Vec<LensPolicy>>;
fn update_lens(vault: &Vault, lens_id: LensId, policy: &LensPolicy) -> Result<()>;
fn delete_lens(vault: &Vault, lens_id: LensId) -> Result<()>;

fn search_with_lens(
    vault: &Vault,
    lens_id: LensId,
    query: &str,
    top_k: usize
) -> Result<Vec<ChunkRef>>;
```

**Schema Additions**

```sql
CREATE TABLE lenses (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

**Exit Criteria**

- Space isolation provably enforced (test: similar content in blocked space never appears)
- Tag include/exclude, content type filtering, sensitivity ceiling all enforced
- Policy filtering degrades Recall@10 by < 10%
- Mac app: lens builder wizard, lens list, edit/delete

---

### Iteration 5: Disclosure, Citations, Receipts

*Duration: 2 weeks*

**Scope**

- Disclosure renderer: summary-only, excerpt-only (with max_quote_chars), full (disabled by default)
- Citation generation with artifact ID, version, chunk ID, byte offsets
- Receipt construction, storage, finalization, export (JSON + HTML)

**API**

```rust
fn render_context(
    vault: &Vault,
    chunks: &[ChunkRef],
    disclosure_mode: DisclosureMode,
    max_quote_chars: Option<usize>
) -> Result<ContextPack>;

fn create_receipt(vault: &Vault, session_id: SessionId) -> Result<ReceiptId>;
fn add_query_to_receipt(
    vault: &Vault,
    receipt_id: ReceiptId,
    query: &QueryRecord
) -> Result<()>;
fn finalize_receipt(vault: &Vault, receipt_id: ReceiptId) -> Result<Receipt>;
fn export_receipt(vault: &Vault, receipt_id: ReceiptId, format: ExportFormat) -> Result<Vec<u8>>;
```

**Exit Criteria**

- Every query produces a receipt
- Receipts are human-readable and include deterministic artifact lists
- Disclosure modes work correctly (summary has no verbatim text)
- Citations include valid byte offsets

---

### v0.0 Checkpoint: CLI Validation and Decision Gate

**This is the most important milestone in the plan.**

The CLI checkpoint validates the core value proposition before committing to UI investment. It answers: does policy-gated semantic retrieval over a curated corpus produce useful, auditable results?

**CLI Commands**

```bash
tessera init <path>                      # Create vault
tessera unlock <path>                    # Unlock vault
tessera space create <name>              # Create space
tessera import <space> <files...>        # Import files
tessera lens create                      # Interactive lens builder
tessera lens list                        # List lenses
tessera query --lens <id> "<question>"   # Query with citations
tessera receipt <id>                     # View receipt
tessera eval --golden <file>             # Run evaluation
tessera diag                             # Performance diagnostics
```

**Decision Gate**

- **Proceed:** Retrieval quality meets targets, policy enforcement is solid, receipts are useful. Continue to gateway and Mac app.
- **Iterate:** Retrieval quality is poor or policy filtering has gaps. Fix chunking, embeddings, or policy logic before UI investment.
- **Pivot:** Core thesis does not hold. Re-evaluate product direction.

---

### Iteration 6: Local Gateway with Multi-Agent Sessions

*Duration: 2.5 weeks*

**Scope — expanded from v2 to support multi-agent topology**

- Agent registration and pairing (6-char code, user approval)
- Multi-session management: concurrent sessions with independent policy evaluation
- Session token minting with agent_id, lens_id, purpose_hash, TTL, allowed_operations
- Query endpoint with policy enforcement and receipt linkage
- SSE activity stream per session
- Cross-session audit endpoint (`/audit/sessions`)
- Session expiry and immediate revocation

**Session Token Contents**

```json
{
  "session_id": "sess_abc123",
  "agent_id": "agent_xyz789",
  "lens_id": "lens_3f2a",
  "purpose_hash": "sha256:...",
  "ttl": 3600,
  "allowed_operations": ["answer", "draft", "cite"],
  "issued_at": "2026-04-15T14:00:00Z"
}
```

**Exit Criteria**

- Two mock agents can run concurrent sessions with different lenses
- Cross-session audit returns unified activity timeline
- Session isolation verified: Agent A cannot see Agent B's activity
- Revocation is immediate for both agent-level and session-level

---

### Iteration 7: Mac UI for Agent Grants, Session Monitor, Receipts

*Duration: 2.5 weeks*

**Scope**

- Agent registry view: list paired agents, revoke agent
- Grant access dialog: select lens, enter purpose, TTL selector, approval rule display
- Multi-session monitor: active sessions list, real-time activity streams, revoke/finalize per session
- Receipt viewer: list receipts, detail view, open referenced artifacts, export
- Cross-session dashboard: unified vault activity timeline

**Exit Criteria — end-to-end user story**

- Import artifacts, create lens, agent requests access, user approves, agent queries, user monitors, user reviews receipt, user revokes access
- Multi-agent scenario: two agents active simultaneously, user can monitor and manage both

---

### Iteration 8: Hardening, Packaging, Ship

*Duration: 2 weeks*

**Hardening**

- Vault integrity: transaction wrapping, WAL checkpoint management, crash recovery tests
- Index maintenance: integrity check on startup, background rebuild on mismatch
- Performance: batch embedding during ingest, background indexing queue, cancellation support
- UX polish: progress indicators, error messages, empty states, keyboard shortcuts

**Packaging**

- macOS code signing and notarization
- DMG with drag-to-Applications
- Auto-update framework placeholder (Sparkle)
- Diagnostic bundle export (no sensitive content)

**Exit Criteria**

- Fresh install works on macOS 13+
- Vault migration path exists (schema versioning)
- All performance budgets met
- No P0 bugs remaining

---

## v0.1 Fast-Follow: Team Foundations

The Mythos analysis and broader market signals indicate that the B2B demand for agent governance infrastructure is accelerating. v0.1 should move team/multi-user capabilities from "future enhancement" to "first post-launch sprint."

### v0.1 Scope

| Feature | Priority | Description |
|---|---|---|
| Shared spaces | Critical | Multiple users can access the same vault space with role-based permissions (owner, editor, viewer) |
| Org-level lens policies | Critical | Admins can define organization-wide lens templates that enforce minimum security floors |
| Centralized audit dashboard | Critical | Unified view of all agent activity across all users in an organization |
| Tagging UI improvements | High | Bulk tagging, tag suggestions, tag-based search |
| OCR for scanned PDFs | High | Opt-in text extraction for image-based PDFs |
| Live folder connector | Medium | Index a local folder automatically; vault controls exposure |
| Summary cache | Medium | Cache LLM-generated summaries for frequently accessed artifacts |
| Key rotation | Medium | Re-encrypt blobs with new DEK in background |

### Why This Matters Commercially

The moment you add shared spaces, org-level policies, and centralized audit, Tessera crosses from "prosumer tool" to "enterprise pilot candidate." The existing architecture supports this cleanly — spaces already isolate, lenses already govern, receipts already prove. The extension is adding multi-user identity and org-scoped policy templates.

This is the natural upgrade path: individual users validate the tool, then bring it to their team, then procurement asks for admin controls and audit trails.

---

## MVP Definition of Done

The MVP is complete when all of the following are true:

| Criterion | Verification |
|---|---|
| Spaces and lens policies are easy to create and use | User testing: lens created in < 60 seconds without docs |
| Retrieval is semantic and policy-filtered | Recall@10 > 0.85 on golden set; policy degradation < 10% |
| Multiple agents can access concurrently via scoped sessions | Integration test: two agents, different lenses, concurrent queries |
| Every query yields citations and a receipt | Automated test: no query completes without receipt entry |
| User can revoke access immediately | Revocation latency < 1 second; post-revocation queries fail |
| Cross-session audit provides unified activity view | Manual test: all sessions visible in time-window query |
| Everything works offline | Test: full flow with network disabled |
| Performance budgets met | `tessera diag` reports all metrics within budget |
| No P0 bugs | Bug triage complete; zero critical issues open |
| Fresh install works on macOS 13+ | Clean VM test |

---

## Strategic Positioning

### The Tessera Thesis in One Paragraph

As AI agents become more capable and more agentic, the question shifts from "can the model do useful work?" to "under what authority structure may it act?" Tessera answers that question. It is the trust substrate that sits between users and agents, providing curated context with granular disclosure, policy enforcement with default deny, and immutable receipts that prove what happened. The model commoditizes. The trust stack endures.

### What Tessera Owns

A startup survives the wrapper tax only if it owns something the model provider cannot absorb. Tessera owns three things simultaneously:

- **Proprietary domain context:** The user's curated corpus. No model provider has this.
- **Proprietary enforcement layer:** Lens policies, disclosure modes, approval workflows. This is governance, not a feature toggle.
- **Proprietary evidence trail:** Receipts, audit logs, cross-session dashboards. This is the "prove it" layer that enterprises demand.

### Tessera + Orkestr: The Constrained Agency Stack

Tessera and Orkestr form complementary planes of a complete agent governance architecture:

- **Orkestr is the execution plane** — how agents run, coordinate, and get supervised. Workflow DAGs, tool access, guardrails, approval gates, cost tracking, execution traces.
- **Tessera is the context plane** — what agents can know, with what proof. Curated knowledge, policy-gated retrieval, disclosure minimization, immutable receipts.

Together, they form a **constrained agency** stack: a complete least-privilege envelope covering both bounded actions (Orkestr) and bounded context (Tessera). An Orkestr pipeline calls Tessera via MCP server or REST tool provider for policy-gated context retrieval, producing complementary audit trails — execution traces on the Orkestr side, context receipts on the Tessera side.

### Go-to-Market Wedge

**Wedge 1 (v0): Professional domain experts.** Architects, lawyers, engineers, consultants — professionals whose expertise is a curated corpus. They pay for faster work product in their voice and standards, reuse of personal IP across projects, and safe boundaries between clients.

**Wedge 2 (v0.1): Teams deploying agents.** Engineering teams, security teams, regulated industries. They pay for least-privilege context access, auditable disclosure, and reduced risk of overexposure. This is where the Mythos-class market signal points most urgently.

### Open Source Strategy

The core engine, policy layer, and gateway are open source. This is not idealism — it is positioning:

- Trust requires inspectability. Users who care about context governance need to see the code.
- The orchestration layer is where open-source builders differentiate. Tessera occupies that layer.
- Frontier models get gated; the control plane stays open. Tessera is the control plane.
- Commercial value comes from hosting, team features, integrations, and support — not from hiding the engine.

---

## Future Enhancements (Beyond v0.1)

| Feature | Priority | Strategic Rationale |
|---|---|---|
| MCP server mode | High | Expose Tessera as an MCP tool for any agent framework — model-agnostic by default |
| Orkestr native integration | High | First-class tool provider in Orkestr pipelines with shared auth and audit correlation |
| Agent orchestration hooks | High | Enable a pipeline coordinator to request sessions for multiple specialist agents |
| Windows and Linux ports | Medium | Expand addressable market after Mac validation |
| Cloud sync (E2E encrypted) | Medium | Multi-device access without compromising local-first promise |
| Abstractive summaries | Medium | LLM-generated summaries for disclosure mode — better than extractive |
| Entity redaction | Medium | Automatic PII/entity redaction in disclosure outputs |
| Decision graph | Low | Track reasoning chains across sessions for long-term audit |
| Shared vault federation | Low | Organizations federate vaults across departments with policy inheritance |

---

## Appendix A: Suggested Rust Dependencies

| Category | Crate | Purpose |
|---|---|---|
| Database | `rusqlite` (bundled) | SQLite with WAL mode |
| Encryption | `chacha20poly1305`, `argon2`, `sha2` | Blob encryption, key derivation, hashing |
| Embeddings | `ort` (ONNX Runtime) | Local model inference |
| Tokenization | `tokenizers` | WordPiece tokenization for chunking |
| Vector index | `instant-distance` or `hnsw_rs` | HNSW approximate nearest neighbor |
| PDF extraction | `pdf-extract` | Text layer extraction |
| Async | `tokio` (full) | Async runtime |
| Gateway | `axum`, `tower`, `tower-http` | HTTP server, middleware |
| Serialization | `serde`, `serde_json` | JSON handling |
| CLI | `clap` (derive) | Command-line argument parsing |
| IDs | `uuid` (v4) | Unique identifier generation |
| Time | `chrono` (serde) | Timestamps |
| Errors | `thiserror` | Error type definitions |
| Logging | `tracing`, `tracing-subscriber` | Structured logging |
| Keychain | `keyring` | Cross-platform credential storage |

---

## Appendix B: File Type Support (v0)

| Type | Extension | Extraction | Notes |
|---|---|---|---|
| PDF | .pdf | Text layer | No OCR in v0 |
| Markdown | .md | Direct | Preserves structure |
| Plain text | .txt | Direct | |
| Word | .docx | Via pandoc | |
| Images | .png, .jpg | Metadata only | No OCR in v0 |

---

## Appendix C: Sensitivity Levels

| Level | Description | Default Behavior |
|---|---|---|
| `public` | Can be freely shared | Auto-approve |
| `internal` | Internal use, not secret | Auto-approve |
| `confidential` | Business sensitive | Require approval |
| `restricted` | Highly sensitive | Always require approval |

---

## Appendix D: Glossary

| Term | Definition |
|---|---|
| **Artifact** | A file or document in the vault |
| **Chunk** | A segment of text sized for embedding and retrieval |
| **Context Pack** | The data returned to an agent for a query (filtered, rendered, cited) |
| **DEK** | Data Encryption Key — encrypts blobs |
| **Disclosure Mode** | How much of an artifact is revealed: summary, excerpt, or full |
| **HNSW** | Hierarchical Navigable Small World — vector index algorithm |
| **Lens** | A reusable access policy governing what an agent can see and how |
| **Receipt** | Immutable record of session activity — the trust primitive; a tessera |
| **Session** | Time-bounded, purpose-declared access grant for an agent |
| **Space** | A container for organizing artifacts with hard isolation boundaries |
| **Tessera** | (Latin) A token proving authorized access — the project's namesake and governing metaphor |
| **Vault** | The encrypted local storage container holding all user data |
