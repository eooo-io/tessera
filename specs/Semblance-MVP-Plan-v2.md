# Semblance v0 MVP Implementation Plan

**Version 2.0 — Revised and Enhanced**

## Executive Summary

Semblance is a curated, user-owned personal context vault with granular disclosure controls. Users curate what matters, then grant AI agents permission to only what they need for a specific task.

This plan describes the Mac-first MVP: a local desktop vault with policy-gated semantic retrieval, receipts for auditability, and a localhost gateway for agent access.

---

## MVP Goal

Ship a Mac-first desktop vault that lets a user:

- Create Spaces and import artifacts (PDF, MD, TXT, images)
- Build Lens policies (scoped access rules)
- Grant desktop-native agents purpose-bound access via a local gateway
- Answer queries using Policy-RAG (HNSW semantic retrieval + SQLite metadata filters)
- Produce receipts that prove what was accessed and what was disclosed

**Explicit non-goals for v0:**
- Cloud sync
- Always-on capture or recording
- Multi-user or team features
- Mobile apps

---

## Architecture (v0)

### Components

| Component | Technology | Responsibility |
|-----------|------------|----------------|
| **semblance-core** | Rust library | Vault storage, ingestion, extraction, chunking, embeddings, HNSW index, policy evaluation, disclosure rendering, receipts |
| **semblance-gateway** | Rust daemon | Localhost API, agent registry, session tokens, purpose binding, query endpoint, activity stream |
| **semblance-mac** | SwiftUI app | Spaces UI, import, tagging, lens builder, agent grant dialog, session monitor, receipt viewer |
| **semblance-cli** | Rust binary | Command-line interface for vault operations (v0.0 validation) |

### Storage Foundations

| Layer | Technology | Contents |
|-------|------------|----------|
| Metadata | SQLite (WAL mode) | Spaces, artifacts, versions, tags, chunks, embeddings map, lenses, sessions, audit logs |
| Blobs | Encrypted file store | Original files, derived text, thumbnails |
| Vector index | HNSW (instant-distance or similar) | Chunk embeddings for semantic search |
| Receipts | JSON files | Session records with human-readable export |

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

---

## Core Concepts

### Spaces
Hierarchical containers for organizing artifacts. Examples: "Client A", "Project X", "Published Work", "Personal R&D".

### Artifacts
Individual files or documents with metadata, tags, and version history. Content-addressed for deduplication.

### Chunks
Segments of extracted text, sized for embedding and retrieval. Each chunk maintains a link to its source artifact and byte offsets.

### Lenses
Reusable access policies that define what an agent can see and how. A lens specifies spaces, content types, disclosure modes, and allowed operations.

### Sessions
Time-bounded access grants. An agent requests a session with a lens and purpose; the gateway mints a token; all queries are logged.

### Receipts
Immutable records of what was accessed during a session. The "prove what happened" primitive.

---

## Security and Encryption

### Vault Key Derivation

1. User provides a passphrase on vault creation
2. Derive a 256-bit vault key using Argon2id:
   - Memory: 64 MB
   - Iterations: 3
   - Parallelism: 4
   - Salt: random 16 bytes, stored in `vault.db`
3. Vault key encrypts a randomly generated Data Encryption Key (DEK)
4. DEK encrypts all blobs

### Key Storage

- **macOS**: Store DEK in Keychain, keyed by vault path
- Passphrase is never stored; user re-enters to unlock
- Optional: Touch ID unlock via Keychain ACL

### Blob Encryption

- Algorithm: XChaCha20-Poly1305 (via `chacha20poly1305` crate)
- Each blob has a unique 24-byte nonce (random)
- Nonce stored as prefix to ciphertext
- Verify hash on read; mark corrupted if mismatch

### Key Rotation (v0.1)

- Generate new DEK
- Re-encrypt all blobs in background
- Atomic swap when complete

### Threat Model (v0)

| Protected against | Not protected against |
|-------------------|----------------------|
| Stolen laptop | Malware with memory access |
| Disk access without passphrase | Keylogger during unlock |
| Casual snooping | Targeted forensic analysis |

Receipts are stored unencrypted by default (they contain metadata, not content).

---

## Embedding Strategy

### Default Model

- **Model**: `all-MiniLM-L6-v2`
- **Dimensions**: 384
- **Runtime**: ONNX Runtime via `ort` crate
- **Inference**: Local, no external API calls

### Rationale

- Small footprint (~80 MB)
- Fast inference (<10ms per chunk on Apple Silicon)
- Good quality for general-purpose retrieval
- Well-documented baseline

### Future Upgrades (v0.1+)

| Model | Dimensions | Notes |
|-------|------------|-------|
| `nomic-embed-text` | 768 | Better quality, larger |
| `bge-small-en-v1.5` | 384 | Strong benchmark performance |
| `jina-embeddings-v2-small-en` | 512 | Good for longer chunks |

### Reindexing Strategy

- `embeddings_map` tracks `embedding_model_version`
- On model change, mark old embeddings `deprecated`
- Background job re-embeds all chunks
- Rebuild HNSW index incrementally
- Queries use latest index; old index serves until rebuild complete

---

## Chunking Strategy

### Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Target chunk size | 512 tokens | Balances context vs. precision |
| Overlap | 64 tokens | Prevents information loss at boundaries |
| Boundary preference | Sentence-aware | Improves coherence |

### Implementation

1. Tokenize using WordPiece (matches MiniLM tokenizer)
2. Split on sentence boundaries where possible
3. If a sentence exceeds 512 tokens, split at clause boundaries (commas, semicolons)
4. Store precise byte offsets for citation

### Chunk Metadata

```sql
CREATE TABLE chunks (
    id TEXT PRIMARY KEY,
    artifact_version_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    byte_offset_start INTEGER NOT NULL,
    byte_offset_end INTEGER NOT NULL,
    token_count INTEGER NOT NULL,
    section_heading TEXT,  -- extracted if available
    created_at TEXT NOT NULL,
    FOREIGN KEY (artifact_version_id) REFERENCES artifact_versions(id)
);
```

---

## Lens Policy Schema

### Minimal Schema (v0)

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
  "default_ttl_minutes": 60,
  "created_at": "2025-01-22T10:00:00Z",
  "updated_at": "2025-01-22T10:00:00Z"
}
```

### Field Definitions

| Field | Type | Description |
|-------|------|-------------|
| `space_ids` | string[] | Spaces to include (required) |
| `space_exclude_ids` | string[] | Spaces to exclude (overrides include) |
| `tag_include` | string[] | Only include artifacts with these tags |
| `tag_exclude` | string[] | Exclude artifacts with these tags |
| `content_types` | string[] | Allowed file types: pdf, docx, md, txt, png, jpg |
| `disclosure_mode` | enum | `summary`, `excerpt`, or `full` |
| `max_quote_chars` | int | Max verbatim text per excerpt (only if mode=excerpt) |
| `allow_metadata` | bool | Include title, date, tags in response |
| `operations` | string[] | `answer`, `draft`, `extract`, `cite` |
| `sensitivity_ceiling` | enum | `public`, `internal`, `confidential`, `restricted` |
| `approval_rule` | enum | `never`, `always`, `on_sensitive` |
| `default_ttl_minutes` | int | Default session duration |

### Policy Enforcement Strategy

For HNSW (which doesn't support pre-filtering):

1. Retrieve top-N candidates from vector index (N = 5 × K)
2. Join to chunk metadata in SQLite
3. Filter by lens constraints:
   - Space membership
   - Tag include/exclude
   - Content type
   - Sensitivity ceiling
4. If fewer than K results, increase N and retry (up to max cap)
5. Return top K valid results

---

## Disclosure Rendering

### Modes

#### summary-only
- **Returns**: Artifact title, type, date, tags, one-sentence summary
- **Does NOT return**: Any verbatim text from the artifact
- **Summary generation**: Extractive (first sentence of most relevant chunk) in v0
- **Future**: Abstractive summary via LLM

#### excerpt-only
- **Returns**: Artifact metadata + verbatim excerpts up to `max_quote_chars`
- **Excerpts**: Contiguous spans from retrieved chunks
- **Citation format**:
```json
{
  "artifact_id": "art_abc123",
  "artifact_title": "Fire Safety Spec v3",
  "excerpt": "The minimum fire rating for corridor walls shall be...",
  "chunk_id": "chunk_xyz789",
  "byte_range": [1024, 1156]
}
```

#### full
- **Returns**: Complete artifact content
- **Default**: Disabled in v0 UI
- **Use case**: When user explicitly needs raw access
- **Logging**: Prominently recorded in receipt

### Context Pack Structure

```json
{
  "session_id": "sess_abc123",
  "lens_id": "lens_3f2a",
  "query": "What are the fire rating requirements?",
  "timestamp": "2025-01-22T14:30:00Z",
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
  "receipt_id": "rcpt_def456"
}
```

---

## Agent Identity and Pairing

### Trust Model

- Agents are "trusted on this device" after user-initiated pairing
- No cryptographic attestation in v0 (platform-specific complexity)
- User explicitly approves each agent

### Pairing Flow

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   Agent     │         │   Gateway   │         │   Mac App   │
└──────┬──────┘         └──────┬──────┘         └──────┬──────┘
       │                       │                       │
       │ POST /agents/register │                       │
       │ {name: "Claude"}      │                       │
       │──────────────────────>│                       │
       │                       │                       │
       │ {agent_id, pairing_code: "ABC123"}            │
       │<──────────────────────│                       │
       │                       │                       │
       │                       │ Pairing request       │
       │                       │──────────────────────>│
       │                       │                       │
       │                       │         User verifies │
       │                       │         code, clicks  │
       │                       │         "Approve"     │
       │                       │<──────────────────────│
       │                       │                       │
       │ {agent_token}         │                       │
       │<──────────────────────│                       │
       │                       │                       │
```

### Pairing Code

- 6 alphanumeric characters (uppercase + digits, no ambiguous chars)
- Expires in 5 minutes
- Single use

### Agent Token Contents

```json
{
  "agent_id": "agent_abc123",
  "device_id": "dev_xyz789",
  "issued_at": "2025-01-22T10:00:00Z",
  "revocable": true
}
```

- Signed by gateway
- Long-lived (until revoked)
- Stored by agent in its own secure storage

### Revocation

- User can revoke any agent from Mac app
- Revocation is immediate
- Agent must re-pair to regain access

### Session Flow (After Pairing)

1. Agent calls `POST /sessions` with:
   - `agent_token`
   - `lens_id`
   - `purpose` (free text, required)
   - `requested_ttl`
2. Gateway evaluates:
   - Is agent trusted?
   - Does lens exist?
   - Does purpose comply with lens operations?
   - Does approval rule require user confirmation?
3. If approved (or auto-approved), returns session token:
   - `session_id`
   - `lens_id`
   - `purpose_hash`
   - `ttl`
   - `allowed_operations`
4. Session token used for `/query` calls
5. Session expires at TTL or on explicit revocation

---

## Gateway API (v0)

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/agents/register` | Initiate agent pairing |
| `GET` | `/agents` | List registered agents |
| `DELETE` | `/agents/{id}` | Revoke agent |
| `POST` | `/sessions` | Request access session |
| `GET` | `/sessions/{id}` | Get session details |
| `DELETE` | `/sessions/{id}` | Revoke session |
| `GET` | `/sessions/{id}/stream` | SSE activity stream |
| `POST` | `/query` | Execute policy-filtered retrieval |
| `POST` | `/receipts/{session_id}/finalize` | Close session and finalize receipt |
| `GET` | `/receipts/{id}` | Get receipt |
| `GET` | `/receipts/{id}/export` | Export receipt as HTML/PDF |

### Security

- Gateway binds to `127.0.0.1` only
- All endpoints require valid token (except `/agents/register`)
- Tokens are signed with gateway key (stored in Keychain)
- Rate limiting: 100 queries per minute per session

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
  "results": [...],
  "receipt_id": "rcpt_def456",
  "tokens_used": 1247
}
```

---

## Receipt Structure

### JSON Format

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
  "started_at": "2025-01-22T14:00:00Z",
  "ended_at": "2025-01-22T14:35:00Z",
  "queries": [
    {
      "query_id": "q_001",
      "timestamp": "2025-01-22T14:05:00Z",
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
  },
  "approvals": [
    {
      "timestamp": "2025-01-22T14:02:00Z",
      "action": "session_approved",
      "user_action": "auto"
    }
  ]
}
```

### Human-Readable Export

Generate HTML or Markdown with:
- Session metadata header
- Timeline of queries
- List of artifacts accessed with disclosure details
- Summary statistics
- "Open in vault" links for each artifact

---

## Error Handling and Recovery

### Database

- SQLite WAL mode for crash resistance
- All writes wrapped in transactions
- On corruption: attempt recovery, rebuild indexes, notify user

### Vector Index

- HNSW index is rebuildable from `embeddings_map`
- On startup: quick integrity check (compare count and sample hashes)
- On mismatch: trigger background rebuild, queries use stale index until complete

### Blob Store

- Content-addressed: verify hash on every read
- On hash mismatch: mark artifact as corrupted, exclude from retrieval, notify user

### Gateway Errors

All endpoints return structured errors:

```json
{
  "error": "session_expired",
  "message": "Session has expired. Request a new session.",
  "code": "ERR_SESSION_EXPIRED",
  "retry": false
}
```

| Error | Code | Retry |
|-------|------|-------|
| Rate limited | `ERR_RATE_LIMIT` | Yes (after backoff) |
| Temporary unavailable | `ERR_UNAVAILABLE` | Yes |
| Session expired | `ERR_SESSION_EXPIRED` | No (request new) |
| Invalid token | `ERR_INVALID_TOKEN` | No |
| Policy violation | `ERR_POLICY_VIOLATION` | No |
| Not found | `ERR_NOT_FOUND` | No |

### User-Facing Errors

- Never show stack traces
- Provide actionable messages: "Import failed: PDF appears corrupted. Try re-exporting from the source application."
- Offer diagnostics export for bug reports (no sensitive content)

---

## Performance Budgets

### Ingest

| Operation | Target | Notes |
|-----------|--------|-------|
| PDF extraction | < 2s per MB | Text layer only in v0 |
| Text chunking | < 100ms per doc | Includes tokenization |
| Embedding (local) | < 50ms per chunk | On Apple Silicon |
| Total ingest | < 5s per doc | Typical 10-page PDF |

### Query

| Operation | Target | Notes |
|-----------|--------|-------|
| HNSW search | < 50ms | For 100k vectors |
| Policy filtering | < 20ms | SQLite join + filter |
| Disclosure rendering | < 30ms | Per result |
| Total query latency | < 200ms (p95) | End-to-end |

### Startup

| Operation | Target |
|-----------|--------|
| Vault unlock | < 500ms |
| Index load | < 1s (100k vectors) |
| UI ready | < 2s |

### Memory

| State | Budget |
|-------|--------|
| Idle | < 100 MB |
| During ingest | < 500 MB |
| During query | < 200 MB |

### Measurement

- Instrument critical paths with timing spans
- `semblance diag` command reports performance metrics
- Log slow operations (> 2× budget) as warnings

---

## Retrieval Evaluation

### Golden Set

Create 30–50 question/answer pairs from your own corpus:

```json
{
  "id": "eval_001",
  "question": "What is the minimum fire rating for corridor walls?",
  "expected_artifact_ids": ["art_abc123", "art_def456"],
  "expected_answer": "The minimum fire rating is 1 hour for corridors serving...",
  "tags": ["fire_safety", "building_code"]
}
```

### Metrics

| Metric | Definition | Target |
|--------|------------|--------|
| Recall@5 | Fraction of expected artifacts in top 5 | > 0.70 |
| Recall@10 | Fraction of expected artifacts in top 10 | > 0.85 |
| MRR | Mean reciprocal rank of first relevant result | > 0.60 |

### Evaluation Harness

```bash
# Run evaluation
semblance eval --golden eval_set.json --output results/

# Output
Recall@5:  0.76
Recall@10: 0.88
MRR:       0.65

Failed queries:
- eval_012: expected art_xyz but got art_abc (similarity: 0.72)
- eval_023: no relevant results in top 10
```

### Quality Gates

| Iteration | Gate |
|-----------|------|
| Iteration 3 | Recall@10 > 0.70 on golden set |
| Iteration 4 | Policy filtering degrades Recall@10 by < 10% |

### Failure Analysis

- Log queries where expected artifacts weren't retrieved
- Common causes: poor chunking, embedding model mismatch, metadata errors
- Track improvements over iterations

---

## Iteration Plan

### Dependency Diagram

```
Iteration 0 (scaffolding)
    │
    ▼
Iteration 1 (vault, spaces, artifacts)
    │
    ├────────────────────────────┐
    ▼                            ▼
Iteration 2 (extraction)         Mac app: vault picker,
    │                            spaces sidebar (parallel)
    ▼
Iteration 3 (embeddings, HNSW)
    │
    ▼
Iteration 4 (lens, policy retrieval)
    │
    ├────────────────────────────┐
    ▼                            ▼
Iteration 5 (disclosure,         Mac app: lens builder
citations, receipts)             (parallel)
    │
    ▼
══════════════════════════════════════════════════════════
    │  v0.0 CHECKPOINT: CLI validation
══════════════════════════════════════════════════════════
    │
    ▼
Iteration 6 (gateway)
    │
    ▼
Iteration 7 (Mac UI: grants, monitor, receipts)
    │
    ▼
Iteration 8 (hardening, packaging)
```

### Parallelism Opportunities

- Mac app basic UI can start after Iteration 1 (vault/spaces)
- Mac app lens builder can start after Iteration 4 API is stable
- Gateway development can start after Iteration 5 if API contracts are defined early

**Recommendation**: Define OpenAPI spec in Iteration 0 to unblock parallel work.

---

### Iteration 0: Foundations and Repo Scaffolding

**Duration**: 1 week

**Deliverables**
- Monorepo structure:
  ```
  semblance/
  ├── core/           # Rust workspace
  ├── gateway/        # Rust binary
  ├── cli/            # Rust binary
  ├── mac/            # SwiftUI app
  └── spec/           # OpenAPI, JSON schemas
  ```
- Shared protocol definitions:
  - `spec/gateway-api.yaml` — OpenAPI 3.0
  - `spec/lens-policy.schema.json`
  - `spec/receipt.schema.json`
- CI pipeline:
  - Rust: `cargo fmt --check`, `cargo clippy`, `cargo test`
  - macOS: compile, unit tests
- Basic vault directory initializer

**Exit Criteria**
- `cargo test` passes for core and gateway
- Mac app builds and can create an empty vault directory
- CI green on main branch

---

### Iteration 1: Vault Storage, Spaces, Artifacts

**Duration**: 2 weeks

#### Core

**Scope**
- Vault initialization with encryption
- Spaces CRUD
- Artifact ingest pipeline
- Content-addressed encrypted blob store
- Deduplication

**API**
```rust
// Core API surface
fn create_vault(path: &Path, passphrase: &str) -> Result<Vault>;
fn open_vault(path: &Path, passphrase: &str) -> Result<Vault>;
fn create_space(vault: &Vault, name: &str, parent: Option<SpaceId>) -> Result<SpaceId>;
fn list_spaces(vault: &Vault) -> Result<Vec<Space>>;
fn import_files(vault: &Vault, space_id: SpaceId, paths: &[PathBuf]) -> Result<Vec<ArtifactId>>;
fn list_artifacts(vault: &Vault, space_id: SpaceId, filters: &Filters) -> Result<Vec<Artifact>>;
```

**Schema v0**
```sql
-- spaces
CREATE TABLE spaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    parent_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES spaces(id)
);

-- artifacts
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

-- artifact_versions
CREATE TABLE artifact_versions (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    blob_hash TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
);

-- tags
CREATE TABLE tags (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

-- artifact_tags
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
- Dedup works (same file imported twice → same blob)
- Artifact listing stable and fast (< 100ms for 10k artifacts)
- Encryption verified (blobs unreadable without passphrase)

#### Mac App

**Scope**
- Vault picker or create vault
- Unlock flow (passphrase entry)
- Spaces sidebar (tree view)
- Import via drag-drop and file dialog
- Artifact list view (title, type, size, date)

**Exit Criteria**
- Non-technical user can create spaces and import files
- Vault lock/unlock works correctly

---

### Iteration 2: Extraction and Chunking

**Duration**: 1.5 weeks

#### Core

**Scope**
- Text extraction:
  - PDF (text layer via `pdf-extract` or similar)
  - Markdown and plain text
- Chunking with sentence awareness
- Store chunk offsets and hashes
- Derived text stored as encrypted blob

**API**
```rust
fn extract_text(vault: &Vault, version_id: ArtifactVersionId) -> Result<DerivedTextId>;
fn chunk_text(vault: &Vault, derived_text_id: DerivedTextId) -> Result<Vec<ChunkId>>;
fn get_chunks(vault: &Vault, artifact_id: ArtifactId) -> Result<Vec<Chunk>>;
```

**Schema additions**
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
- Queryable chunk corpus exists for imported PDFs and MD/TXT
- Extraction is deterministic (same input → same chunks)
- Chunk boundaries respect sentences
- Re-extraction skipped for unchanged artifacts

---

### Iteration 3: Embeddings and HNSW Index

**Duration**: 2 weeks

#### Core

**Scope**
- Embedding pipeline with pluggable provider
- HNSW index integration
- Vector ID ↔ chunk ID mapping
- Index persistence and reload

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

**Schema additions**
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
- Embedding ingestion indexes 10k+ chunks
- Query returns relevant chunks in < 100ms
- Reopen vault preserves index and mappings
- Model version tracked; reindex possible on upgrade
- Recall@10 > 0.70 on golden set

---

### Iteration 4: Lens Policies and Policy-Filtered Retrieval

**Duration**: 2 weeks

#### Core

**Scope**
- LensPolicy model and storage
- Policy evaluation → retrieval constraints
- Post-retrieval filtering
- Over-fetch and filter strategy for HNSW

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

**Schema additions**
```sql
CREATE TABLE lenses (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    policy_json TEXT NOT NULL,  -- serialized LensPolicy
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

**Exit Criteria**
- Space isolation is provably enforced (test: similar content in blocked space never appears)
- Tag include/exclude works correctly
- Content type filtering works
- Sensitivity ceiling enforced
- Policy filtering degrades Recall@10 by < 10%

#### Mac App

**Scope**
- Lens builder wizard (4 steps)
- Lens list view
- Edit and delete lens

**Exit Criteria**
- User can create a lens in < 60 seconds without documentation

---

### Iteration 5: Disclosure Modes, Citations, Receipts

**Duration**: 2 weeks

#### Core

**Scope**
- Disclosure renderer (summary, excerpt, full)
- Citation generation with byte offsets
- Receipt construction and storage
- Receipt export (JSON + HTML)

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
- Receipt is human-readable
- Receipt includes deterministic list of artifacts touched
- Disclosure modes work correctly (summary has no verbatim text)
- Citations include valid byte offsets

---

### v0.0 Checkpoint: CLI Validation

**Purpose**: Validate the core value proposition before UI investment.

**Deliverables**
- `semblance-cli` binary with commands:
  ```bash
  semblance init <path>                    # Create vault
  semblance unlock <path>                  # Unlock vault
  semblance space create <name>            # Create space
  semblance import <space> <files...>      # Import files
  semblance lens create                    # Interactive lens builder
  semblance lens list                      # List lenses
  semblance query --lens <id> "<question>" # Query with citations
  semblance receipt <id>                   # View receipt
  semblance eval --golden <file>           # Run evaluation
  semblance diag                           # Performance diagnostics
  ```

**Exit Criteria**
- End-to-end flow works in terminal
- Can demo value proposition without UI
- Retrieval quality validated on real corpus
- Receipts generated and readable
- Performance within budgets

**Decision Gate**
- If this feels valuable → proceed to Mac app
- If retrieval quality is poor → iterate on chunking/embedding before UI

---

### Iteration 6: Local Gateway with Sessions and Agent Registry

**Duration**: 2 weeks

#### Gateway

**Scope**
- Agent registration and pairing
- Session token minting
- Purpose-bound access
- Query endpoint
- Activity stream (SSE)
- Receipt finalization

**Endpoints** (see Gateway API section above)

**Security**
- Bind to `127.0.0.1` only
- Token signing with Keychain-stored key
- Rate limiting
- Session expiry enforcement

**Exit Criteria**
- Mock agent can register, pair, request session, query, receive results
- Session expires correctly at TTL
- Revocation works (token becomes invalid immediately)
- Activity stream delivers real-time events
- All operations logged

---

### Iteration 7: Mac UI for Agent Grants, Session Monitor, Receipts

**Duration**: 2.5 weeks

#### Mac App

**Scope**
- Agent registry view
  - List paired agents
  - Revoke agent
- Grant access dialog
  - Select lens
  - Enter purpose
  - TTL selector
  - Approval rule display
  - Approve/Deny buttons
- Session monitor
  - Active sessions list
  - Real-time activity stream
  - Revoke button
  - Finalize receipt button
- Receipt viewer
  - List receipts
  - Receipt detail view
  - Open referenced artifacts
  - Export receipt

**Exit Criteria**
- End-to-end user story works:
  1. Import artifacts
  2. Create lens
  3. Agent requests access
  4. User approves
  5. Agent queries
  6. User monitors activity
  7. User reviews receipt
  8. User revokes access
- All flows feel natural and responsive

---

### Iteration 8: Hardening, Packaging, and Ship

**Duration**: 2 weeks

#### Hardening

**Vault integrity**
- Transaction wrapping for all writes
- WAL checkpoint management
- Crash recovery tests (kill process mid-write)
- Backup command (`semblance backup`)

**Index maintenance**
- Integrity check on startup
- Background rebuild on mismatch
- `semblance index rebuild` command

**Performance**
- Batch embedding during ingest
- Background indexing queue
- Progress indicators in UI
- Cancellation support for long operations

**UX polish**
- Clear error messages
- Retry states
- Empty states
- Keyboard shortcuts
- Accessibility basics

#### Packaging

**macOS distribution**
- Code signing with Developer ID
- Notarization
- DMG with drag-to-Applications
- Auto-update framework (Sparkle) — placeholder, actual updates in v0.1

**First-run experience**
- Welcome screen
- Create or open vault
- Quick import tutorial

**Diagnostics**
- `semblance diag` command
- Export diagnostic bundle (no sensitive content)
- Crash reporting opt-in

**Exit Criteria**
- Fresh install works on clean macOS
- Vault migration path exists (schema versioning)
- One-click export of receipt and selected artifacts
- No P0 bugs remaining
- Performance within budgets

---

## Quality Gates and Test Plan

### Core Test Layers

**Unit tests**
- Policy evaluation logic
- Disclosure mode rendering
- Receipt construction
- Chunking algorithm
- Encryption/decryption

**Integration tests**
- Full pipeline: ingest → extract → chunk → embed → index → search
- Index rebuild from embeddings_map
- Vault corruption and recovery

**Security tests**
- Blocked spaces never appear in results (even with high similarity)
- Token expiry enforcement
- Revocation immediacy
- Encryption key not accessible without passphrase

### Gateway Tests

- Contract tests (responses match OpenAPI spec)
- Session lifecycle (create, use, expire, revoke)
- Concurrent query handling
- Rate limiting behavior

### Mac App Tests

- UI flow automation (XCUITest)
- Import various file types
- Lens creation wizard
- Agent pairing flow

### Evaluation Tests

- Golden set retrieval quality
- Performance budget compliance
- Regression detection on code changes

---

## Definition of Done

### MVP is complete when:

- [ ] Spaces and lens policies exist and are easy to use
- [ ] Retrieval is semantic and policy-filtered
- [ ] Agents access only via session tokens with purpose and TTL
- [ ] Every query yields citations and a receipt
- [ ] User can revoke access immediately
- [ ] Everything works offline
- [ ] Recall@10 > 0.80 on golden set
- [ ] All performance budgets met
- [ ] No P0 bugs
- [ ] Fresh install works on macOS 13+

---

## Future Enhancements (v0.1+)

| Feature | Priority | Notes |
|---------|----------|-------|
| Tagging UI improvements | High | Bulk tagging, tag suggestions |
| OCR for scanned PDFs | High | Opt-in, Tesseract or similar |
| Live folder connector | Medium | Index folder, never expose directly |
| Summary cache | Medium | Cache LLM-generated summaries |
| Key rotation | Medium | Re-encrypt blobs with new key |
| Windows/Linux ports | Low | After Mac validated |
| Cloud sync | Low | Optional, E2E encrypted |
| Team spaces | Low | Requires auth infrastructure |

---

## Appendix A: Rust Crate Dependencies (Suggested)

```toml
[dependencies]
# Core
rusqlite = { version = "0.31", features = ["bundled"] }
chacha20poly1305 = "0.10"
argon2 = "0.5"
sha2 = "0.10"
hex = "0.4"

# Embeddings
ort = "2.0"  # ONNX Runtime
tokenizers = "0.15"

# Vector index
instant-distance = "0.6"  # or hnsw_rs

# PDF extraction
pdf-extract = "0.7"

# Async
tokio = { version = "1", features = ["full"] }

# Gateway
axum = "0.7"
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "trace"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# CLI
clap = { version = "4", features = ["derive"] }

# Utilities
uuid = { version = "1", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
thiserror = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
```

---

## Appendix B: File Type Support (v0)

| Type | Extension | Extraction | Notes |
|------|-----------|------------|-------|
| PDF | .pdf | Text layer | No OCR in v0 |
| Markdown | .md | Direct | Preserves structure |
| Plain text | .txt | Direct | |
| Word | .docx | Via pandoc | |
| Images | .png, .jpg | Metadata only | No OCR in v0 |

---

## Appendix C: Sensitivity Levels

| Level | Description | Default behavior |
|-------|-------------|------------------|
| `public` | Can be freely shared | Auto-approve |
| `internal` | Internal use, not secret | Auto-approve |
| `confidential` | Business sensitive | Require approval |
| `restricted` | Highly sensitive | Always require approval |

---

## Appendix D: Glossary

| Term | Definition |
|------|------------|
| **Artifact** | A file or document in the vault |
| **Chunk** | A segment of text sized for embedding |
| **Context Pack** | The data returned to an agent for a query |
| **DEK** | Data Encryption Key — encrypts blobs |
| **Disclosure Mode** | How much of an artifact is revealed (summary, excerpt, full) |
| **HNSW** | Hierarchical Navigable Small World — vector index algorithm |
| **Lens** | A reusable access policy |
| **Receipt** | Immutable record of session activity |
| **Session** | Time-bounded access grant for an agent |
| **Space** | A container for organizing artifacts |
| **Vault** | The encrypted storage container |
