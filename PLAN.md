# Tessera — Development Roadmap

> **Note (2026-07-05):** execution now tracks GitHub milestones M1–M7 (see `GOAL.md` and the design doc in `docs/superpowers/specs/`). Checkboxes below are kept roughly in sync; milestone/issue state on GitHub is authoritative. Guardian (MCP) replaces the REST gateway; M6=Guardian, M7=Multimodal. The owner workbench is Tauri 2 + React at `apps/tessera-desktop/` (see Iteration 7), not SwiftUI. CI and vault portability run on macOS and Ubuntu.

## Iteration 0: Scaffolding
- [x] Repo cleanup — remove legacy files, submodules
- [x] Rust workspace structure with crate scaffolding
- [x] CI/CD pipeline (fmt, clippy, test)
- [x] OpenAPI stub, JSON schemas
- [x] README, CLAUDE.md, PLAN.md
- [x] Basic vault directory initializer (bridge to Iteration 1)

## Iteration 1: Vault Storage, Spaces, Artifacts
- [x] Vault initialization with encryption (Argon2id key derivation + XChaCha20-Poly1305)
- [ ] macOS Keychain integration for DEK storage
- [x] SQLite schema v0 with WAL mode
- [x] Spaces CRUD (hierarchical containers)
- [ ] Artifact ingest pipeline
- [x] Content-addressed encrypted blob store
- [x] Deduplication (same file → same blob)
- [x] Tags model and artifact tagging

**Exit criteria**: Import 1,000 files without corruption. Dedup verified. Listing < 100ms for 10k artifacts.

## Iteration 2: Extraction and Chunking
- [ ] PDF text extraction (text layer)
- [ ] Markdown and plaintext extraction
- [ ] Sentence-aware chunking (512 tokens, 64 overlap)
- [ ] Chunk byte offset tracking for citation
- [ ] Derived text stored as encrypted blob
- [ ] Re-extraction skipped for unchanged artifacts

**Exit criteria**: Queryable chunk corpus exists. Extraction is deterministic.

## Iteration 3: Embeddings and Vector Index
- [ ] `EmbeddingProvider` trait + ONNX MiniLM-L6-v2 implementation
- [ ] `VectorIndex` trait + sqlite-vec implementation (vectors in same SQLite DB)
- [ ] Embedding pipeline (chunk → vector → index)
- [ ] Vector ID ↔ chunk ID mapping
- [ ] Model version tracking for future reindexing

**Exit criteria**: 10k+ chunks indexed. Query returns relevant chunks < 100ms. Recall@10 > 0.70 on golden set.

## Iteration 4: Lens Policies and Policy-Filtered Retrieval
- [ ] LensPolicy model and CRUD
- [ ] Policy evaluation engine
- [ ] Policy-filtered retrieval via SQL WHERE clauses (sqlite-vec enables single-query filtering)
- [ ] Space isolation enforcement
- [ ] Tag include/exclude, content type, sensitivity ceiling filtering

**Exit criteria**: Blocked spaces never appear in results. Policy filtering degrades Recall@10 by < 10%.

## Iteration 5: Disclosure, Citations, Receipts
- [ ] Disclosure modes: summary, excerpt, full
- [ ] Citation generation with byte offsets
- [ ] Receipt construction and storage (JSON)
- [ ] Receipt export (HTML)
- [ ] **v0.0 CLI checkpoint** — end-to-end validation in terminal

**Exit criteria**: Every query produces a receipt. Citations have valid byte offsets. Core value proposition demoed without UI.

## Iteration 6: Gateway
- [ ] Axum localhost server bound to 127.0.0.1
- [ ] Agent registration and pairing (6-char code)
- [ ] Token signing (Keychain-stored key)
- [ ] Session management (create, expire, revoke)
- [ ] Query endpoint with policy enforcement
- [ ] SSE activity stream
- [ ] Rate limiting (100 queries/min/session)

**Exit criteria**: Mock agent can register, pair, query, and be revoked. Sessions expire at TTL.

## Iteration 7: Owner workbench
- [x] Tauri 2 + React workbench at `apps/tessera-desktop/`
- [x] Open an existing current format-v3 vault
- [x] Sanitized aggregate overview
- [x] Explicit lock
- [ ] Remaining owner screens (inbox, spaces, lenses, agents, sessions, receipts, evaluation, diagnostics) stay labeled previews until they have native backing
- `mac/` remains a preserved dormant SwiftUI placeholder; it is not the app

**Exit criteria**: The owner can open a current format-v3 vault, read the sanitized aggregate, and lock it from the workbench. Preview screens do not claim live data or successful mutations.

## Iteration 8: Hardening and Ship
- [ ] Transaction wrapping, WAL checkpoint management
- [ ] Crash recovery tests
- [ ] Batch embedding during ingest
- [ ] Background indexing queue with progress indicators
- [ ] Performance profiling against budgets
- [ ] Security audit (encryption, policy enforcement, token handling)
- [ ] macOS code signing and notarization
- [ ] DMG packaging with first-run experience
- [ ] `tessera diag` diagnostics command
- [ ] Schema versioning for vault migration

**Exit criteria**: Fresh install works on macOS 13+. CI and protected-bundle interchange remain green on Ubuntu as well as macOS. All performance budgets met. No P0 bugs.

---

## Testing Strategy

Every iteration includes tests at all relevant layers:

- **Unit tests**: Module-level in `#[cfg(test)] mod tests`
- **Integration tests**: Cross-crate in `tests/integration/`
- **Property-based tests** (`proptest`): Policy evaluation, encryption round-trips, chunking invariants
- **Security tests**: Blocked space isolation, token expiry, revocation, encryption without passphrase
- **Retrieval quality tests**: Golden set evaluation (Recall@5, Recall@10, MRR)
- **Performance tests**: Budget compliance for ingest, query, startup, memory

## MVP Definition of Done

- [ ] Spaces and Lens policies exist and are easy to use
- [ ] Retrieval is semantic and policy-filtered
- [ ] Agents access only via session tokens with declared purpose and TTL
- [ ] Every query yields citations and a receipt
- [ ] User can revoke access immediately
- [ ] Everything works fully offline
- [ ] Recall@10 > 0.80 on golden evaluation set
- [ ] All performance budgets met
- [ ] Fresh install works on macOS 13+
- [ ] CI and vault portability remain green on Ubuntu as well as macOS
- [ ] No P0 bugs remaining
