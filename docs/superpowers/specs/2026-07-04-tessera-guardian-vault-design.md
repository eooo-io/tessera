# Tessera — Guardian Vault Design

**Date:** 2026-07-04
**Status:** Approved direction (sections 1–2 reviewed interactively; sections 3–7 derived from the same decision session)
**Supersedes:** the architecture/sequencing portions of `Tessera-MVP-Plan-v3.md`. The v3 plan remains the reference for crypto parameters, lens schema semantics, sensitivity levels, and performance budgets except where this document overrides it.

## Vision

A portable, media-agnostic personal context vault — a self-curated "semblance" of its owner — that can move to any runtime substrate while retaining owner-controlled access and complete, tamper-evident records of every disclosure, especially disclosures to LLMs and agents.

## Decisions made (2026-07-04 session)

| Question | Decision |
|---|---|
| Portability model | **Vault + guardian travel together.** The vault is a portable encrypted bundle; the guardian is the only process that opens it for agents. Substrates connect via MCP. |
| Audience | **Me-first.** Personal daily-driver tool; productization is a later option, not a current constraint. Mac app deferred indefinitely. |
| Media scope (v1) | Documents (PDF/MD/TXT/DOCX incl. white papers), AI conversations (Claude Code/Claude/ChatGPT exports), images with understanding (OCR + captions), web content & bookmarks, transcripts. |
| Inbox autonomy | **Auto-process, quarantine until reviewed.** Pipeline does everything; items are invisible to all lenses until owner approval. |
| Processing locality | **Local-only by default; cloud opt-in per item/source**, and the choice is recorded in provenance. |
| Derived forms (v1) | **Baseline + per-item summaries/captions.** Derivations are first-class (source, model, version tracked). Synthesis layer and knowledge graph deferred. |
| Build approach | **Evolve existing workspace** (guardian-first, MCP-native) **+ versioned vault format doc from day one.** |

## 1. Architecture

Three artifacts: a **vault bundle** (data), a **guardian** (enforcement), a **CLI** (owner's hands).

```
crates/
├── tessera-core/      # library: vault format, crypto, ingestion, retrieval,
│                      #   lenses, receipts
├── tessera-guardian/  # renamed from tessera-gateway: MCP server (stdio +
│                      #   streamable HTTP), sessions, receipt finalization
└── tessera-cli/       # `tessera` binary: init, inbox, review, query, lens,
                       #   receipts, sessions, guardian serve, diag, eval
spec/
├── vault-format.md    # versioned bundle format doc (day one)
├── lens-policy.schema.json
└── receipt.schema.json
mac/                   # dormant
```

- The guardian is the **only** process that ever opens a vault on behalf of an agent. Agents connect via MCP: stdio for same-machine agents, streamable HTTP with MCP 2026 authorization (OAuth 2.1) for remote. The v3 REST API and 6-char pairing protocol are **deleted**.
- The CLI links tessera-core directly; the owner's own use never requires the guardian.
- Portability = bundle + single static guardian binary per platform. macOS Keychain is a convenience, never a requirement; the passphrase path always works.
- The `VectorIndex` trait is redrawn at a higher boundary — `search(query_embedding, lens_constraints, k) -> Vec<ChunkRef>` — so the sqlite-vec implementation performs policy filtering in a single SQL join. The orphaned `extract` module is wired into `lib.rs`.

## 2. Vault bundle format and crypto

The bundle is a plain directory (survives rsync/Syncthing/drives without special handling):

```
MyVault.tessera/
├── tessera.json     # format_version, crypto params, embedding model registry
├── vault.db         # SQLite (WAL): metadata, chunks, sqlite-vec embeddings,
│                    #   lenses, sessions, receipts index, quarantine, provenance
├── keyslot.bin      # LUKS-style key slot list: DEK wrapped by Argon2id-derived keys
├── blobs/           # content-addressed (BLAKE3), XChaCha20-Poly1305 encrypted
├── receipts/        # finalized receipts, individual JSON files, hash-chained
└── inbox/           # drop zone; plaintext staging for content not yet in the vault
```

- `tessera.json` is the portability contract: format version, Argon2id parameters, cipher IDs, embedding model registry (name/version/dimensions) so a new host knows whether it can query existing vectors or must re-embed. `spec/vault-format.md` is updated in the same commit as any code that changes the format.
- Crypto per v3 plan: Argon2id (64 MB, 3 iters, p=4) → vault key → wraps random DEK → XChaCha20-Poly1305 per blob, unique 24-byte nonces. `keyslot.bin` holds a list of slots so additional unlock methods (recovery key, hardware token) can be added without re-encrypting.
- All derived content (extracted text, captions, summaries, thumbnails) is encrypted blobs too.
- **Honest caveat (documented in format doc):** v1 does not encrypt `vault.db`; filenames/tags/offsets are visible with disk access. Full metadata encryption (SQLCipher or column-level) is future work.

## 3. Ingestion pipeline (inbox)

Entry points: drop files into `inbox/`, or `tessera inbox add <paths...>` (copies in). `tessera inbox process` runs the pipeline (a watch mode may come later).

Pipeline stages, all local by default:

1. **Detect & hash** — media type detection, BLAKE3 hash, dedup against existing blobs.
2. **Encrypt original** into the blob store; remove from `inbox/`.
3. **Extract** — per-type extractor produces normalized text (see media matrix).
4. **Chunk** — sentence-aware for prose (512-token target, 64 overlap); **turn-aware for conversations and transcripts** (chunk boundaries respect speaker turns; a chunk records its turn range).
5. **Embed** — via `EmbeddingProvider` (v1 default: all-MiniLM-L6-v2 ONNX, 384d; registry allows swap/re-embed).
6. **Understand** — per-item summary (local summarizer); for images: OCR + local VLM caption. Cloud models only by explicit per-item/per-source opt-in.
7. **Suggest** — space, tags, sensitivity proposed by heuristics/local model.
8. **Quarantine** — artifact enters state `pending`.

Media matrix (v1):

| Type | Extractor | Notes |
|---|---|---|
| PDF | text layer (`pdf-extract`) | no OCR of scanned PDFs in v1 unless routed through image path |
| MD/TXT | direct | structure preserved |
| DOCX | pandoc | external tool dependency, checked by `tessera diag` |
| AI conversations | importers: Claude Code JSONL, Claude export, ChatGPT export | turn-aware chunking; conversation/session metadata kept |
| Images (PNG/JPG/HEIC) | OCR + local VLM caption | caption + OCR text are the searchable surface |
| Web content | readability extraction → Markdown | source URL preserved as provenance |
| Transcripts (VTT/SRT/TXT) | speaker/timestamp-aware parser | turn-aware chunking |

- **Provenance table:** every derived blob records source artifact/version, tool or model + version, locality (`local`/`cloud`), and timestamp.
- **Quarantine invariant (testable):** artifacts have state `pending | live | archived`. Lenses match **only** `live`. Nothing an agent can reach was never seen by the owner. `tessera review` provides a fast accept/adjust queue with bulk accept of suggestions.

## 4. Lenses and retrieval

- LensPolicy keeps the v3 schema, plus `media_types` (mirrors the broader media scope). Quarantine exclusion is implicit and non-overridable.
- Retrieval is one SQL query: sqlite-vec KNN joined against artifact/space/tag/sensitivity/media/state constraints derived from the lens. Over-fetch retry is a fallback only if the join under-fills `k`.
- Disclosure modes unchanged: `summary` (metadata + stored summary, no verbatim text), `excerpt` (verbatim up to `max_quote_chars`, byte offsets for citation), `full` (off by default, loudly logged).
- The CLI query path (`tessera query --lens <id> "…"`) exercises the identical code path the guardian uses — the v0.0 validation gate remains meaningful.

## 5. Guardian (MCP server)

- **Session = MCP connection bound to (lens, purpose, TTL).** stdio: the client's server config declares lens id + purpose; the owner authorizes the pairing once via CLI. HTTP: OAuth 2.1 per MCP 2026 authorization spec; scopes map to lens ids; incremental consent maps to lens switching.
- **Tools exposed (gated by the session's lens):** `vault_query` (policy-filtered retrieval with citations), `vault_get_item` (single artifact at the lens's disclosure mode), `vault_list_spaces` (only spaces the lens includes, only if `allow_metadata`).
- **Receipts:** opened at session start, appended per query (query text, artifacts touched, disclosure mode, bytes disclosed), finalized at session end or revocation. Each finalized receipt embeds the BLAKE3 hash of the previous receipt — a per-vault hash chain making the audit log tamper-evident. `tessera receipts verify` walks the chain.
- **Revocation:** `tessera sessions revoke <id|--all>` takes effect on the next tool call (guardian checks session validity per call). Guardian holds the DEK in memory only while unlocked; `tessera guardian lock` zeroes it.
- Rate limiting per session (default 100 queries/min) as in v3.

## 6. CLI surface (v1)

`tessera init | unlock | lock | space (create/list/tree) | inbox (add/process/status) | review | import --accept (inbox shortcut for pre-trusted files) | query --lens | lens (create/list/show/edit/delete) | receipts (list/show/export/verify) | sessions (list/revoke) | guardian (serve/status/lock) | eval --golden | diag`

## 7. Error handling and testing

- Errors: `thiserror` per module in core (existing enums kept), `anyhow` at binary edges. Pipeline failures are per-item: a failed stage leaves the item in `pending` with a recorded error, never blocks the queue, never loses the original (encrypt-first ordering).
- **Property tests (proptest):** crypto round-trips; chunking invariants (coverage, no overlap violations, byte-offset validity); lens evaluation (e.g., excluded space never appears regardless of other constraints).
- **Invariant tests:** quarantine (pending never disclosed), space isolation (planted near-duplicate content in a blocked space never retrieved), receipt chain verification, revocation (post-revocation calls fail).
- **Golden retrieval set:** 30–50 Q/A pairs over a real personal corpus; Recall@10 > 0.70 gate before guardian work starts (v0.0 checkpoint from the v3 plan, kept).
- **MCP integration tests:** scripted MCP client (stdio) runs a full session → receipt lifecycle.

## 8. Roadmap (GitHub milestones)

1. **M1 — Vault core:** bundle format + `tessera.json`, crypto (keyslots, DEK, blob store), spaces, artifacts, dedup, `vault-format.md` v1. Fix `VectorIndex` boundary + orphaned `extract` module; rename gateway→guardian; update plan docs.
2. **M2 — Text ingestion & inbox:** PDF/MD/TXT/DOCX extractors, chunking, quarantine states, provenance, `inbox`/`review` CLI.
3. **M3 — Embeddings & retrieval:** ONNX embedding provider, sqlite-vec index, model registry, `query` CLI, golden-set eval harness.
4. **M4 — Lenses & policy-filtered retrieval:** lens CRUD, single-query filtered search, isolation/property tests.
5. **M5 — Disclosure, summaries & receipts:** local summarizer, disclosure renderer, citations, hash-chained receipts. **v0.0 decision gate.**
6. **M6 — Guardian:** MCP server (stdio first, then HTTP+OAuth), sessions, receipt finalization, revocation, rate limiting, MCP integration tests.
7. **M7 — Multimodal:** conversation importers (Claude Code/Claude/ChatGPT), turn-aware chunking, images (OCR + VLM captions), web clipper, transcripts.

Ordering decided 2026-07-05: agent access to the text corpus (Guardian) lands before multimodal ingestion. **First stable version (v0.1.0) = M1–M6.** M7 follows as v0.2.0.

## Explicit non-goals (v1)

Mac app; cloud sync; multi-user/team features; synthesis layer ("about me" profiles, topic digests); knowledge graph; always-on capture; Windows support (Linux is expected to work for guardian hosting; only macOS is a tested dev target).
