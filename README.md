# Tessera

[![Rust](https://img.shields.io/badge/Rust-DEA584?style=for-the-badge&logo=rust&logoColor=000000)](https://www.rust-lang.org/)
[![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![SwiftUI](https://img.shields.io/badge/SwiftUI-F05138?style=for-the-badge&logo=swift&logoColor=white)](https://developer.apple.com/xcode/swiftui/)
[![macOS](https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=apple&logoColor=white)](https://www.apple.com/macos/)
[![Axum](https://img.shields.io/badge/Axum-E6522C?style=for-the-badge&logo=rust&logoColor=white)](https://github.com/tokio-rs/axum)
[![ONNX Runtime](https://img.shields.io/badge/ONNX_Runtime-005CED?style=for-the-badge&logo=onnx&logoColor=white)](https://onnxruntime.ai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-F5C518?style=for-the-badge)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/eooo-io/tessera/ci.yml?style=for-the-badge&logo=github&label=CI)](https://github.com/eooo-io/tessera/actions/workflows/ci.yml)

**Curate your context. Control your agents. Prove what happened.**

A Mac-first personal context vault with policy-gated semantic retrieval — the trust substrate for agentic AI.

Tessera lets you curate what matters, then grant AI agents a narrow, owner-approved lens with exact disclosure receipts. The declared purpose is audit context, not a semantic firewall. The name draws from the Roman *tessera*: a physical token that represented specific access granted by a specific authority.

## Core Principles

- **Nothing Automatic** — All data enters the vault by explicit user action
- **Default Deny** — Agents see nothing unless granted a scoped lens
- **Minimize Disclosure** — Agents receive the smallest slice required
- **Prove What Happened** — Every access is logged with receipts
- **User-Owned and Portable** — Your vault is exportable, inspectable, and revocable

## Architecture

| Crate | Type | Description |
|-------|------|-------------|
| `tessera-core` | Library | Vault storage, ingestion, chunking, embeddings, vector index, policy evaluation, disclosure rendering, receipts |
| `tessera-guardian` | Binary | MCP guardian — stdio plus OAuth-protected Streamable HTTP, purpose/lens sessions, and exact receipts |
| `tessera-cli` | Binary | Command-line interface for vault operations, evaluation harness, diagnostics |

A **SwiftUI Mac app** (`mac/`) provides the desktop interface for spaces, lens building, agent grant dialogs, session monitoring, and receipt viewing.

## Key Concepts

- **Spaces** — Hierarchical containers for organizing artifacts
- **Artifacts** — Files/documents with metadata, tags, and version history
- **Lenses** — Reusable access policies defining what an agent can see and how
- **Sessions** — Time-bounded uses of an immutable pairing and lens revision
- **Receipts** — Encrypted, owner-authenticated records of what Tessera accessed and disclosed

## Development

```bash
# Build all crates
cargo build

# Run all tests
cargo test

# Check formatting and lints
cargo fmt --check
cargo clippy -- -D warnings

# Run the CLI
cargo run -p tessera-cli -- --help

# Run the guardian with a no-echo owner prompt
cargo run -p tessera-guardian -- --vault /path/V.tessera \
  --pairing pair_... --prompt-passphrase
```

Remote MCP uses the published `2025-11-25` Streamable HTTP/OAuth contract,
binds loopback by default, and requires an owner pairing for the exact OAuth
client and lens. Setup and TLS-boundary guidance are in
[`docs/http-oauth.md`](docs/http-oauth.md). Real-binary stdio and HTTP lifecycle
coverage, adversarial cases, and remaining limitations are recorded in
[`docs/evidence/mcp-integration-report.md`](docs/evidence/mcp-integration-report.md).
The versioned consumer surface, negotiation rules, checked-in schemas, and
portable synthetic clients are documented in
[`docs/guardian-consumer-contract-v1.md`](docs/guardian-consumer-contract-v1.md)
and [`conformance/guardian-v1/`](conformance/guardian-v1/).

Purpose, identity, pairing reuse, lens changes, expiry, and revocation have
deliberately narrow semantics. In particular, purpose is recorded but not
semantically enforced, stdio identity is local configuration trust rather than
attestation, and revocation cannot retract prior disclosure. See
[`docs/authorization-model.md`](docs/authorization-model.md).

Guardian startup never reads `TESSERA_PASSPHRASE`. Non-interactive clients
should deliver the passphrase once over an inherited descriptor; private-file
and no-echo prompt fallbacks remain portable. Idle/explicit lock behavior,
keyslot recovery, and residual risks are documented in
[`docs/guardian-unlock.md`](docs/guardian-unlock.md).

Embedding assets are pinned by a repository-controlled manifest and verified
before installation and again before runtime loading. Online fetch, offline
cross-host provisioning, fixed v1 dimensions, and resumable shadow reindexing
are documented in
[`docs/model-supply-chain.md`](docs/model-supply-chain.md).

Integrity classifications, consistency-barrier backup, restore verification,
and the no-fabricated-repair boundary are documented in
[`docs/recovery-runbook.md`](docs/recovery-runbook.md).

Finalized receipt payloads are stored in encrypted `.trc` containers. Their
chain uses vault-derived keyed tokens, so `tessera receipts verify` proves
owner-keyed local authenticity after unlock. It does not provide a public
signature, identity attestation, external timestamp, or non-repudiation.
Legacy plaintext receipt chains require an explicit, restart-safe `tessera
receipts migrate --yes`. `receipts show` and `receipts export` produce
plaintext owner-review material and warn accordingly. The exact threat and
recovery boundary is recorded in
[`ADR-0001`](docs/adr/0001-receipt-protection-v0.1.md).

## Quarantine review

Ingested artifacts remain `pending` and unreachable through every lens until
the owner reviews them. `tessera review` shows an in-memory content preview,
encrypted-original and processing status, provenance, version, tags,
sensitivity, chunks, embeddings, summaries, and active processing errors. The
owner can inspect a longer preview, retry processing, edit classification and
accept, archive, skip, or quit. Previews are printed only to the owner terminal
and are never written to plaintext temporary files.

`tessera review --accept-all` first lists the affected set and requires an
explicit `PROMOTE <count>` confirmation (or `--yes`). It refuses unsupported,
failed, or empty processing results unless the owner also passes
`--allow-incomplete`. That override is deliberately loud; a filename is not a
content review, no matter how confident the flag looks.

## Transcript ingestion

VTT and SRT files are parsed into normalized speaker turns with exact
media-time ranges. Plain `.txt` files use the transcript path only
when at least two `Speaker: text` lines are recognized; bracketed timestamps
such as `[00:01.000 --> 00:02.500]` are preserved when present. Ordinary text
remains on the passthrough extractor.

Transcript chunks pack whole turns, even when one turn exceeds the normal
target size. Owner CLI results and Guardian citations include the covered media
time range; source text remains untrusted evidence under the same lens,
quarantine, disclosure, and receipt path as documents.

## Claude Code session ingestion

`tessera conversation import-claude-code <session.jsonl> --space <id>` imports
an explicit Claude Code session export through the branch- and tool-aware
conversation pipeline. The raw JSONL and every derived conversation remain
encrypted, restricted, and pending; imports never replay tools or silently
promote content. Interrupted runs resume with `conversation
resume-claude-code`, while `conversation metadata` filters the whitelisted
session/project/git metadata index. The exact preservation and private-test
boundary are documented in
[`docs/claude-code-importer-v1.md`](docs/claude-code-importer-v1.md).

## Claude and ChatGPT archive ingestion

`tessera conversation import-claude <conversations.json> --space <id>` and
`tessera conversation import-chatgpt <conversations.json> --space <id>` import
account data exports through separate source adapters and the same durable
conversation runner. Their matching `resume-claude` and `resume-chatgpt`
commands continue intentional checkpoints from the authenticated encrypted
source. ChatGPT mapping branches remain separate and only the explicit current
branch is rendered; Claude content blocks, tool events, and attachments retain
source order and identifiers. Originals and derived conversations are
restricted, encrypted, and pending by default. No attachment URL is fetched.
The supported v1 shapes, safe-drift behavior, and post-freeze private-archive
test boundary are documented in
[`docs/conversation-archive-importers-v1.md`](docs/conversation-archive-importers-v1.md).

## Web clipping

`tessera inbox add-url <url>` performs one explicit, bounded article fetch and
stages Readability-extracted Markdown. It does not crawl, execute page scripts,
or follow redirects. Fetches accept only HTTP(S), reject credentials and any
DNS result in a non-public address range, pin the validated address for the
request, require an HTML response, and stop at 10 MiB or 30 seconds. When a
site redirects, pass the canonical destination URL explicitly.

Run `tessera inbox process --space <id>` after staging, then review the pending
artifact normally. The requested/final URL, extracted title, publication date,
and fetch time remain attached to the exact artifact version. Owner results and
Guardian citations show the source URL only when metadata disclosure is
allowed. In vault format v3, URLs and web-source metadata are inside the
SQLCipher-protected database. Curl returns the bounded response body, status,
and content type through an in-memory pipe without a named response or header
file. The intentional staged Markdown remains plaintext in `inbox/` until the
normal intake pipeline encrypts and removes it.

## Relevance minimization

Semantic queries use cosine similarity over normalized MiniLM vectors and
apply the calibrated floor for the exact embedding model before any content is
rendered or counted as disclosed. The current
`all-MiniLM-L6-v2@onnx-1` floor is `0.20`. An unknown model/version fails closed
until it is calibrated; it does not inherit another model's number by vibes.

A lens may set `min_relevance_score` to a stricter value. The effective floor
is `max(model floor, lens floor)`, so an agent cannot weaken the system default.
Empty semantic results print `No results.` and receipts record the threshold,
candidate/rejection counts, best candidate score, and whether the outcome was
`results`, `no_result`, or `failed`. Rejected candidates are never recorded as
accessed artifacts. Direct `vault_get_item` access is policy-checked but is not
a semantic query and has no relevance threshold.

The floor reduces accidental low-relevance disclosure. It does **not** prove
that a returned passage is true or answers the question. Calibration method,
tradeoffs, and limitations are recorded in
[`docs/evidence/relevance-floor-calibration.md`](docs/evidence/relevance-floor-calibration.md).

A bounded FTS5/reciprocal-rank-fusion experiment found no improvement over the
vector path, so production remains vector-only. The reproducible fixture,
measurements, rejected design, and reindex decision are recorded in
[`docs/evidence/hybrid-retrieval-experiment.md`](docs/evidence/hybrid-retrieval-experiment.md).

The realistic private-corpus gate uses a local `private-eval-v1` plan with
30–50 owner-reviewed questions. Its schema is
[`spec/private-eval-plan.schema.json`](spec/private-eval-plan.schema.json), and
the v0.1 thresholds are predeclared in
[`docs/evidence/private-eval-thresholds-v0.1.md`](docs/evidence/private-eval-thresholds-v0.1.md).
Raw private plans, queries, source text, and raw results stay outside Git.

## Untrusted evidence boundary

Guardian tool results use the versioned
`tessera.guardian.tool-result.v1` structured envelope. Retrieved text, titles,
space names, historical code/tool events, and diagnostics are explicitly
classified as untrusted data with no instruction authority. The text fallback
is a serialized copy of the same JSON object, so source text cannot escape by
spoofing Markdown, XML, or JSON-RPC delimiters. Consumer duties and residual
limits are documented in
[`docs/untrusted-content-boundary.md`](docs/untrusted-content-boundary.md).

## Project Structure

```
├── crates/
│   ├── tessera-core/         # Domain logic library
│   ├── tessera-guardian/      # Localhost HTTP daemon
│   └── tessera-cli/          # CLI binary
├── mac/                      # SwiftUI Mac app
├── spec/                     # OpenAPI spec, JSON schemas
├── Tessera-MVP-Plan-v3.md    # Authoritative MVP plan
└── tests/                    # Integration tests and fixtures
```

## License

MIT — see [LICENSE](LICENSE).

## Contact

- Email: dev@eooo.io
- Website: https://eooo.io
