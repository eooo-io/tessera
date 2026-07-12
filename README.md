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
- **Receipts** — Hash-chained records of what Tessera accessed and disclosed

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

# Run the guardian
cargo run -p tessera-guardian
```

Remote MCP uses the published `2025-11-25` Streamable HTTP/OAuth contract,
binds loopback by default, and requires an owner pairing for the exact OAuth
client and lens. Setup and TLS-boundary guidance are in
[`docs/http-oauth.md`](docs/http-oauth.md).

Purpose, identity, pairing reuse, lens changes, expiry, and revocation have
deliberately narrow semantics. In particular, purpose is recorded but not
semantically enforced, stdio identity is local configuration trust rather than
attestation, and revocation cannot retract prior disclosure. See
[`docs/authorization-model.md`](docs/authorization-model.md).

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
