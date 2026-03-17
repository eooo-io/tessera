# Semblance AI

**Your context. Your rules.**

A Mac-first personal context vault with policy-gated semantic retrieval for agentic AI.

Semblance lets you curate what matters, then grant AI agents permission to access only what they need for a specific task — with full auditability through receipts that prove what was accessed and what was disclosed.

## Core Principles

- **Nothing Automatic** — All data enters the vault by explicit user action
- **Default Deny** — Agents see nothing unless granted a scoped lens
- **Minimize Disclosure** — Agents receive the smallest slice required
- **Prove What Happened** — Every access is logged with receipts
- **User-Owned and Portable** — Your vault is exportable, inspectable, and revocable

## Architecture

| Crate | Type | Description |
|-------|------|-------------|
| `semblance-core` | Library | Vault storage, ingestion, chunking, embeddings, HNSW index, policy evaluation, disclosure rendering, receipts |
| `semblance-gateway` | Binary | Localhost API daemon — agent registry, session tokens, purpose-bound access, query endpoint, SSE activity stream |
| `semblance-cli` | Binary | Command-line interface for vault operations, evaluation harness, diagnostics |

A **SwiftUI Mac app** (`mac/`) provides the desktop interface for spaces, lens building, agent grant dialogs, session monitoring, and receipt viewing.

## Key Concepts

- **Spaces** — Hierarchical containers for organizing artifacts
- **Artifacts** — Files/documents with metadata, tags, and version history
- **Lenses** — Reusable access policies defining what an agent can see and how
- **Sessions** — Time-bounded, purpose-declared access grants for agents
- **Receipts** — Immutable records of what was accessed during a session

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
cargo run -p semblance-cli -- --help

# Run the gateway
cargo run -p semblance-gateway
```

## Project Structure

```
├── crates/
│   ├── semblance-core/       # Domain logic library
│   ├── semblance-gateway/    # Localhost HTTP daemon
│   └── semblance-cli/        # CLI binary
├── mac/                      # SwiftUI Mac app
├── spec/                     # OpenAPI spec, JSON schemas
├── specs/                    # Product specs and MVP plan
├── tests/                    # Integration tests and fixtures
└── assets/                   # Logo assets
```

## License

MIT — see [LICENSE](LICENSE).

## Contact

- GitHub Issues: [eooo-io/semblance-ai](https://github.com/eooo-io/semblance-ai/issues)
- Email: dev@eooo.io
- Website: https://eooo.io
