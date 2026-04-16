# Tessera

**Curate your context. Control your agents. Prove what happened.**

A Mac-first personal context vault with policy-gated semantic retrieval — the trust substrate for agentic AI.

Tessera lets you curate what matters, then grant AI agents permission to access only what they need for a specific task — with full auditability through receipts that prove what was accessed and what was disclosed. The name draws from the Roman *tessera*: a physical token that proved specific access had been granted, for a specific purpose, by a specific authority.

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
| `tessera-gateway` | Binary | Localhost API daemon — agent registry, session tokens, purpose-bound access, query endpoint, SSE activity stream |
| `tessera-cli` | Binary | Command-line interface for vault operations, evaluation harness, diagnostics |

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
cargo run -p tessera-cli -- --help

# Run the gateway
cargo run -p tessera-gateway
```

## Project Structure

```
├── crates/
│   ├── tessera-core/         # Domain logic library
│   ├── tessera-gateway/      # Localhost HTTP daemon
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
