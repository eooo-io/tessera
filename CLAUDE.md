# CLAUDE.md — Project Conventions

## Project

Tessera — Rust monorepo for a portable personal context vault with
policy-gated semantic retrieval. The vault, CLI, and guardian run on macOS
and Ubuntu; CI and protected-bundle interchange cover both.

## Structure

- `crates/tessera-core/` — library crate (all domain logic)
- `crates/tessera-guardian/` — binary crate (the guardian: MCP server daemon, the only agent-facing entry to a vault)
- `crates/tessera-cli/` — binary crate (CLI, ships as `tessera`)
- `apps/tessera-desktop/` — Tauri 2 + React owner workbench. Live workflow: open a current format-v3 vault, view a sanitized aggregate overview, and explicitly lock. Other owner screens are labeled previews.
- `mac/` — preserved dormant SwiftUI placeholder (not the app)
- `spec/` — OpenAPI spec, JSON schemas
- `docs/desktop-owner-workbench.md` — current desktop decision and live/preview boundary
- `docs/superpowers/specs/2026-07-04-tessera-guardian-vault-design.md` — Authoritative design (architecture, sequencing). The 2026-07-04 "Mac app deferred" / macOS-only-dev notes are historical; see the desktop doc for the current workbench.
- `Tessera-MVP-Plan-v3.md` — Reference for crypto params, lens semantics, sensitivity levels, performance budgets (architecture/sequencing sections superseded)
- `tests/` — Integration tests and fixtures

## Build & Test

```bash
cargo build                        # build all
cargo test                         # test all
cargo test -p tessera-core         # test core only
cargo fmt --check                  # format check
cargo clippy -- -D warnings        # lint
```

Workspace CI runs that suite on macOS and Ubuntu, plus protected-vault
interchange between them. Desktop UI and native-boundary jobs live under
`apps/tessera-desktop/` (see that app's README).

## Conventions

- **Error handling**: `thiserror` for library errors in core, `anyhow` in binary crates.
- **IDs**: ULID strings prefixed with type (e.g., `space_01HXYZ...`, `art_01HXYZ...`).
- **Database**: SQLite via rusqlite. WAL mode. Migrations in `crates/tessera-core/src/db/migrations/`.
- **Vector index**: sqlite-vec (SQLite extension). Vectors live in the same database as metadata, enabling policy-filtered retrieval in a single SQL query. `VectorIndex` trait allows swapping to Qdrant/pgvector for v1.
- **Tests**: Unit tests in `#[cfg(test)] mod tests` at the bottom of each module. Integration tests in `tests/integration/`. Property-based tests with `proptest` for policy evaluation and crypto.
- **Naming**: snake_case for files/modules. PascalCase for structs/enums/variants.
- **Public API**: Each module directory has `mod.rs` with the public surface. `lib.rs` re-exports top-level types.
- **Traits**: `EmbeddingProvider` and `VectorIndex` are trait-based for implementation swapping.
- **Crypto**: XChaCha20-Poly1305 for blobs. Argon2id for key derivation. Passphrase unlock is the portable path; macOS Keychain is optional convenience, never a requirement.
- **No unwrap in lib code**: Use `expect()` only in tests and binary entry points with clear messages.
- **Dependencies**: Shared versions pinned in workspace `Cargo.toml`. Crates use `workspace = true`.

## Spec Reference

The authoritative design is `docs/superpowers/specs/2026-07-04-tessera-guardian-vault-design.md`; work items live in GitHub milestones M1–M7 (see `GOAL.md`). `Tessera-MVP-Plan-v3.md` remains the reference for crypto parameters, lens semantics, sensitivity levels, and performance budgets. The owner workbench is documented in `docs/desktop-owner-workbench.md`.
