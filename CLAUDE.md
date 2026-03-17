# CLAUDE.md — Project Conventions

## Project

Semblance AI — Rust monorepo for a Mac-first personal context vault with policy-gated semantic retrieval.

## Structure

- `crates/semblance-core/` — library crate (all domain logic)
- `crates/semblance-gateway/` — binary crate (localhost HTTP daemon)
- `crates/semblance-cli/` — binary crate (CLI, ships as `semblance`)
- `mac/` — SwiftUI Mac app (placeholder)
- `spec/` — OpenAPI spec, JSON schemas
- `specs/` — Product specs and MVP plan (source of truth for domain design)
- `tests/` — Integration tests and fixtures

## Build & Test

```bash
cargo build                        # build all
cargo test                         # test all
cargo test -p semblance-core       # test core only
cargo fmt --check                  # format check
cargo clippy -- -D warnings        # lint
```

## Conventions

- **Error handling**: `thiserror` for library errors in core, `anyhow` in binary crates.
- **IDs**: ULID strings prefixed with type (e.g., `space_01HXYZ...`, `art_01HXYZ...`).
- **Database**: SQLite via rusqlite. WAL mode. Migrations in `crates/semblance-core/src/db/migrations/`.
- **Tests**: Unit tests in `#[cfg(test)] mod tests` at the bottom of each module. Integration tests in `tests/integration/`. Property-based tests with `proptest` for policy evaluation and crypto.
- **Naming**: snake_case for files/modules. PascalCase for structs/enums/variants.
- **Public API**: Each module directory has `mod.rs` with the public surface. `lib.rs` re-exports top-level types.
- **Traits**: `EmbeddingProvider` and `VectorIndex` are trait-based for implementation swapping.
- **Crypto**: XChaCha20-Poly1305 for blobs. Argon2id for key derivation. macOS Keychain for key storage.
- **No unwrap in lib code**: Use `expect()` only in tests and binary entry points with clear messages.
- **Dependencies**: Shared versions pinned in workspace `Cargo.toml`. Crates use `workspace = true`.

## Spec Reference

The authoritative spec for domain types, schemas, APIs, and iteration sequencing is `specs/Semblance-MVP-Plan-v2.md`.
