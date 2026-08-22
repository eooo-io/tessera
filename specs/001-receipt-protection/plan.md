# Implementation Plan: Protected Receipt Baseline

**Branch**: `skippy/issue-39-receipt-protection` | **Date**: 2026-08-20 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/001-receipt-protection/spec.md`

**Note**: This template is filled in by the `$speckit-plan` command; its definition describes the execution workflow.

## Summary

Replace plaintext receipt JSON and its unkeyed BLAKE3 chain with a versioned,
opaque receipt container encrypted under a domain-separated vault-derived key
and a chain authenticated under a separate domain-separated key. Preserve the
logical receipt v1/v2 export schema. Add an explicit, idempotent, crash-safe
legacy migration; distinct verification failures; explicit plaintext export;
and matching format, security, recovery, and operator documentation.

## Technical Context

**Language/Version**: Rust 1.97.0, edition 2021

**Primary Dependencies**: Existing `blake3`, `chacha20poly1305`, `rand`,
`zeroize`, `serde`, `serde_json`, `rusqlite`, `clap`; no new runtime dependency

**Storage**: Portable vault bundle, binary protected receipt files, SQLite WAL
receipt index and chain head, versioned `tessera.json` manifest

**Testing**: Rust unit and CLI integration tests, property/adversarial fixtures,
`cargo fmt`, strict Clippy, workspace all-target tests

**Target Platform**: macOS and Linux local vault/Guardian operation

**Project Type**: Rust workspace with core library, CLI, and MCP Guardian binary

**Performance Goals**: Receipt finalization and verification remain bounded by
receipt payload size; migration processes at least 1,000 ordinary receipts
without losing order or exceeding normal local-memory expectations

**Constraints**: Offline-capable; no external trust service; no passphrases or
derived keys in logs or files; distinct key domains; crash-safe migration;
portable cross-host unlock; fail closed on unknown container versions

**Scale/Scope**: One owner-controlled vault, concurrent Guardian receipt
finalizers, existing logical receipt v1/v2 compatibility, vault format v2

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Owner-controlled evidence**: PASS. Receipt payloads remain local and become
  confidential at rest; export is explicit plaintext.
- **Default deny**: PASS. Locked, unauthenticated, malformed, or legacy receipt
  storage fails closed for ordinary list/show/verify/finalize operations.
- **Exact provenance and honest claims**: PASS. Logical v2 evidence remains
  unchanged; ADR limits claims to local owner-keyed authenticity.
- **Portable recovery**: PASS. Container format, manifest transition, migration,
  failpoints, backup/restore, and copied-vault behavior are specified.
- **Test-first evidence**: PASS. Adversarial tests precede implementation and
  full repository gates are required.
- **Approval boundary**: PASS. Local implementation is authorized. Commit,
  push, merge, tag, release, and issue mutation remain outside authority.

**Post-design recheck**: PASS. The container, migration, failure contract, and
quickstart preserve every gate without an exception or new dependency.

## Project Structure

### Documentation (this feature)

```text
specs/001-receipt-protection/
├── plan.md              # This file ($speckit-plan command output)
├── research.md          # Phase 0 output ($speckit-plan command)
├── data-model.md        # Phase 1 output ($speckit-plan command)
├── quickstart.md        # Phase 1 output ($speckit-plan command)
├── contracts/           # Phase 1 output ($speckit-plan command)
└── tasks.md             # Phase 2 output ($speckit-tasks command - NOT created by $speckit-plan)
```

### Source Code (repository root)
```text
crates/tessera-core/src/
├── crypto/keys.rs
├── receipt/mod.rs
└── vault/
    ├── manifest.rs
    └── mod.rs

crates/tessera-cli/src/commands/mod.rs
crates/tessera-cli/tests/cli.rs
crates/tessera-guardian/src/mcp/tools.rs

docs/
├── adr/0001-receipt-protection-v0.1.md
├── authorization-model.md
└── recovery-runbook.md

spec/
├── receipt.schema.json
└── vault-format.md
```

**Structure Decision**: Keep receipt cryptography, storage, migration, and
verification in `tessera-core::receipt`; expose only explicit owner operations
through the existing CLI; keep Guardian behavior unchanged except for bounded
error classification. No new crate or storage abstraction is justified.

## Complexity Tracking

No constitution violations require justification.
