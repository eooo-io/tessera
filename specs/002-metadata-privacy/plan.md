# Implementation Plan: Locked-Vault Metadata Privacy

**Branch**: `skippy/issue-50-metadata-privacy` | **Date**: 2026-08-23 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/002-metadata-privacy/spec.md`

## Summary

Move the complete SQLite metadata store, including journals and vector pages,
behind owner-keyed page encryption; replace public plaintext-hash blob paths
with vault-keyed opaque addresses while retaining the plaintext content hash
inside the protected database and protected receipts; minimize the public
manifest; and provide an explicit, restart-safe format-v2 to format-v3
migration. Add synthetic locked-vault scanning, restrictive filesystem
handling, bounded temporary processing, recovery tests, performance evidence,
and exact residual-exposure documentation.

## Technical Context

**Language/Version**: Rust 1.97.0, edition 2021

**Primary Dependencies**: Existing `blake3`, `chacha20poly1305`, `rand`,
`zeroize`, `serde`, `serde_json`, `rusqlite`, `sqlite-vec`, `tempfile`; switch
the existing bundled SQLite build to the reviewed bundled SQLCipher feature
with vendored OpenSSL

**Storage**: Portable vault format v3, SQLCipher-encrypted SQLite database and
journals, versioned XChaCha20-Poly1305 blob containers at keyed opaque paths,
protected receipt containers, minimal JSON manifest, binary keyslots

**Testing**: Rust unit and CLI integration tests, migration fault injection,
synthetic byte-and-path scanner, property/adversarial fixtures, ignored
controlled performance tests, `cargo fmt`, strict Clippy, all-target build and
workspace test suites

**Target Platform**: macOS and Ubuntu local vault and Guardian operation

**Project Type**: Rust workspace with core library, CLI, and MCP Guardian

**Performance Goals**: Ordinary protected queries remain practical for a local
single-owner vault; a controlled representative migration completes with
linear blob and database work; evidence records storage overhead and at least
three repeated query, migration, backup, diagnostic, and repair measurements

**Constraints**: Offline-capable; no external key service; existing keyslots
remain portable; no raw keys or private data in diagnostics; database key and
blob-address key are domain-separated; temporary SQLite stores remain in
memory; migration preserves one authoritative recoverable state; no silent
empty-database creation on wrong keys or unsupported formats

**Scale/Scope**: One owner-controlled vault, all 21 current schema migrations,
all content and derived blob classes, existing protected receipts, existing
backup and repair flows, bundle format transition from v1/v2 to v3

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Owner-controlled private evidence**: PASS. Encryption remains local and
  derives from the existing owner-held vault key. No service or machine
  identity becomes authoritative.
- **Default deny and minimum disclosure**: PASS. Wrong keys, unsupported
  formats, incomplete migrations, and damaged metadata fail closed. Public
  bundle metadata is reduced to the unlock and portability minimum.
- **Exact provenance and honest claims**: PASS. Logical content hashes and
  receipt evidence remain unchanged inside protected storage. Residual size,
  count, timing, inbox, rollback, and forensic limits are explicit.
- **Portable and recoverable formats**: PASS. SQLCipher and both blob container
  versions are open and documented. Migration, backup, restore, and repair are
  exercised on both required platforms.
- **Test-first evidence**: PASS. Sentinel, confirmation, migration-fault,
  tamper, portability, permissions, and performance tests precede completion.
- **Cryptographic separation**: PASS. Database encryption, blob addressing,
  blob encryption, receipt encryption, and receipt authentication use distinct
  derivation domains.
- **Approval boundary**: PASS. The migration is non-destructive until a fully
  validated replacement exists, introduces no accepted confirmation risk, and
  retains portability and repairability. Merge, release, private evaluation,
  and unrelated work remain owner-gated.

**Post-design recheck**: PASS. The selected design protects the full schema
without hundreds of column-specific query changes, keeps plaintext hashes as
protected integrity evidence, preserves ordinary SQLite diagnostics after
unlock, and provides an explicit recoverable format boundary. No constitution
exception or unresolved owner decision remains.

## Project Structure

### Documentation (this feature)

```text
specs/002-metadata-privacy/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── metadata-format-v3.md
│   ├── migration-state-v1.md
│   └── plaintext-scan-v1.md
├── checklists/requirements.md
└── tasks.md
```

### Source Code (repository root)

```text
crates/tessera-core/src/
├── blob/mod.rs
├── crypto/keys.rs
├── db/
│   ├── mod.rs
│   └── migrations/
├── inbox/mod.rs
├── recovery.rs
├── search/mod.rs
├── vault/
│   ├── manifest.rs
│   ├── metadata.rs
│   └── mod.rs
└── web.rs

crates/tessera-cli/src/commands/mod.rs
crates/tessera-cli/tests/cli.rs

spec/vault-format.md
docs/
├── adr/0002-metadata-confidentiality-v0.1.md
├── metadata-confidentiality-threat-model.md
├── recovery-runbook.md
└── evidence/metadata-confidentiality-report.md
```

**Structure Decision**: Keep encryption, migration, keyed addressing, and
filesystem enforcement inside `tessera-core`; add one explicit owner migration
command to the existing CLI; keep all Guardian and domain queries operating on
ordinary unlocked SQLite connections. No new service, crate, storage
abstraction, or transport behavior is justified.

## Complexity Tracking

No constitution violations require justification. The database library build
change is a focused replacement for the existing bundled SQLite feature, not a
second persistence system.
