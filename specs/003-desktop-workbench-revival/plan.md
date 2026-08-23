# Implementation Plan: Desktop Owner Workbench Revival

**Branch**: `skippy/desktop-workbench-revival` | **Date**: 2026-08-23 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/003-desktop-workbench-revival/spec.md`

## Summary

Reconcile the additive Tauri 2 and React workbench from donor commit `50a830f3c08874e990d588291220328c7fceb13c` onto exact post-#89 base `488560894d188f97f2365e56cfdc4853a1ad2f00`. Replace its fixture overview with three narrow native commands for capability discovery, open-and-sanitize, and explicit lock. A process-local serialized state owns the only `tessera-core::Vault`; React receives a closed aggregate contract and every remaining fixture view is labeled preview-only.

## Technical Context

**Language/Version**: Rust 1.97.0; TypeScript 6.0.x; React 19.2.x

**Primary Dependencies**: `tessera-core`; Tauri 2.11.x; Vite 8.1.x; Tailwind CSS 4.3.x; DaisyUI 5.6.x; packaged `@eooo-io/theme` 0.1.0; Serde; zeroize

**Storage**: Existing portable Tessera format-v3 vault bundle with protected SQLCipher metadata, opaque blob addresses, protected receipts, and owner-held keyslots. No desktop-specific persistent state.

**Testing**: Rust unit and integration tests with synthetic temporary vaults; Vitest and Testing Library; TypeScript and Oxlint; Cargo workspace regression gates; Tauri debug bundle smoke test

**Target Platform**: macOS manual/native primary target; Ubuntu and macOS CI; browser-only frontend harness for deterministic presentation tests

**Project Type**: Cross-platform desktop application layered beside an existing Rust workspace

**Performance Goals**: Unlock remains governed by the vault KDF; aggregate projection adds no content reads; lock and repeated-lock operations complete immediately from the owner's perspective; compact-to-wide UI remains responsive

**Constraints**: Offline; least disclosure; no path or secret echoes; no general filesystem, shell, SQL, or generic command capability; no new persistent format; no Guardian bypass; donor and preserved worktrees remain immutable

**Scale/Scope**: One live workflow, three owner commands, one sanitized overview, nine retained views, four responsive classes, two themes

## Constitution Check

*GATE: Passed before research and passed again after design.*

- **Owner-Controlled Private Evidence**: Passphrase exists only for the explicit invocation, native state owns the unlocked vault, and no desktop persistence is introduced.
- **Default Deny and Minimum Disclosure**: The result contract is a closed aggregate field set; all other native capabilities remain unavailable.
- **Exact Provenance and Honest Audit Claims**: Donor/base/final commits, fixture/live matrix, tests, reviews, and CI are recorded exactly.
- **Portable, Recoverable Formats**: The desktop uses current `tessera-core::Vault::open` and does not alter format, migration, backup, repair, receipt, or portability behavior.
- **Test-First Evidence**: Native and frontend behavioral tests precede implementation changes, followed by targeted, workspace, ignored, packaged, responsive, and manual validation.
- **Release authority**: Work ends at a draft pull request. No merge, tag, release, issue closure, or private evaluation is authorized.

No constitutional exception or ADR is required. The existing desktop decision remains valid after adding the post-#89 confidentiality and secret-lifecycle constraints documented in this feature.

## Project Structure

### Documentation (this feature)

```text
specs/003-desktop-workbench-revival/
├── checklists/requirements.md
├── contracts/native-owner-v1.md
├── data-model.md
├── plan.md
├── quickstart.md
├── research.md
├── spec.md
└── tasks.md
```

### Source Code (repository root)

```text
apps/tessera-desktop/
├── src/
│   ├── components/       # owner shell, navigation, lifecycle controls
│   ├── data/             # visibly preview-only donor fixtures
│   ├── native/           # typed invoke adapter
│   ├── views/            # live overview plus preview views
│   └── *.test.tsx        # behavior and layout tests
├── src-tauri/
│   ├── capabilities/     # core-only Tauri capability allowlist
│   └── src/
│       ├── lib.rs        # Tauri registration and app lifecycle
│       └── owner.rs      # testable serialized native session adapter
└── vendor/               # exact Factor-E theme package snapshot

docs/
├── desktop-owner-workbench.md
├── desktop-unlock-boundary.md
└── evidence/desktop-workbench-revival.md

.github/workflows/ci.yml  # current CI plus focused desktop UI/native jobs
```

**Structure Decision**: Keep the desktop crate as an independent Cargo workspace under `apps/` so root Rust gates do not acquire platform WebView toolchains. Domain behavior remains in `tessera-core`; the nested native crate is an adapter and the frontend is a projection client.

## Design Sequence

1. Import only the donor's additive application and decision document.
2. Add native contract tests for current-format open, safe refusals, least disclosure, state serialization, lock lifecycle, and concurrency.
3. Implement the native owner adapter by composing public `tessera-core` APIs.
4. Add frontend contract and behavior tests, then connect the live lifecycle and label fixture-only views.
5. Reconcile root README, desktop docs, security boundary, and current CI without overwriting #89 portability jobs.
6. Run exact validation, manual synthetic smoke, independent reviews, publication, and exact-head CI.

## Complexity Tracking

No constitution violations require justification.
