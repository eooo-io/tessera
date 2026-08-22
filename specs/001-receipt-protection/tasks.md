# Tasks: Protected Receipt Baseline

**Input**: Design documents from `/specs/001-receipt-protection/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`,
`contracts/receipt-container-v1.md`, `quickstart.md`

**Tests**: Required by Tessera's TDD convention and issue #39.

## Phase 1: Requirements and Decision Setup

**Purpose**: Establish traceable requirements and the consequential security
decision before behavior changes.

- [x] T001 Initialize Spec Kit and record Tessera governance in `.specify/` and `.agents/skills/`
- [x] T002 Create the feature specification, research, data model, container contract, and validation guide in `specs/001-receipt-protection/`
- [x] T003 Write the accepted threat model and architectural decision in `docs/adr/0001-receipt-protection-v0.1.md`

---

## Phase 2: Foundational Failing Tests

**Purpose**: Encode confidentiality, authentication, migration, and owner
interface behavior before implementation.

- [x] T004 [US1] Add failing container confidentiality, keyed authentication, tamper, insertion, deletion, and keyless-regeneration tests in `crates/tessera-core/src/receipt/mod.rs`
- [x] T005 [US2] Add failing legacy migration, format-version, interruption-recovery, copied-vault, and idempotence tests in `crates/tessera-core/src/receipt/mod.rs` and `crates/tessera-core/src/vault/manifest.rs`
- [x] T006 [US3] Add failing CLI migration, verification classification, and plaintext-export warning tests in `crates/tessera-cli/tests/cli.rs`

**Checkpoint**: Each new test fails for the intended missing behavior.

---

## Phase 3: User Story 1 - Protect and Authenticate Receipts (Priority: P1)

**Goal**: Newly finalized receipts are opaque at rest and owner-keyed end to end.

**Independent Test**: Finalize protected sentinel receipts, scan the locked
bundle, verify the chain, and reject tampering or keyless regeneration.

- [x] T007 [US1] Add zeroizing domain-separated receipt key derivation in `crates/tessera-core/src/crypto/keys.rs`
- [x] T008 [US1] Implement protected container v1 encode/decode and explicit receipt error classes in `crates/tessera-core/src/receipt/mod.rs`
- [x] T009 [US1] Replace new receipt finalization, loading, recovery, and chain verification with protected storage and keyed authentication in `crates/tessera-core/src/receipt/mod.rs`
- [x] T010 [US1] Map protected receipt failures to bounded Guardian error responses in `crates/tessera-guardian/src/mcp/tools.rs`

**Checkpoint**: User Story 1 tests pass without legacy migration support.

---

## Phase 4: User Story 2 - Migrate and Recover Legacy Receipts (Priority: P1)

**Goal**: A complete valid plaintext chain transitions atomically to protected
storage and recovers deterministically after interruption.

**Independent Test**: Migrate legacy receipts through each failpoint, reopen,
and compare ids, order, logical content, and exact disclosure verification.

- [x] T011 [US2] Advance and document the supported vault format transition in `crates/tessera-core/src/vault/manifest.rs` and `crates/tessera-core/src/vault/mod.rs`
- [x] T012 [US2] Implement explicit complete-chain legacy migration and deterministic recovery in `crates/tessera-core/src/receipt/mod.rs`
- [x] T013 [US2] Add the confirmed `receipts migrate --yes` owner command in `crates/tessera-cli/src/commands/mod.rs`

**Checkpoint**: User Stories 1 and 2 pass, including copied-vault continuation.

---

## Phase 5: User Story 3 - Verify and Export Honestly (Priority: P2)

**Goal**: Owners receive distinct bounded verification results and explicit
plaintext export behavior.

**Independent Test**: Exercise one fixture per failure class and both JSON/HTML
exports, confirming warnings and complete content.

- [x] T014 [US3] Expose distinct malformed, inconsistent, unauthenticated, and cryptographically invalid verification outcomes in `crates/tessera-core/src/receipt/mod.rs`
- [x] T015 [US3] Update receipt list/show/verify/export output and plaintext warnings in `crates/tessera-cli/src/commands/mod.rs`
- [x] T016 [US3] Reconcile logical receipt schema and portable conformance expectations in `spec/receipt.schema.json`, `conformance/guardian-v1/`, and `crates/tessera-guardian/tests/consumer_contract.rs`

**Checkpoint**: Every verification class and owner export scenario is independently proven.

---

## Phase 6: Documentation and Full Evidence

**Purpose**: Align product claims, storage/recovery contracts, and state-bound
verification with the shipped behavior.

- [x] T017 [P] Update receipt guarantees and limitations in `README.md` and `docs/authorization-model.md`
- [x] T018 [P] Update storage, backup, restore, migration, key-loss, and key-rotation behavior in `spec/vault-format.md` and `docs/recovery-runbook.md`
- [x] T019 Run the targeted tests and quickstart scenarios from `specs/001-receipt-protection/quickstart.md`
- [x] T020 Run `cargo fmt --all -- --check`, strict workspace Clippy, workspace all-target tests, applicable ignored tests, and `git diff --check`
- [x] T021 Audit every issue #39 acceptance criterion against fresh evidence and record remaining #35, #50, #43, and #44 blockers without external publication

---

## Dependencies & Execution Order

- Phase 1 precedes code because it fixes the security claim and non-goals.
- Phase 2 precedes implementation under Tessera's TDD rule.
- User Story 1 is foundational for legacy migration and owner operations.
- User Story 2 depends on protected container and keyed-chain support.
- User Story 3 depends on both storage modes so each failure class is real.
- Documentation tasks T017 and T018 can proceed in parallel only after behavior
  stabilizes; final validation follows all code and documentation changes.

## Implementation Strategy

Implement sequentially on the mission-owned feature branch. Preserve the
existing receipt logical schema and concurrency transaction. Do not add a new
cryptographic dependency, public signing system, external anchor, automatic
retention, or broad metadata encryption. Stop if a failing acceptance test
requires weakening quarantine, exact disclosure verification, portable unlock,
or crash recovery.
