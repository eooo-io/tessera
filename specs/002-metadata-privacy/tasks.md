# Tasks: Locked-Vault Metadata Privacy

**Input**: Design documents from `/specs/002-metadata-privacy/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, all
files in `contracts/`, and `quickstart.md`

**Tests**: Required by Tessera's constitution, issue #50, and the active goal.

## Phase 1: Requirements, Inventory, and Decision Record

**Purpose**: Establish the complete baseline and approved security contract
before behavior changes.

- [x] T001 Create and validate the feature specification, quality checklist, research, data model, contracts, and validation guide in `specs/002-metadata-privacy/`
- [x] T002 Inventory every current plaintext database field, manifest field, path class, temporary file, journal, backup, and interrupted residue in `docs/metadata-confidentiality-threat-model.md`
- [x] T003 Record the selected database protection, keyed addressing, manifest minimization, migration, permissions, and residual-risk tradeoffs in `docs/adr/0002-metadata-confidentiality-v0.1.md`

---

## Phase 2: Foundational Failing Tests

**Purpose**: Encode the externally meaningful confidentiality and recovery
contract before implementation.

- [x] T004 [US1] Add failing database-key, wrong-key, plaintext-database, tamper, truncation, WAL, temporary-store, and model-registry tests in `crates/tessera-core/src/db/mod.rs` and `crates/tessera-core/src/vault/metadata.rs`
- [x] T005 [US1] Add failing keyed-address, cross-vault unlinkability, confirmation, container-version, relocation, tamper, orphan, and deduplication tests in `crates/tessera-core/src/blob/mod.rs`
- [x] T006 [US1] Add a failing synthetic sentinel inventory and recursive locked-vault byte-and-path scanner in `crates/tessera-core/tests/metadata_privacy.rs`
- [x] T007 [US2] Add failing new-vault, legacy-vault, repeated, interrupted, resumed, malformed, unsupported, and insufficient-space migration tests in `crates/tessera-core/src/vault/metadata.rs` and the existing manifest/vault suites
- [x] T008 [US3] Add failing migrated backup, copy, restore, query, receipt verification, receipt continuation, diagnostics, and repair coverage in `crates/tessera-core/src/vault/metadata.rs` and the existing recovery suite
- [x] T009 [US1] Add failing Unix bundle, database, blob, receipt, inbox, migration, and temporary-file permission coverage in `crates/tessera-core/tests/metadata_privacy.rs` and migration fault tests
- [x] T010 [US2] Add failing owner-confirmed migration and bounded error-output tests in `crates/tessera-cli/tests/cli.rs`

**Checkpoint**: Every new test fails for the intended missing behavior, not a
fixture or compilation defect.

---

## Phase 3: User Story 1 - Protect a Locked Vault Copy (Priority: P1)

**Goal**: New vaults conceal protected metadata and prevent public exact-content confirmation.

**Independent Test**: Populate and close a synthetic vault, then pass the
sentinel scanner and 100-candidate confirmation test with only documented
structural and intentional inbox exposure.

- [x] T011 [US1] Switch the existing bundled SQLite dependency to the reviewed portable SQLCipher build in `Cargo.toml` and `Cargo.lock`
- [x] T012 [US1] Add zeroizing domain-separated database and blob-address key derivation in `crates/tessera-core/src/crypto/keys.rs`
- [x] T013 [US1] Implement keyed SQLCipher connection initialization, immediate key validation, in-memory temporary storage, and bounded errors in `crates/tessera-core/src/db/mod.rs`
- [x] T014 [US1] Add the encrypted `vault_metadata` registry migration in `crates/tessera-core/src/db/migrations/0022_vault_metadata.sql` and `crates/tessera-core/src/db/migrations/mod.rs`
- [x] T015 [US1] Minimize public format-v3 manifests and move creation/model/extension metadata access to `crates/tessera-core/src/vault/manifest.rs`, `crates/tessera-core/src/vault/metadata.rs`, `crates/tessera-core/src/search/mod.rs`, and `crates/tessera-core/src/recovery.rs`
- [x] T016 [US1] Implement versioned blob container v2 and vault-keyed opaque filesystem addressing while retaining protected logical hashes in `crates/tessera-core/src/blob/mod.rs`
- [x] T017 [US1] Require the unlocked key for blob existence and deletion and update affected diagnostics and tests in `crates/tessera-core/src/recovery.rs`, `crates/tessera-core/src/review/mod.rs`, and `crates/tessera-core/src/conversation/persistence.rs`
- [x] T018 [US1] Apply restrictive portable bundle permissions and atomic private writes in `crates/tessera-core/src/vault/mod.rs`, `crates/tessera-core/src/vault/manifest.rs`, `crates/tessera-core/src/crypto/keys.rs`, `crates/tessera-core/src/blob/mod.rs`, and `crates/tessera-core/src/receipt/mod.rs`
- [x] T019 [US1] Remove named web-body temporary files, bound in-memory fetches, harden required external-tool temporary paths, and clean abandoned inbox partials in `crates/tessera-core/src/web.rs`, `crates/tessera-core/src/extract/mod.rs`, and `crates/tessera-core/src/inbox/mod.rs`

**Checkpoint**: User Story 1 passes for newly created synthetic vaults.

---

## Phase 4: User Story 2 - Migrate Without Ambiguity or Data Loss (Priority: P1)

**Goal**: A legacy v1/v2 vault transitions explicitly and recovers from every
durable interruption boundary.

**Independent Test**: Convert a representative legacy fixture at every
failpoint and compare logical inventories, authenticated content, receipts,
queries, and diagnostics after each resumed completion.

- [x] T020 [US2] Implement authenticated legacy blob reading and idempotent v1-to-v2 blob conversion in `crates/tessera-core/src/blob/mod.rs`
- [x] T021 [US2] Implement fixed-path migration state, distrustful phase validation, and exclusive entry checks in `crates/tessera-core/src/vault/metadata.rs`
- [x] T022 [US2] Implement plaintext checkpoint, protected export, inventory comparison, protected selection, retired-source cleanup, and format commit in `crates/tessera-core/src/vault/metadata.rs` and `crates/tessera-core/src/db/mod.rs`
- [x] T023 [US2] Refuse ordinary legacy or in-progress operation and expose the explicit owner-confirmed migration API in `crates/tessera-core/src/vault/mod.rs`
- [x] T024 [US2] Add the `metadata migrate --yes` operation with safe phase reporting and recovery guidance in `crates/tessera-cli/src/commands/mod.rs`

**Checkpoint**: New and migrated vaults satisfy the same protected format
contract; every injected interruption resumes or fails closed with one
authoritative state.

---

## Phase 5: User Story 3 - Preserve Portable Ownership and Recovery (Priority: P2)

**Goal**: Protected vaults retain backup, restore, diagnostics, repair, query,
and receipt continuity across supported hosts.

**Independent Test**: Back up a migrated vault, restore to a new path, unlock,
query, verify and extend its receipt chain, diagnose, repair a derived fault,
and repeat the exact-head suite on macOS and Ubuntu.

- [x] T025 [US3] Key backup barrier and destination connections and preserve protected format permissions in `crates/tessera-core/src/recovery.rs`
- [x] T026 [US3] Reconcile diagnostic blob enumeration, orphan validation, metadata key checks, and repair behavior in `crates/tessera-core/src/recovery.rs`
- [x] T027 [US3] Add ignored controlled storage, migration, query, backup, restore, diagnostic, and repair measurements in `crates/tessera-core/tests/metadata_performance.rs`

**Checkpoint**: User Stories 1 through 3 pass locally with controlled
performance evidence.

---

## Phase 6: User Story 4 - State Exact Remaining Limits (Priority: P2)

**Goal**: Documentation and evidence match every observable locked-vault fact
without claiming protection the implementation cannot provide.

**Independent Test**: Compare a fresh scanner inventory to the threat-model
exposure matrix and find no undocumented path, byte match, attacker claim, or
temporary-file behavior.

- [x] T028 [US4] Update the complete format-v3 storage and migration contract in `spec/vault-format.md`
- [x] T029 [P] [US4] Update backup, restore, migration, repair, temporary-file, forensic, and key-loss guidance in `docs/recovery-runbook.md` and directly affected security docs
- [ ] T030 [US4] Produce the safe criterion matrix, exposure results, test topology, migration results, measurements, residual limitations, and exact CI links in `docs/evidence/metadata-confidentiality-report.md`

**Checkpoint**: The scanner, threat model, ADR, format document, recovery
guidance, and evidence report agree exactly.

---

## Phase 7: Validation, Independent Review, and Publication

**Purpose**: Bind completion to the exact final commit and leave publication
ready for owner review.

- [x] T031 Run all targeted metadata, migration, backup, recovery, permission, plaintext-scan, and performance tests from `specs/002-metadata-privacy/quickstart.md`
- [x] T032 Run `cargo fmt --all -- --check`, strict workspace all-feature Clippy, all-target build, workspace all-target tests, workspace ignored tests, `git diff --check`, and Spec Kit prerequisite and consistency checks
- [ ] T033 Obtain independent security and acceptance review of the exact commit, resolve every blocking finding, and rerun affected validation
- [ ] T034 Commit only issue #50 files, push `skippy/issue-50-metadata-privacy`, open a draft PR with `Closes #50`, and add the safe issue evidence comment
- [ ] T035 Verify local and remote commit equality and require exact-head macOS and Ubuntu CI success while leaving the PR draft and issue open

---

## Dependencies & Execution Order

- Phase 1 fixes the security claim and architecture before code changes.
- Phase 2 precedes implementation under Tessera's test-first rule.
- User Story 1 provides protected storage required by migration.
- User Story 2 depends on User Story 1's v3 readers and writers.
- User Story 3 depends on both new-vault and migrated-vault behavior.
- User Story 4 documents only stabilized behavior and measured results.
- Independent review examines the exact candidate commit before publication;
  blocking fixes require a new exact commit and affected reruns.
- Publication and CI verification follow every local gate. Merge, tag, release,
  private evaluation, and final issue closure remain owner actions.

## Parallel Opportunities

- Threat-model inventory and ADR drafting touch different documentation files
  but converge before foundational tests.
- Within the failing-test phase, database, blob, scanner, migration, recovery,
  permission, and CLI fixtures use separate files and can be prepared
  independently.
- Documentation tasks T028 and T029 can proceed in parallel after behavior
  stabilizes.
- No implementation task is marked parallel because database keying, manifest
  state, blob addressing, migration, and recovery share persistent invariants.

## Implementation Strategy

Work sequentially in the mission-owned worktree. Keep logical hashes and domain
semantics stable inside protected storage while changing only their locked
representation. At every migration write, authenticate and sync the replacement
before retiring its source. Stop for Ezra if implementation evidence reveals a
destructive-only conversion, exact-content confirmation, material portability
regression, ambiguous authoritative state, or repairability/data-loss tradeoff.
