# Tasks: Desktop Owner Workbench Revival

**Input**: Design documents in `specs/003-desktop-workbench-revival/`

**Tests**: Required by the feature specification and constitution. Tests precede the corresponding implementation.

## Phase 1: Setup and provenance

- [X] T001 Record base CI, donor diff, dependency topology, capabilities, fixtures, drift, and remote-state provenance in `docs/evidence/desktop-workbench-revival.md`
- [X] T002 Restore the donor application tree from `50a830f` into `apps/tessera-desktop/` without modifying the donor checkout
- [X] T003 Restore and reconcile the donor decision baseline in `docs/desktop-owner-workbench.md`
- [X] T004 Verify Node, Rust, Tauri, theme, ignore, lockfile, and nested-workspace configuration in `apps/tessera-desktop/`

---

## Phase 2: Foundational native boundary

- [X] T005 Add native contract tests for allowed serialized fields and prohibited sensitive fields in `apps/tessera-desktop/src-tauri/src/owner.rs`
- [X] T006 Add synthetic-vault tests for successful format-v3 open and aggregate computation in `apps/tessera-desktop/src-tauri/src/owner.rs`
- [X] T007 Add refusal tests for wrong passphrase, legacy/future formats, migration state, malformed bundles, tampering, and symlinks in `apps/tessera-desktop/src-tauri/src/owner.rs`
- [X] T008 Add lifecycle tests for lock, repeated lock, second open, concurrent operations, and state drop in `apps/tessera-desktop/src-tauri/src/owner.rs`
- [X] T009 Add safe-error and synthetic secret/artifact scan tests in `apps/tessera-desktop/src-tauri/src/owner.rs`
- [X] T010 Implement the process-local serialized vault session and bounded error mapping in `apps/tessera-desktop/src-tauri/src/owner.rs`
- [X] T011 Implement least-disclosure aggregation through public `tessera-core` APIs in `apps/tessera-desktop/src-tauri/src/owner.rs`
- [X] T012 Register only capability, open, and lock commands and remove runtime logging in `apps/tessera-desktop/src-tauri/src/lib.rs`
- [X] T013 Reconcile dependencies and lockfile for zeroization and the narrow command adapter in `apps/tessera-desktop/src-tauri/Cargo.toml`
- [X] T014 Verify the core-only capability allowlist and CSP in `apps/tessera-desktop/src-tauri/capabilities/default.json` and `apps/tessera-desktop/src-tauri/tauri.conf.json`

**Checkpoint**: Native tests prove one deterministic vault lifecycle and closed projection without a WebView.

---

## Phase 3: User Story 1 and 2, live open and lock (P1)

**Goal**: Open one synthetic format-v3 vault, render its sanitized aggregate, and explicitly lock it.

**Independent Test**: Complete wrong-passphrase, correct-passphrase, overview, lock, repeated-lock, and restart scenarios without fixture values or retained secrets.

- [X] T015 [P] [US1] Add typed invoke-adapter tests for success and safe failure in `apps/tessera-desktop/src/native/owner.test.ts`
- [X] T016 [P] [US1] Add locked-initial, unlock-success, unlock-failure, and passphrase-clearing tests in `apps/tessera-desktop/src/App.test.tsx`
- [X] T017 [P] [US2] Add explicit-lock, overview-clearing, and repeated-lock tests in `apps/tessera-desktop/src/App.test.tsx`
- [X] T018 [US1] Implement the typed native contract adapter in `apps/tessera-desktop/src/native/owner.ts`
- [X] T019 [US1] Replace the fixture overview with locked, unlocking, unlocked, and error presentation in `apps/tessera-desktop/src/views/WorkbenchViews.tsx`
- [X] T020 [US1] Connect open and sanitized overview state with unconditional passphrase clearing in `apps/tessera-desktop/src/App.tsx`
- [X] T021 [US2] Connect explicit lock and immediate protected-state clearing in `apps/tessera-desktop/src/App.tsx` and `apps/tessera-desktop/src/components/AppShell.tsx`
- [X] T022 [US1] Add the closed native and overview types in `apps/tessera-desktop/src/types.ts`

**Checkpoint**: The overview is live, least-disclosure, and lockable; no preview record participates.

---

## Phase 4: User Story 3, honest preview shell (P2)

**Goal**: Preserve donor views without representing fixtures or disconnected actions as live owner operations.

**Independent Test**: Navigate every non-overview screen and confirm preview labeling and disabled mutation controls.

- [X] T023 [P] [US3] Add preview-label and disabled-action behavior tests in `apps/tessera-desktop/src/App.test.tsx`
- [X] T024 [US3] Add a persistent preview banner and disable disconnected mutations in `apps/tessera-desktop/src/views/WorkbenchViews.tsx`
- [X] T025 [US3] Remove fixture mutations and success toasts from `apps/tessera-desktop/src/App.tsx`

---

## Phase 5: User Story 4, accessible responsive operation (P2)

**Goal**: Preserve keyboard, theme, reduced-motion, coarse-pointer, and compact-to-wide behavior.

**Independent Test**: Exercise both themes and keyboard flow at all four viewport classes with no page-level overflow.

- [X] T026 [P] [US4] Add theme, focus, semantic, and responsive structure tests in `apps/tessera-desktop/src/App.test.tsx`
- [X] T027 [US4] Reconcile focus, reduced-motion, coarse-pointer, and overflow styling in `apps/tessera-desktop/src/index.css`
- [X] T028 [US4] Reconcile responsive navigation and lifecycle control behavior in `apps/tessera-desktop/src/components/AppShell.tsx` and `apps/tessera-desktop/src/components/Navigation.tsx`

---

## Phase 6: Documentation, CI, and evidence

- [X] T029 [P] Reconcile the root repository map and desktop commands in `README.md`
- [X] T030 [P] Document live versus preview capabilities and secret lifecycle in `apps/tessera-desktop/README.md`
- [X] T031 [P] Update security and unlock boundaries in `docs/desktop-unlock-boundary.md` and `docs/desktop-owner-workbench.md`
- [X] T032 Reconcile frontend and native desktop jobs with post-#89 portability CI in `.github/workflows/ci.yml`
- [X] T033 Complete the provenance, capability, test, smoke, review, limitation, and deferred-workflow matrices in `docs/evidence/desktop-workbench-revival.md`

---

## Phase 7: Exact-state validation and publication

- [X] T034 Run all required Spec Kit prerequisite, checklist, and cross-artifact consistency checks
- [X] T035 Run frontend typecheck, lint, tests, build, and responsive/theme verification from `apps/tessera-desktop/`
- [X] T036 Run native formatting, locked check, tests, and debug Tauri package build from `apps/tessera-desktop/`
- [X] T037 Run root formatting, strict clippy, build, workspace all-target tests, ignored tests, and `git diff --check`
- [X] T038 Perform and record the macOS synthetic-vault smoke test for unlock, overview, lock, themes, focus, and responsive layout
- [ ] T039 Obtain independent security, acceptance, and UX reviews of the exact clean final commit and resolve every blocking finding
- [ ] T040 Publish only focused files to `skippy/desktop-workbench-revival`, open a draft PR, verify local/remote equality, and record the exact commit
- [ ] T041 Require exact-head macOS and Ubuntu CI success, update evidence links if needed, and verify the final remote state

## Dependencies and execution order

- Phase 1 establishes immutable provenance and the recovered buildable donor shell.
- Phase 2 blocks all live frontend work.
- User Stories 1 and 2 share lifecycle state and are delivered together as the MVP.
- User Story 3 depends on the live overview boundary so fixture separation is testable.
- User Story 4 may begin after the donor shell is restored but completes after lifecycle controls settle.
- Documentation and CI follow the implementation; evidence, reviews, and publication bind the final exact state.

## Parallel opportunities

- T015, T016, and T017 target separate adapter and behavior concerns before shared implementation.
- T023 can be authored while native lifecycle implementation is stabilizing.
- T026 can be authored independently of native code.
- T029, T030, and T031 touch separate documentation files.
- Independent security, acceptance, and UX reviews run concurrently on one immutable commit.

## Implementation strategy

The MVP is User Stories 1 and 2: one real open, aggregate overview, and lock workflow. The donor shell remains useful only after User Story 3 makes unfinished capabilities honest. User Story 4 preserves the existing UI quality gate. No later owner workflow is pulled into this slice.
