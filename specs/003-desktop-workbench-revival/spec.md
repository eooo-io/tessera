# Feature Specification: Desktop Owner Workbench Revival

**Feature Branch**: `skippy/desktop-workbench-revival`

**Created**: 2026-08-23

**Status**: Approved for implementation

**Input**: Ezra's owner-authorized request to revive donor commit `50a830f3c08874e990d588291220328c7fceb13c` on post-#89 main `488560894d188f97f2365e56cfdc4853a1ad2f00` and complete one real native owner workflow.

## User Scenarios & Testing

### User Story 1 - Open and understand a vault (Priority: P1)

As the vault owner, I want to select an existing current-format vault, unlock it, and see a deliberately small operational summary without exposing private records to the desktop presentation layer.

**Why this priority**: A native workbench is useful only when it performs a real owner operation while preserving Tessera's post-#89 confidentiality boundary.

**Independent Test**: Open a synthetic current-format vault with the correct passphrase and verify that the workbench reports only lock state, format version, approved aggregate counts, receipt-chain status, and bounded diagnostic status.

**Acceptance Scenarios**:

1. **Given** a valid current-format synthetic vault, **When** the owner supplies its location and correct passphrase, **Then** the workbench becomes unlocked and renders only the allowed aggregate overview.
2. **Given** a wrong passphrase, malformed vault, unsupported or legacy format, active migration, or symlinked bundle, **When** open is attempted, **Then** the workbench remains locked and shows bounded guidance without sensitive technical detail.
3. **Given** an already unlocked vault, **When** a second open is attempted, **Then** the original state remains authoritative and no ambiguous replacement occurs.

---

### User Story 2 - Lock and clear protected state (Priority: P1)

As the vault owner, I want an explicit lock action that immediately removes protected overview data and releases the native unlocked state.

**Why this priority**: Unlock without dependable relock is an incomplete secret lifecycle.

**Independent Test**: Unlock a synthetic vault, invoke lock, and verify that the UI returns to its locked state, all live overview data disappears, and repeating lock is harmless.

**Acceptance Scenarios**:

1. **Given** an unlocked vault and visible aggregate overview, **When** the owner locks it, **Then** native unlocked state is dropped and protected UI state is immediately cleared.
2. **Given** a locked workbench, **When** lock is requested again, **Then** it remains safely locked without an error or state ambiguity.
3. **Given** a passphrase submission that succeeds or fails, **When** the native call completes, **Then** the passphrase field is empty and the secret is absent from persistent storage, logs, telemetry, crash text, fixtures, and generated artifacts.

---

### User Story 3 - Distinguish live and preview capabilities (Priority: P2)

As the vault owner, I want every unfinished screen and action to identify itself as preview-only so I cannot confuse sample records with my vault or mistake a visual control for a completed operation.

**Why this priority**: Honest capability labeling prevents a polished shell from becoming misleading product evidence.

**Independent Test**: Navigate every non-overview screen and confirm that fixture records and disconnected actions are visibly labeled or disabled and never merge with the live overview.

**Acceptance Scenarios**:

1. **Given** any fixture-only screen, **When** the owner views it, **Then** it displays a persistent preview label and disconnected mutations are disabled or explicitly unavailable.
2. **Given** an unlocked live overview, **When** the owner navigates to another screen, **Then** fixture content remains visually and structurally separate from live data.

---

### User Story 4 - Operate the workbench accessibly (Priority: P2)

As the vault owner, I want the desktop shell to remain usable across supported window sizes, themes, keyboard navigation, reduced-motion settings, and coarse-pointer input.

**Why this priority**: Revival must preserve the donor's usable interface rather than reducing it to a narrow technical demonstration.

**Independent Test**: Exercise the synthetic unlock and lock flow at compact, medium, desktop, and wide sizes in light and dark themes using keyboard-only navigation, and confirm no horizontal page overflow.

**Acceptance Scenarios**:

1. **Given** any supported viewport class, **When** the owner navigates and completes unlock and lock, **Then** controls remain reachable, focus is visible, and no page-level horizontal overflow occurs.
2. **Given** light, dark, reduced-motion, or coarse-pointer preferences, **When** the workbench is used, **Then** the interface honors the applicable preference without hiding state or controls.

### Edge Cases

- The selected path does not exist, is a file rather than a bundle, lacks required files, or contains a symlink at any protected boundary.
- The vault is format v1 or v2, advertises a future format, is mid-migration, or has malformed, truncated, tampered, or cross-vault metadata.
- The passphrase contains whitespace or non-ASCII characters, or unlock is attempted repeatedly after failure.
- Open and lock calls overlap, the state mutex is poisoned, or application exit occurs while unlocked.
- Receipt-chain verification fails while the vault can otherwise open.
- Aggregate retrieval fails after unlock; the workbench must not leak a partial sensitive result or raw error.
- An empty valid vault returns zeros rather than fixture values.
- The native runtime is unavailable during browser-only frontend testing.

## Requirements

### Functional Requirements

- **FR-001**: The revived application MUST originate from donor commit `50a830f3c08874e990d588291220328c7fceb13c` but be reconciled onto exact base `488560894d188f97f2365e56cfdc4853a1ad2f00` without mutating the donor branch or worktree.
- **FR-002**: The workbench MUST allow the owner to specify or select an existing Tessera vault bundle and submit a passphrase for one explicit unlock attempt.
- **FR-003**: Only the native trusted process MUST own the unlocked vault, database connection, derived encryption key, and domain operations; none may be serializable or directly reachable by the WebView.
- **FR-004**: The workbench MUST use `tessera-core` as the sole implementation of vault opening, validation, receipt verification, and aggregate domain queries.
- **FR-005**: Open MUST accept only a valid, non-symlinked, current format-v3 vault that is not in an active migration state.
- **FR-006**: Wrong passphrases, legacy or future formats, migration in progress, malformed data, tampering, and symlink violations MUST fail closed and leave the workbench locked.
- **FR-007**: Owner-visible failures MUST use a typed, bounded error contract whose code and guidance contain no owner path, passphrase, database detail, hash, receipt identifier, private metadata, stack trace, or source error text.
- **FR-008**: A successful open MUST return only lock state, vault format version, space count, pending-review count, active-session count, receipt-chain verification status and aggregate count, and bounded diagnostic status.
- **FR-009**: The overview MUST NOT return document content, filenames, titles, tags, source URLs, logical hashes, blob addresses, receipt payloads or identifiers, database rows, cryptographic material, private evaluation content, or owner filesystem paths.
- **FR-010**: Explicit lock MUST drop native unlocked state and immediately remove the live overview from the presentation layer; repeated lock MUST be safe.
- **FR-011**: Concurrent open and lock requests MUST serialize to one unambiguous state, and a second open MUST NOT replace an already unlocked vault.
- **FR-012**: Application exit MUST drop all native unlocked state without persisting recovery tokens or cached secrets.
- **FR-013**: The passphrase MUST be cleared from presentation state immediately after every invocation and MUST NOT enter logs, storage, telemetry, crash text, fixtures, generated artifacts, or error output.
- **FR-014**: Documentation MUST state that the passphrase exists transiently in the owner WebView and Tauri IPC during the explicit unlock call and that same-user memory inspection while unlocked is outside this slice's guarantee.
- **FR-015**: Native capabilities MUST be narrowly allowlisted and MUST NOT grant the WebView general filesystem, shell, SQL, database, key, or generic command access.
- **FR-016**: The live overview MUST never combine with fixture records; every other unconnected screen and mutation MUST remain visibly marked preview-only, disabled, or unavailable.
- **FR-017**: The donor's responsive shell, light and dark themes, keyboard focus, reduced-motion behavior, and coarse-pointer affordances MUST remain functional across compact, medium, desktop, and wide layouts without page-level horizontal overflow.
- **FR-018**: Tests MUST use only synthetic temporary vaults and test KDF parameters and MUST exercise success, refusal, lock lifecycle, concurrency, safe errors, least disclosure, fixture honesty, themes, focus, and responsive behavior.
- **FR-019**: The revival MUST preserve format-v3 metadata confidentiality, protected receipt verification, backup, repair, migration, portability, and Guardian's agent-facing policy boundary.
- **FR-020**: The workbench MUST NOT claim that fixture-only inbox review, lens editing, pairing, revocation, receipts, evaluation, diagnostics, backup, migration, or repair operations are connected.
- **FR-021**: Documentation and evidence MUST bind donor, base, implementation, tests, reviews, and CI to exact commits and MUST disclose known limitations without including secrets or private owner data.
- **FR-022**: Any need for broader native permissions, a persistent-format change, weakened post-#89 security, or a materially different secret-entry architecture MUST stop for owner approval.

### Key Entities

- **Native Vault Session**: Process-local, non-serializable ownership of one unlocked vault, with states locked, opening, unlocked, locking, and terminating.
- **Sanitized Overview**: The immutable least-disclosure aggregate returned after a successful open.
- **Owner-Safe Error**: A stable code plus bounded owner guidance with no underlying sensitive detail.
- **Workbench Capability**: A narrowly scoped native operation available to the owner interface.
- **Preview Capability**: A presentation-only screen or action that has no connected native operation and is labeled accordingly.

## Success Criteria

### Measurable Outcomes

- **SC-001**: All synthetic format-v3 happy-path tests unlock successfully and return exactly the allowed overview field set.
- **SC-002**: All wrong-passphrase, legacy, future, migration-in-progress, malformed, tampered, and symlink refusal cases remain locked and return only enumerated safe error codes.
- **SC-003**: Automated secret scanning reports zero occurrences of test passphrases, protected metadata sentinels, raw paths, hashes, or receipt identifiers in logs and generated artifacts.
- **SC-004**: One hundred repeated lock calls and adversarial concurrent lifecycle tests end in a defined locked or original-unlocked state with no replacement or deadlock.
- **SC-005**: Frontend behavior tests prove passphrase clearing after success and failure, overview clearing on lock, locked initial state, and fixture-only labeling.
- **SC-006**: Frontend behavior tests plus packaged-app smoke checks report no page-level horizontal overflow at compact, medium, desktop, and wide breakpoints in light and dark themes, with keyboard focus visible.
- **SC-007**: Root workspace, frontend, native boundary, ignored, Spec Kit, and packaged debug build gates pass on the same final commit.
- **SC-008**: Independent security, acceptance, and UX reviewers report no unresolved blocking findings on the exact final commit.
- **SC-009**: Exact-head macOS and Ubuntu CI pass on the pushed commit referenced by the draft pull request and evidence report.

## Assumptions

- This is an owner-local desktop interface. Agents continue to use Guardian MCP and receive no new authority.
- The owner may type or paste a vault path in the first workflow; a native chooser is optional if it can be added without broad filesystem capability.
- Transient secret presence in the owner WebView, Tauri IPC serialization, and native process memory is accepted only for the duration of the explicit unlock call and is documented as residual exposure.
- Fixture-only views are retained to preserve the donor shell and inform later bounded owner-workflow slices.
- macOS is the manual smoke-test host; CI provides macOS and Ubuntu build and behavioral evidence.
- No new GitHub issue is required for this owner-authorized slice.
