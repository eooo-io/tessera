# Feature Specification: Protected Receipt Baseline

**Feature Branch**: `skippy/issue-39-receipt-protection`

**Created**: 2026-08-20

**Status**: Approved for implementation

**Input**: Tessera issue #39 and the active goal to complete the v0.1 receipt
confidentiality and authenticity baseline.

## User Scenarios & Testing

### User Story 1 - Protect finalized receipts (Priority: P1)

As the vault owner, I want finalized access receipts to conceal queries,
artifact titles, purposes, agent identifiers, and disclosure details while the
vault is locked, and I want unauthorized changes to be detected when I verify
the vault.

**Why this priority**: Receipts currently expose sensitive context in plaintext
and an unauthorized vault writer can regenerate the existing unkeyed chain.
This blocks the first stable release.

**Independent Test**: Finalize multiple receipts containing unique protected
sentinels, lock and scan the entire bundle, then unlock and verify the chain.
The sentinels are absent from the locked bundle and every receipt verifies.

**Acceptance Scenarios**:

1. **Given** an unlocked vault and a completed disclosure session, **When** the
   receipt is finalized, **Then** its protected fields are not present as
   plaintext anywhere in the locked bundle.
2. **Given** a valid protected receipt chain, **When** an attacker edits a
   receipt without owner-held audit key material, **Then** verification reports
   a cryptographic authentication failure.
3. **Given** a valid protected chain, **When** a receipt is inserted, deleted
   from the middle, reordered, or regenerated without audit key material,
   **Then** verification fails without disclosing protected content.

---

### User Story 2 - Migrate and recover existing receipts (Priority: P1)

As an existing vault owner, I want legacy plaintext receipts migrated without
changing their meaning, order, disclosure evidence, or receipt identifiers, and
I want an interrupted migration to recover deterministically.

**Why this priority**: A new protected format is not a real confidentiality
control if existing receipts remain exposed or if migration can corrupt the
audit trail.

**Independent Test**: Build a vault with legacy receipt files, interrupt the
migration at each durable boundary, reopen it, and confirm that the same logical
receipts and chain order are recovered in protected storage.

**Acceptance Scenarios**:

1. **Given** a valid legacy receipt chain, **When** the owner explicitly runs
   the protected-receipt migration, **Then** all receipts become protected while
   preserving their identifiers, sequence, content, and disclosure verification.
2. **Given** an invalid or malformed legacy receipt, **When** migration begins,
   **Then** migration stops before replacing that receipt and reports the
   failure category.
3. **Given** an interruption during migration, **When** the owner reopens the
   vault, **Then** recovery completes or rolls back deterministically without a
   mixed ambiguous chain.

---

### User Story 3 - Verify and export honestly (Priority: P2)

As the vault owner, I want verification to tell me whether a receipt is
malformed, internally inconsistent, legacy and unauthenticated, or
cryptographically invalid, and I want reviewable export to be an explicit
plaintext action.

**Why this priority**: Honest error categories and explicit export prevent
stronger claims than the implementation earns and avoid accidental plaintext
copies.

**Independent Test**: Present one fixture for each failure class and confirm
the owner receives a distinct bounded result. Export a valid receipt and confirm
the output is complete, reviewable, and accompanied by a plaintext warning.

**Acceptance Scenarios**:

1. **Given** malformed, inconsistent, unauthenticated legacy, and
   cryptographically invalid fixtures, **When** the owner verifies them,
   **Then** each produces a distinct actionable classification.
2. **Given** a protected receipt, **When** the owner explicitly exports it,
   **Then** the complete reviewable form is written only to the requested output
   and the command states that the export is plaintext.
3. **Given** a copied complete vault bundle on another supported host, **When**
   the owner unlocks and verifies it with an existing keyslot, **Then** receipt
   verification succeeds and the chain can continue.

### Edge Cases

- Empty receipt directories and vaults with no finalized receipts verify
  successfully.
- Legacy version 1 and version 2 receipts retain their historical content
  semantics after protection.
- Wrong passphrases and locked vault handles cannot decrypt or authenticate
  receipts.
- Truncated headers, noncanonical lengths, altered nonces, altered ciphertext,
  unknown container versions, and mismatched receipt identifiers fail closed.
- A receipt prepared before a process interruption is never treated as
  committed unless the durable index identifies it.
- Removing the final receipt and rolling back the plaintext database head is a
  residual rollback risk unless an external head is separately trusted.

## Requirements

### Functional Requirements

- **FR-001**: Finalized receipt payloads MUST be confidential while the vault is
  locked, including queries, titles, purposes, identities, policy snapshots,
  timestamps inside the receipt, and disclosure details.
- **FR-002**: Every newly finalized receipt MUST carry owner-keyed
  authentication that covers its complete logical content and predecessor
  relationship.
- **FR-003**: Audit encryption and authentication MUST use distinct,
  domain-separated owner-held key material.
- **FR-004**: Verification MUST authenticate every protected receipt before
  parsing or exposing its protected payload.
- **FR-005**: Verification MUST distinguish malformed storage, internal chain
  inconsistency, legacy unauthenticated records, and cryptographic
  authentication failure.
- **FR-006**: Legacy receipt migration MUST be idempotent, crash-safe, and
  preserve receipt identifiers, sequence, content, and exact disclosure
  evidence.
- **FR-007**: Migration MUST verify the complete legacy chain before replacing
  any committed plaintext receipt.
- **FR-008**: Listing, showing, disclosure verification, backup, restore, and
  recovery MUST continue to operate on protected receipts after unlock.
- **FR-009**: Owner export MUST require an explicit command, produce a complete
  reviewable JSON or HTML representation, and warn that the output is plaintext.
- **FR-010**: A complete copied vault MUST remain verifiable and appendable on
  another supported host using an existing owner keyslot.
- **FR-011**: Passphrase keyslot changes that retain the same vault data key MUST
  not require receipt rewriting. Actual data-key rotation and re-encryption MUST
  be documented as unsupported in v0.1 unless implemented by this feature.
- **FR-012**: The system MUST NOT require an external service, blockchain, or
  network trust anchor for ordinary local operation.
- **FR-013**: Documentation MUST state remaining plaintext metadata and attacker
  capabilities, including process-memory compromise and whole-bundle rollback.
- **FR-014**: Product and operator text MUST NOT describe the v0.1 receipt
  mechanism as immutable, non-repudiable, or publicly verifiable.

### Key Entities

- **Logical Receipt**: The existing versioned record of one access session,
  including exact disclosures, effective policy, sequence, and predecessor.
- **Protected Receipt Container**: A versioned opaque file carrying the
  authenticated encrypted representation of one logical receipt.
- **Audit Key Material**: Owner-held, vault-specific encryption and
  authentication capabilities derived for receipt protection.
- **Receipt Chain State**: The durable ordering and head metadata used for
  concurrency, recovery, and consistency checks.
- **Plaintext Export**: An owner-requested review artifact outside the vault's
  protected-storage guarantees.

## Success Criteria

### Measurable Outcomes

- **SC-001**: A byte scan of a locked test vault containing at least 20 unique
  protected sentinels finds zero sentinel occurrences anywhere in the bundle.
- **SC-002**: All required edit, insertion, middle deletion, reordering, and
  keyless full-chain-regeneration adversarial cases are rejected.
- **SC-003**: Migration fault tests at every supported interruption boundary
  recover 100 percent of committed receipts with unchanged identifiers and
  logical content.
- **SC-004**: Fixtures for malformed, internally inconsistent, unauthenticated,
  and cryptographically invalid records produce four distinguishable results.
- **SC-005**: A copied complete vault verifies every receipt and successfully
  finalizes and verifies one additional receipt on the destination host.
- **SC-006**: Owner JSON and HTML exports contain all expected receipt fields and
  every export invocation identifies the output as plaintext.
- **SC-007**: The full repository formatting, strict lint, workspace test, and
  applicable fault-test gates pass after the final implementation.

## Assumptions

- The v0.1 trust anchor is the unlocked local vault and its owner-held key
  material. Public third-party verification and non-repudiation are out of
  scope.
- A process that can read unlocked process memory can decrypt receipts and can
  forge future local authentication records. That attacker is explicitly not
  protected against by this baseline.
- Whole-bundle truncation or rollback cannot be proven without a separately
  trusted external head. External anchoring remains optional future work.
- Receipt count, opaque filenames, file sizes, and the existing SQLite receipt
  index may remain observable until coordinated metadata hardening in issue #50.
- Retention policy remains owner-managed backup and deletion policy; this slice
  does not add automatic expiration or deletion.
- Existing receipt schema versions remain the logical export contract. The
  protected storage container is versioned separately.

## Non-Goals

- Public signing identity, certificates, hardware-backed attestations, or
  exportable public verification keys.
- External append-only anchoring, transparency logs, or blockchain storage.
- Protection against malware or an attacker reading an unlocked process.
- Automatic receipt retention, redaction profiles, or silent plaintext export.
- Broad database metadata encryption or keyed content addressing tracked by
  issue #50.
