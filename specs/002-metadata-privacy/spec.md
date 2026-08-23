# Feature Specification: Locked-Vault Metadata Privacy

**Feature Branch**: `skippy/issue-50-metadata-privacy`

**Created**: 2026-08-23

**Status**: Approved for implementation

**Input**: Tessera issue #50 and the active goal to complete the v0.1 metadata-confidentiality and content-address privacy baseline.

## User Scenarios & Testing

### User Story 1 - Protect a locked vault copy (Priority: P1)

As the vault owner, I want a stolen, copied, or synchronized locked vault to conceal my filenames, spaces, tags, sensitivity, source details, conversation context, access history, errors, model registry, and content-derived identifiers.

**Why this priority**: The current bundle encrypts content but exposes enough surrounding metadata to reveal personal context and confirm guessed documents. That gap blocks an honest first release.

**Independent Test**: Populate a synthetic vault with unique sentinels for every protected metadata category, lock it, scan every file and path byte-for-byte, and confirm that no protected sentinel or guess-confirming identifier is present while the documented residual exposure remains observable.

**Acceptance Scenarios**:

1. **Given** a vault populated with synthetic protected metadata, **When** an observer scans a locked copy without owner key material, **Then** no protected sentinel appears in database files, journals, manifests, indexes, blob paths, receipt paths, staging residue, backups, or temporary artifacts.
2. **Given** an observer who knows the exact bytes of a candidate document, **When** the observer computes public content hashes and compares them with a locked vault, **Then** the observer cannot confirm whether the candidate is stored.
3. **Given** an intentionally staged inbox file, **When** the vault is locked before ingestion, **Then** Tessera reports and documents that file as plaintext owner-controlled staging rather than claiming it is protected.

---

### User Story 2 - Migrate without ambiguity or data loss (Priority: P1)

As an existing owner, I want a legacy vault upgraded deterministically without losing content, provenance, receipts, deduplication, recovery state, or portability, even if the process is interrupted.

**Why this priority**: A confidentiality upgrade is unacceptable if it creates a half-converted vault, silently drops evidence, or leaves the owner unable to restore on another supported platform.

**Independent Test**: Create a representative legacy vault, interrupt migration at each durable boundary, retry it repeatedly, and verify the same logical data, receipt chain, query results, diagnostics, backup, restore, and continued writes after recovery.

**Acceptance Scenarios**:

1. **Given** a valid legacy vault, **When** the authorized migration completes, **Then** the protected format preserves every supported logical record and encrypted content object.
2. **Given** an interruption before or after any durable migration boundary, **When** migration resumes, **Then** exactly one authoritative state is recovered without mixed-format operation.
3. **Given** malformed, truncated, tampered, unsupported, or inconsistent legacy metadata, **When** migration is attempted, **Then** it fails closed before discarding the last valid authoritative state.
4. **Given** an already migrated vault, **When** migration is requested again, **Then** it completes as a safe no-op after validation.

---

### User Story 3 - Preserve portable ownership and recovery (Priority: P2)

As the vault owner, I want protected metadata to survive complete-bundle copy, backup, restore, diagnostics, repair, and operation on macOS and Ubuntu using my existing keyslots.

**Why this priority**: Metadata confidentiality cannot trade away the repository's owner-controlled portability and recovery guarantees.

**Independent Test**: Back up a protected synthetic vault, copy the result to a new path and supported platform, unlock it with an existing keyslot, query it, verify receipts, run diagnostics and repair, and append new content and receipts.

**Acceptance Scenarios**:

1. **Given** a complete protected vault backup, **When** it is restored to a new path or supported host, **Then** the existing passphrase unlocks it and all integrity and receipt checks pass.
2. **Given** repairable derived-state damage, **When** diagnostics and owner-approved repair run after migration, **Then** source evidence and protected metadata remain authoritative and recovery produces the documented result.
3. **Given** an unsupported protected format or incorrect key, **When** open is attempted, **Then** the vault fails closed without creating a replacement database or modifying the bundle.

---

### User Story 4 - Understand the remaining limits (Priority: P2)

As the vault owner, I want documentation and diagnostics to state exactly what remains visible and which attackers are outside the v0.1 protection boundary.

**Why this priority**: A precise limitation is safer than a broad encryption claim that the implementation does not earn.

**Independent Test**: Compare the committed exposure matrix with a fresh synthetic locked-vault scan and verify that every observable path or byte class is listed, justified, and assigned an attacker consequence.

**Acceptance Scenarios**:

1. **Given** the final protected format, **When** an owner reads the threat model and exposure matrix, **Then** file count, sizes, bundle structure, intended inbox plaintext, and filesystem limitations are described without overstating protection.
2. **Given** malware or a same-user process while the vault is unlocked, **When** the documented claim boundary is reviewed, **Then** Tessera does not claim protection for readable process memory, open database handles, or owner-visible plaintext output.
3. **Given** deletion on an SSD, snapshotting filesystem, or backup provider, **When** residue risk is described, **Then** Tessera does not claim secure deletion it cannot verify.

### Edge Cases

- Empty and newly created vaults must use the protected metadata format without a legacy transition.
- A wrong passphrase, wrong metadata key, altered database page, stale journal, or swapped database from another vault must fail closed.
- Migration must handle an existing write-ahead log and shared-memory sidecar without omitting committed rows or retaining stale plaintext sidecars.
- Insufficient disk space, permission errors, process interruption, and destination collisions must preserve one recoverable authoritative database.
- Complete bundle rollback remains indistinguishable without an external trusted state and must not be described as prevented.
- Intentional inbox plaintext and owner-requested plaintext exports remain outside locked-vault confidentiality.
- File counts, ciphertext sizes, directory topology, modification times, and access patterns may remain observable where the filesystem exposes them.
- Deleted plaintext may remain recoverable through snapshots, journaling filesystems, SSD behavior, or provider retention after Tessera removes a directory entry.

## Requirements

### Functional Requirements

- **FR-001**: The system MUST maintain a committed threat model covering stolen offline copies, read-only filesystem access, malicious same-user processes, vault-write attackers, guessed-document confirmation, backup or sync providers, and forensic recovery.
- **FR-002**: The threat model MUST inventory every bundle field and filesystem path visible while locked, including database schema and journals, manifests, blobs, receipts, inbox, staging, backups, temporary paths, migration metadata, and deleted-residue boundaries.
- **FR-003**: Protected metadata MUST include filenames, titles, spaces, tags, sensitivity, timestamps, source URLs, projects, repositories, branches, sessions, pairings, errors, receipt indexes, conversation metadata, and model registries.
- **FR-004**: A locked-vault observer without owner key material MUST NOT be able to confirm guessed exact document content using a public content-derived identifier exposed by the bundle.
- **FR-005**: Content addressing MUST preserve authenticated content integrity and the documented deduplication semantics without exposing a public exact-content verifier.
- **FR-006**: The public manifest and filesystem layout MUST contain only the minimum fields and stable paths needed to identify and open a portable vault, plus the explicitly documented residual exposure.
- **FR-007**: Persistent metadata protection MUST use vault-specific, domain-separated owner key material that is never serialized in plaintext.
- **FR-008**: New vaults MUST use the protected metadata format from creation and MUST apply restrictive portable permissions where the host supports them.
- **FR-009**: Existing vaults MUST have a versioned, deterministic, non-destructive migration path that preserves the last valid authoritative state until the protected replacement is fully written and validated.
- **FR-010**: Migration MUST be restart-safe, idempotent, and fail closed, with no state in which ordinary operation can ambiguously mix legacy and protected metadata.
- **FR-011**: Malformed, truncated, tampered, cross-vault, incorrectly keyed, and unsupported metadata containers or rows MUST fail closed without silently creating an empty replacement.
- **FR-012**: New and migrated vaults MUST preserve source content integrity, promised deduplication, provenance, lenses, quarantine, sessions, protected receipts, receipt-chain continuation, backup, restore, diagnostics, and repair behavior.
- **FR-013**: A complete bundle MUST remain portable between supported macOS and Ubuntu hosts without machine-bound secrets or an external service.
- **FR-014**: An automated scanner MUST populate only synthetic data, inspect every locked-vault path and file, and report protected sentinel matches and allowed structural exposure without reading private owner content.
- **FR-015**: Inbox and temporary processing MUST use restrictive permissions, remove abandoned working copies during bounded recovery, and document the limits of deletion on filesystems, snapshots, SSDs, and providers.
- **FR-016**: Intentional plaintext staging and explicit owner exports MUST remain clearly distinguishable from protected at-rest storage.
- **FR-017**: The final evidence MUST measure storage overhead, legacy migration time, protected query behavior, backup and restore, diagnostics, and repair under controlled synthetic fixtures.
- **FR-018**: Documentation MUST state the exact residual locked-vault exposure and MUST NOT claim protection against unlocked process inspection, owner-visible output, whole-bundle rollback, traffic analysis, or guaranteed forensic deletion.
- **FR-019**: The implementation MUST retain open, reviewable, and documented formats and MUST NOT require proprietary services or machine identity for ordinary recovery.
- **FR-020**: Any format transition that would require destructive conversion, loss of repairability, material portability regression, or owner acceptance of exact-content confirmation MUST stop for explicit owner approval.

### Key Entities

- **Protected Metadata Store**: The portable, owner-keyed persistent store containing vault records, indexes, and model or conversation metadata.
- **Opaque Content Address**: A vault-specific stable lookup identifier that supports authenticated reads and promised deduplication without serving as a public exact-content verifier.
- **Public Manifest**: The minimal locked-visible description needed to recognize the bundle format and unlock it on another supported host.
- **Migration State**: The small, non-sensitive durable facts and staged files needed to identify the authoritative legacy or protected database during interruption recovery.
- **Exposure Matrix**: The exhaustive mapping from every bundle path or field to protected status, residual visibility, affected threat actors, and validation evidence.
- **Synthetic Sentinel Inventory**: Unique non-private markers covering every protected metadata category for automated locked-vault scanning.

## Success Criteria

### Measurable Outcomes

- **SC-001**: A byte-and-path scan of a locked synthetic vault containing a unique sentinel for every protected metadata category reports zero protected sentinel occurrences outside intentional inbox plaintext fixtures.
- **SC-002**: At least 100 guessed-document confirmation attempts using exact candidate bytes and public hashes produce no matchable identifier in the locked bundle.
- **SC-003**: Fault injection at every durable migration boundary recovers 100 percent of committed logical records and selects exactly one authoritative database state.
- **SC-004**: Successful and repeated migrations produce equivalent logical inventories, receipt chains, query results, and diagnostics.
- **SC-005**: Backup, copy, restore, unlock, query, receipt verification, receipt continuation, diagnostics, and applicable repair tests pass for new and migrated vaults.
- **SC-006**: Exact-head CI passes on macOS and Ubuntu for the same pushed commit used by the evidence report.
- **SC-007**: The evidence report records controlled storage, migration, query, backup, restore, diagnostic, and repair measurements, including variance when repeated results differ materially.
- **SC-008**: Every observable locked-vault path, filename pattern, size class, timestamp source, and intentional plaintext boundary appears in the committed exposure matrix.
- **SC-009**: The full formatting, strict lint, build, targeted security and migration tests, workspace tests, ignored tests, and specification consistency gates pass on the final committed state.

## Assumptions

- The owner-held vault data key remains the root secret and existing keyslots remain the portable unlock mechanism.
- The v0.1 contract protects a locked bundle and its backups. It does not protect plaintext intentionally placed in the inbox, explicitly exported by the owner, or available to a process while unlocked.
- Stable opaque identifiers, row counts, ciphertext lengths, bundle topology, file modification times, and access patterns may remain visible only where documented and justified in the exposure matrix.
- Migration may require temporary additional disk capacity up to the documented bound, but must preserve the legacy authoritative database until the protected replacement validates.
- Secure deletion cannot be guaranteed across filesystems, SSD controllers, snapshots, and backup providers; Tessera minimizes newly created plaintext copies and removes directory entries when safe.
- The feature may change the bundle format while keeping the format open, self-contained, and portable.

## Non-Goals

- Protection against malware reading unlocked process memory, open database handles, owner-visible terminal output, or explicit plaintext exports.
- External rollback detection, public attestations, remote key custody, or network services.
- Redesign of Guardian, MCP, OAuth, lenses, retrieval, conversation ingestion, or receipt semantics beyond their stored representation.
- Private-corpus evaluation, release publication, unrelated hardening issues, tagging, or merging.
- Claims of guaranteed secure deletion or invisibility from filesystem and provider traffic analysis.
- A proprietary container or machine-bound format.
