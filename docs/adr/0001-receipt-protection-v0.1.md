# ADR-0001: v0.1 Receipt Confidentiality and Authenticity

- **Status**: Accepted for local implementation
- **Date**: 2026-08-20
- **Issue**: [#39](https://github.com/eooo-io/tessera/issues/39)
- **Spec**: [`specs/001-receipt-protection/spec.md`](../../specs/001-receipt-protection/spec.md)

## Context

Tessera logical receipt v2 binds a live session, effective lens, retrieval
model, exact source version and range, and the bytes disclosed. Finalization is
transactional and concurrency-safe. Those receipts are nevertheless stored as
plaintext JSON, and their chain uses an unkeyed BLAKE3 content hash.

The current chain detects accidental damage and partial editing. It does not
protect sensitive receipt fields from an offline reader, and a writer can
regenerate the whole chain after changing its contents. Calling that mechanism
immutable, authentic, proof-grade, signed, or non-repudiable would be false.

## Assets

Protected receipt content includes:

- query text and failure detail;
- artifact titles, ids, source versions, ranges, and content hashes;
- agent, pairing, session, lens, purpose, and policy snapshots;
- timestamps, access patterns, retrieval scores, model identity, and summaries;
- exact disclosure evidence and rate-limit events.

The vault DEK and keys derived from it are secret authority. Receipt ids,
sequence, opaque filenames, ciphertext lengths, keyed chain tokens, commit
times, and the SQLite receipt index remain observable metadata in this slice.

## Threat Model

| Attacker | Protected | Not protected |
|----------|-----------|---------------|
| Offline reader of a locked vault copy | Receipt payload confidentiality; inability to compute valid new chain tokens | File count, size, filenames, SQLite index metadata, backup history |
| Read-only same-user process without the unlocked DEK | Same as offline reader when OS permissions hold | Observation of other plaintext vault metadata tracked by #50 |
| Vault writer without the unlocked DEK | Editing, middle insertion/deletion, reordering, and regenerated logical chains fail authentication | Destruction, denial of service, and whole-bundle rollback/truncation without a separately trusted head |
| Backup or sync provider | Receipt payload confidentiality | Object sizes, timing, paths, version history, deletion history |
| Process with the unlocked DEK or derived audit keys | No confidentiality or authenticity guarantee | The process can read receipts and forge future local receipt records |
| Compromised owner export destination | No at-rest vault guarantee applies to the exported plaintext | Owner must protect, redact, or delete the export |

Tessera does not claim that a receipt proves an agent obeyed its declared
purpose, deleted disclosed context, or acted under a publicly verifiable
identity. It does not claim non-repudiation.

## Decision

### Protect the complete receipt payload

Finalized receipts use a dedicated binary protected container rather than
plaintext JSON or the content-addressed blob store. Container v1 is:

```text
TSR1 | 24-byte random nonce | XChaCha20-Poly1305 ciphertext and tag
```

The encrypted plaintext is compact logical receipt JSON. Authenticated
additional data binds the `TSR1` format marker and receipt id. The decrypted id
must equal the durable index and filename id. Files use the `.trc` extension.

Whole-payload encryption avoids a field allowlist that could expose future
receipt fields. The existing blob store is not reused because its filenames are
unkeyed plaintext content hashes and its deduplication lifecycle does not match
receipt-chain recovery.

### Separate encryption and chain-authentication keys

Tessera derives two 32-byte keys from the unlocked vault DEK using distinct
BLAKE3 derive-key contexts:

- `tessera receipt encryption key v1`
- `tessera receipt authentication key v1`

The derived keys are never serialized and are zeroized after use. Receipt files
use the encryption key with XChaCha20-Poly1305. `self_hash` becomes keyed BLAKE3
over canonical logical receipt JSON with `self_hash` cleared after final
sequence and predecessor assignment. `prev_receipt_hash` links to the prior
keyed token.

This is owner-keyed local authenticity. It is not a digital signature. Any
process holding the unlocked DEK can derive both keys and forge records.

### Keep logical schemas separate from protected storage

Logical receipt schema v1 and v2 remain the review/export contract. The storage
container has its own version. The vault format advances from 1 to 2 so older
readers refuse protected receipt storage instead of silently ignoring it or
attempting an incompatible append.

### Require explicit complete-chain migration

Legacy plaintext receipt chains are classified as unauthenticated. Ordinary
list, show, export, verify, and finalization refuse them until the owner runs:

```text
tessera receipts migrate --yes
```

Migration verifies the entire legacy chain before replacing anything, prepares
and syncs every protected replacement, commits the keyed index and head in one
SQLite transaction, completes deterministic renames, deletes plaintext legacy
files, advances the manifest to format 2, and verifies the resulting chain.

Before the transaction commits, legacy files remain authoritative. After
commit, protected filenames in the index are authoritative and recovery
finishes missing renames before deleting legacy files. Re-running migration is
idempotent.

### Make plaintext export explicit

Owner `show` and `export` operations decrypt only after unlock. Both JSON and
standalone HTML remain available. The CLI states that output is plaintext and
outside Tessera's protected at-rest boundary. Tessera does not create automatic
decrypted reports.

## Verification Semantics

The owner can distinguish:

- **malformed**: invalid header, unsupported container, truncated bytes, or
  invalid logical encoding after successful authentication;
- **internally inconsistent**: id, sequence, link, directory/index, policy, or
  exact-disclosure relationships disagree;
- **unauthenticated legacy**: a plaintext receipt chain requires migration;
- **cryptographically invalid**: authenticated decryption or a keyed logical
  chain token fails.

Error output must not include decrypted receipt content, derived keys, or
secret-bearing raw bytes.

## Operational Consequences

### Backup and restore

Consistency-barrier backup continues to copy the complete bundle. Restore must
open with an owner keyslot, finish committed prepared-file recovery, and verify
the protected chain. A partial bundle remains fatal.

### Cross-host portability

The DEK is wrapped by portable keyslots, not machine identity. Copying the
complete vault, keyslots, protected receipts, and database to a supported host
preserves decryption and authentication. The destination can continue the chain
after unlock.

### Key loss and rotation

Loss of every passphrase/keyslot means protected receipts cannot be decrypted
or authenticated. Tessera cannot repair or bypass that loss.

Adding or removing a passphrase keyslot does not change the DEK and does not
rewrite receipts. Full DEK rotation and bulk re-encryption are not implemented
in v0.1 and must not be implied. A future implementation must migrate blobs and
receipts together under a separately reviewed recovery design.

### Retention

No automatic receipt deletion or owner-selectable detail profile is introduced.
The owner controls retention through whole-vault backup and explicit file/data
management. Deleting individual receipt files breaks verification and is not a
supported pruning operation.

## Alternatives Rejected for v0.1

- **Selected-field encryption**: too easy for new sensitive fields to escape;
  creates partial-decryption and listing complexity.
- **Ordinary encrypted blobs**: plaintext content addresses permit confirmation
  attacks and do not match receipt identity/recovery semantics.
- **Ed25519 signatures**: public verification is not a v0.1 requirement and the
  signing-key lifecycle, trust distribution, and rotation surface add material
  complexity without providing confidentiality.
- **External chain-head anchoring**: would add an online dependency and no
  approved trusted anchor consumer currently exists.
- **SQLCipher or broad column encryption**: belongs to #50's larger metadata
  threat model and migration boundary.
- **Blockchain**: adds no relevant local confidentiality and is operationally
  unserious for this product boundary.

## Consequences

Positive consequences:

- sensitive receipt payloads are confidential in a locked vault;
- unauthorized writers cannot regenerate a valid protected chain without the
  owner-held audit key material;
- no new runtime dependency or external service is required;
- logical receipt exports and exact disclosure evidence remain compatible;
- migration and recovery have one explicit authority boundary.

Costs and residual risks:

- vault format 2 is a breaking storage boundary for older binaries;
- receipt count, size, timing, filenames, and SQLite metadata remain visible;
- unlocked process compromise defeats both confidentiality and authenticity;
- whole-bundle rollback remains undetectable without an external trusted head;
- owner plaintext exports require separate handling and protection.
