# Contract: Format-v3 Migration State

## Entry

- Migration requires an unlocked legacy keyslot and explicit owner
  confirmation.
- It refuses unsupported manifest versions, active Guardian sessions,
  insufficiently understood staged files, and fatal source diagnostics.
- It creates the fixed marker atomically with owner-only permissions before
  moving any blob or database path.

## Blob transition

- Every legacy blob is authenticated against its legacy logical hash before a
  v2 destination is accepted.
- The destination is written, synced, reopened, decrypted, and hash-verified
  before the legacy source is removed.
- Resume accepts a valid source-only, valid destination-only, or matching
  source-and-destination state. Any other state fails closed.
- Orphaned authenticated blobs are converted and remain visible to diagnostics.

## Database transition

- The source WAL is checkpointed under an exclusive migration boundary.
- The protected staged database is a complete logical export of the source,
  including schema, triggers, virtual tables, migration ledger, and data.
- Source and staged inventories, full integrity checks, foreign-key checks, and required
  metadata keys MUST agree before selection.
- Selection uses fixed same-directory paths and synced renames.
- The public manifest advances to v3 only after the selected database reopens
  with the derived key and the complete protected blob inventory validates.

## Recovery

- The marker phase is a hint, never sole authority.
- Recovery validates all files that a phase claims before continuing.
- A missing last-authoritative source plus an invalid replacement is fatal and
  MUST NOT be repaired by creating an empty database or fabricating rows.
- Repeating migration after completion validates v3 and returns a no-op result.
- Cleanup removes retired plaintext directory entries only after manifest and
  selected database commit. No secure-deletion claim is made.

## Exit

- Success leaves format v3, no migration marker, no legacy blob containers,
  no plaintext database or sidecars, and a full evidence summary.
- Failure reports the validated phase and retained authoritative state without
  echoing metadata, keys, passphrases, or content.
