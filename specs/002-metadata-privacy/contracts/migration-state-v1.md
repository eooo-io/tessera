# Contract: Format-v3 Migration State

## Entry

- Migration requires an unlocked legacy keyslot and explicit owner
  confirmation.
- Migration is an offline upgrade: every Tessera and Guardian process and
  every open legacy-vault handle MUST be closed before entry. A pre-upgrade
  binary does not know the v3 protocol and is not a supported concurrent
  writer.
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
- Blob conversion is repeated under the final database writer boundary, before
  metadata commit, and during v3 cleanup. Any late legacy container is
  authenticated, converted, and forces a retry rather than allowing a public
  content-hash path to survive successful exit under the quiescence
  precondition. A process that ignores that precondition can recreate
  arbitrary filesystem residue after any finite scan.

## Database transition

- The source WAL is checkpointed before export. Selection then acquires an
  exclusive SQLite writer boundary, repeats active-session and complete logical
  inventory validation, and retains that boundary until the legacy authority
  is retired. A commit completed before exclusive selection makes the staged
  candidate stale and causes fail-closed retry rather than data loss. Writes
  attempted afterward by an already-open pre-upgrade handle are outside the
  supported offline migration contract.
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
  selected database commit. Post-manifest cleanup reacquires the exclusive
  legacy-database writer boundary and unlinks the retired authority before
  releasing it. No secure-deletion claim is made.

## Exit

- Success under the entry precondition leaves format v3, no migration marker,
  no legacy blob containers, no plaintext database or sidecars, and a full
  evidence summary.
- Failure returns one bounded code from the documented migration error classes
  and stable recovery guidance without
  echoing metadata, keys, passphrases, content, or unvalidated claims about
  which file is authoritative. The fixed paths and marker are inspected by the
  explicit retry path, which independently validates authority rather than
  trusting a phase printed by a failed process.
