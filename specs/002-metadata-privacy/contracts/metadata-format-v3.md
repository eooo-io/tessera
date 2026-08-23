# Contract: Metadata Format v3

## Open contract

- A format-v3 manifest MUST be read before opening the database.
- The vault keyslot MUST unlock before a database connection is keyed.
- The database key MUST be installed before the first database read.
- A successful key installation MUST be proven by reading and validating the
  schema before migrations or domain queries execute.
- Wrong key, plaintext database, unsupported format, malformed page, and
  truncated database MUST produce distinct bounded errors where the underlying
  library permits, and all MUST fail closed.
- Every connection, including Guardian siblings, backup barriers, diagnostics,
  and destination snapshots, MUST use the same domain-separated database key.
- File-backed SQLite temporary storage MUST be disabled for protected metadata
  queries.

## Blob contract

- `put` MUST return the logical plaintext BLAKE3 hash and store one v2 container
  at its keyed opaque address.
- Repeating `put` with identical bytes in the same vault MUST not create a
  second blob.
- The same bytes in two independently keyed vaults MUST produce different
  locked-visible paths.
- `get`, `exists`, and `delete` MUST require the unlocked vault key and logical
  hash rather than deriving a public path from the hash alone.
- A container moved to another opaque address, copied from another vault,
  tampered, truncated, or assigned an unsupported magic/version MUST fail.
- `get` MUST recompute and compare the logical plaintext hash after successful
  authenticated decryption.

## Manifest contract

- The v3 public manifest MUST omit creation time and embedding model registry.
- Public fields MUST be limited to portable pre-unlock interpretation.
- Unknown private legacy fields MUST be preserved inside protected metadata,
  not silently discarded or re-exposed.

## Residual exposure contract

The implementation MUST treat anything outside the documented residual
exposure budget in `research.md` and the threat model as a defect. Passing
encryption tests alone is insufficient if a protected sentinel appears in a
path, manifest, database sidecar, staging file, backup, or interrupted residue.
