# Data Model: Protected Receipt Baseline

## Logical Receipt

The existing `Receipt` value remains the owner-visible audit record.

- Identity: `receipt_id`
- Order: `seq`
- Link: `prev_receipt_hash`
- Authentication token: `self_hash`
- Payload: session, agent, lens, purpose, queries, exact disclosures, summary,
  rate-limit events
- Schema: legacy v1 or exact-disclosure v2

For protected chains, `prev_receipt_hash` and `self_hash` contain keyed
authentication tokens rather than public unkeyed content hashes. The JSON shape
and 64-lowercase-hex representation stay compatible.

## Protected Receipt Container v1

- Magic/version: fixed `TSR1` prefix
- Nonce: one random 24-byte value per write
- Ciphertext: authenticated encryption of the complete canonical logical
  receipt JSON
- Authentication context: container version plus receipt id from the durable
  index/filename
- Filename: `<receipt_id>.trc`

The container reveals file existence and approximate payload size. It does not
reveal receipt fields without the unlocked vault DEK-derived encryption key.

## Audit Key Material

- Input authority: unlocked 32-byte vault DEK
- Encryption domain: `tessera receipt encryption key v1`
- Authentication domain: `tessera receipt authentication key v1`
- Lifecycle: derived on demand, zeroized when dropped, never serialized
- Rotation: passphrase/keyslot changes retain the same DEK and do not rewrite
  receipts; full DEK rotation is unsupported in v0.1

## Receipt Chain State

Existing SQLite rows remain the concurrency and recovery authority:

- `receipts_index`: receipt id, sequence, keyed predecessor token, keyed self
  token, protected filename, commit time
- `receipt_chain_state`: next sequence, keyed head token, update time

These fields remain plaintext metadata. Their tokens are keyed and cannot be
recomputed without owner-held audit key material, but count, order, filenames,
and timing remain visible under issue #50's boundary.

## Migration State Transitions

```text
legacy verified
  -> protected replacements prepared and synced
  -> keyed index/head transaction committed
  -> prepared replacements renamed to final `.trc`
  -> legacy `.json` files deleted
  -> manifest advanced to vault format 2
  -> protected chain verified
```

Before the transaction commits, legacy files and index remain authoritative.
After commit, protected filenames in the index are authoritative and recovery
finishes missing renames before deleting legacy files. A malformed or invalid
legacy chain never enters the transition.

## Verification Results

- `valid`: protected container decrypts, keyed chain and index agree, exact
  disclosure evidence verifies
- `malformed`: storage header, length, version, or logical encoding is invalid
- `internally_inconsistent`: ids, sequence, predecessor, directory/index, or
  disclosure relations disagree
- `unauthenticated_legacy`: plaintext v1/v2 record requires explicit migration
- `cryptographically_invalid`: authenticated decryption or keyed logical token
  check fails
