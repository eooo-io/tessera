# Protected Receipt Container v1 Contract

## File discovery

- Durable index filename: `<receipt_id>.trc`
- Prepared filename: `.<receipt_id>.prepared`
- Legacy filename: `<receipt_id>.json`
- Paths containing separators, unexpected extensions, or ids inconsistent with
  the durable index are rejected.

## Binary layout

```text
offset  length  field
0       4       ASCII magic and version: TSR1
4       24      XChaCha20-Poly1305 nonce
28      N       ciphertext followed by 16-byte Poly1305 tag
```

The encrypted plaintext is the compact JSON encoding of one logical `Receipt`.
Authenticated additional data is the length-delimited concatenation of the
container magic and receipt id. The decrypted `receipt_id` MUST equal the id
bound into the additional data and durable index.

## Logical chain authentication

`self_hash` is lowercase hex keyed BLAKE3 over canonical logical receipt JSON
with `self_hash` cleared and with the assigned sequence and predecessor token in
place. `prev_receipt_hash` equals the preceding receipt's `self_hash`, or null
for sequence zero. Encryption and chain authentication use distinct
domain-separated keys.

## Failure contract

| Class | Examples | Required behavior |
|-------|----------|-------------------|
| Malformed | short header, unknown magic/version, impossible length, invalid JSON after successful decryption | refuse and identify malformed storage without printing payload |
| Internally inconsistent | sequence gap, predecessor mismatch, id/index mismatch, invalid exact-disclosure relation | refuse and identify consistency failure |
| Unauthenticated legacy | indexed or discovered plaintext `.json` receipt | refuse ordinary use and direct owner to explicit migration |
| Cryptographically invalid | altered nonce/ciphertext/tag, wrong derived key, keyed self-token mismatch | refuse and identify authentication failure without printing payload |

## CLI contract

- `tessera receipts migrate --yes`: explicit all-or-nothing migration of a valid
  legacy chain; prints migrated count and post-migration verification result.
- `tessera receipts verify`: verifies protected storage, keyed chain, durable
  index/head, and exact disclosures; reports a bounded classification on error.
- `tessera receipts show <id>`: decrypts and prints reviewable JSON after unlock;
  stderr warns that output is plaintext.
- `tessera receipts export <id> [--html] [--out PATH]`: writes owner-requested
  plaintext; stdout/stderr identifies the destination as plaintext.

## Compatibility

- Logical receipt schema v1 and v2 remain readable after migration.
- Vault format 1 may contain legacy `.json` receipts and cannot append protected
  receipts until migration.
- Vault format 2 stores protected `.trc` receipts. Older readers must refuse the
  newer manifest before touching receipt state.
- A complete copied vault with keyslots verifies and appends on a supported host.
