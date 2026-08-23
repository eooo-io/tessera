# Data Model: Locked-Vault Metadata Privacy

## Cryptographic domains

| Capability | Root | Derivation context | Persistence |
|---|---|---|---|
| Blob payload encryption v2 | vault DEK | `tessera blob encryption key v2` | never serialized |
| Blob opaque addressing | vault DEK | `tessera blob address key v1` | never serialized |
| Database page encryption | vault DEK | `tessera database encryption key v1` | never serialized |
| Receipt payload encryption | vault DEK | `tessera receipt encryption key v1` | never serialized |
| Receipt-chain authentication | vault DEK | `tessera receipt authentication key v1` | never serialized |

Every derived key is 256 bits, created on demand, and zeroized on drop. A key
from one domain must not be accepted in another domain. Legacy blob container
v1 decryption uses the direct DEK only inside the explicit migration reader;
all newly written TSB2 payloads use the v2 domain.

## Logical content identity

`BlobHash` remains the lowercase 64-character BLAKE3 hash of plaintext. It is
stored only inside the protected database and protected receipt payloads. It
continues to define content integrity, vault-wide deduplication, provenance
relationships, and exact disclosure evidence.

## Opaque blob address

`OpaqueBlobAddress` is the lowercase 64-character keyed BLAKE3 token over the
logical content hash under the vault-specific blob-address key. It determines
the two-level path `blobs/<first-two>/<full-token>` and is bound into the blob
container authentication data. It is stable within one vault, differs across
vaults, and cannot be computed from guessed content without the vault key.

## Blob container v2

Fields:

1. fixed magic and version `TSB2`;
2. random 24-byte XChaCha20-Poly1305 nonce;
3. encrypted content plus authentication tag.

Authentication data binds the magic/version and complete opaque address.
After decryption, the implementation recomputes the logical BLAKE3 hash and
requires it to equal the protected database or receipt reference supplied by
the caller.

## Protected metadata database

The existing SQLite schema, indexes, vectors, and migration ledger remain the
logical data model. Format v3 encrypts every database and journal page under
the derived database key. Connection initialization order is:

1. open the expected file without performing a query;
2. install the raw database key;
3. perform a read that proves the key and database format;
4. require in-memory temporary storage;
5. configure WAL and foreign keys;
6. apply pending schema migrations transactionally.

An incorrect key, plaintext file at a format-v3 path, malformed header,
truncated page, or authentication failure is a fatal open error. It must never
fall through to creation of an empty database.

## Encrypted vault metadata

Migration 0022 adds:

```text
vault_metadata
  key        TEXT PRIMARY KEY
  value_json TEXT NOT NULL
  updated_at TEXT NOT NULL
```

Initial keys:

- `created_at`: the original vault creation timestamp;
- `embedding_models`: the ordered model registry previously in the manifest;
- `manifest_extensions`: preserved unknown legacy manifest fields.

Unknown keys are preserved. Values are ordinary JSON inside encrypted database
pages and are never copied into the public manifest unless a future format
specification explicitly makes them public.

## Public manifest v3

The public JSON object contains:

- `format_version: 3`;
- `crypto`: the portable keyslot/default cipher parameters required by the
  format contract;
- forward-compatible public fields explicitly defined by a later compatible
  format.

Creation time, model registry, and private legacy extensions are absent.

## Migration state

The fixed path `.metadata-migration-v3` contains a version and one closed phase
enum only:

- `started`;
- `blobs_protected`;
- `database_prepared`;
- `database_selected`;
- `manifest_committed`.

The marker contains no path supplied by a user, hash, key, metadata value, or
private corpus content. Durable phase advancement occurs only after every file
owned by the prior phase is synced. Recovery distrusts the marker and validates
the expected fixed files before advancing.

Fixed staged database paths:

- `.vault.db.v3.prepared`: complete protected replacement not yet selected;
- `.vault.db.v2.retired`: last plaintext authoritative database retained until
  the protected database and manifest validate.

Ordinary open refuses any in-progress marker. The explicit migration command
resumes or fails closed from the validated state matrix.

## State invariants

- Format v1/v2 plus no marker means the legacy vault is authoritative and
  requires explicit migration.
- A marker means only migration recovery may operate on the bundle.
- Format v3 requires a keyed valid `vault.db`, only v2 blob containers at keyed
  paths, and no authoritative plaintext database.
- The retired plaintext database is never removed before the protected
  database passes full integrity check, schema inventory, logical inventory, and key
  reopen validation.
- A format-v3 vault with retired residue completes bounded cleanup before
  ordinary operation or fails closed.
- Blob conversion writes and authenticates the v2 destination before removing
  the v1 source.
- Repeating any completed migration phase does not alter logical content.
