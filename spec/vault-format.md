# Tessera Vault Bundle Format

**Format version: 1** (see `FORMAT_VERSION` in `tessera-core/src/vault/manifest.rs`)

> **Policy:** this document MUST be updated in the same commit as any code
> change that affects the on-disk format. A reader implementing from this
> document alone must be able to interpret a bundle.

## Overview

A vault is a plain directory (conventionally `<Name>.tessera/`). No container
file, no magic bytes, no absolute paths inside — the bundle must survive
`rsync`, Syncthing, external drives, and copying between machines and
operating systems unchanged.

```
MyVault.tessera/
├── tessera.json     # manifest — the portability contract (this doc, §2)
├── vault.db         # SQLite database, WAL mode (§3)
├── keyslot.bin      # key slots wrapping the DEK (§4)
├── blobs/           # content-addressed encrypted blob store (§5)
├── receipts/        # finalized, hash-chained access receipts (§6)
└── inbox/           # plaintext staging for content not yet ingested (§7)
```

Invariants that apply to the whole bundle:

- **I1 — Self-contained:** no file inside the bundle references data outside
  it, and no path stored inside the bundle is absolute.
- **I2 — Copy-is-move:** copying the directory to a new location/host yields
  a fully functional vault; nothing is keyed to machine identity. (The macOS
  Keychain may cache the DEK for convenience, but the passphrase path in
  `keyslot.bin` always works.)
- **I3 — Encrypted at rest:** all user content — originals and derived text,
  captions, summaries, thumbnails — lives in `blobs/` encrypted. Plaintext
  content appears only in `inbox/` (pre-ingestion) and, as a documented v1
  limitation, in `vault.db` *metadata* (filenames, tags, offsets — not
  content). Full metadata encryption is future work.

## 2. `tessera.json` — the manifest

UTF-8 JSON object, pretty-printed, trailing newline. Written by
`VaultManifest::save`, read by `VaultManifest::load`.

| Field | Type | Meaning |
|---|---|---|
| `format_version` | integer ≥ 1 | Bundle format version. Readers MUST refuse to open a bundle whose version is greater than the version they implement. |
| `created_at` | RFC 3339 timestamp | Vault creation time (UTC). |
| `crypto` | object | KDF and cipher parameters, see below. |
| `embedding_models` | array | Registry of embedding models with vectors in this vault. May be empty. |

`crypto` object:

| Field | Type | v1 value |
|---|---|---|
| `kdf` | string | `"argon2id"` |
| `kdf_m_cost_kib` | integer | `65536` (64 MiB) |
| `kdf_t_cost` | integer | `3` |
| `kdf_p_cost` | integer | `4` |
| `cipher` | string | `"xchacha20poly1305"` |

`embedding_models[]` entry:

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Model name, e.g. `"all-MiniLM-L6-v2"`. |
| `version` | string | Implementation/version identifier. |
| `dimensions` | integer | Vector dimensionality. A reader that cannot embed queries with a registered model MUST NOT silently mix vector spaces; it should offer re-embedding. |

**Forward compatibility:** unknown fields — top-level or inside `crypto` —
MUST be preserved on read-modify-write (implemented via captured extra
fields). A version-1 reader may open a bundle with version-1 format and
additional unknown fields; it MUST NOT drop them.

## 3. `vault.db`

SQLite database in WAL mode with foreign keys enforced. Schema is defined by
ordered migrations in `tessera-core/src/db/migrations/` (never edited once
shipped — append-only) and recorded in a `schema_migrations` table
(`version`, `name`, `applied_at`). Readers open with
`open_database`, which applies pending migrations transactionally.

Migration 0001 establishes: `spaces`, `artifacts` (with `sensitivity` and
the quarantine `state` column — `pending`/`live`/`archived`, CHECK-enforced,
default `pending`), `artifact_versions` (→ `blob_hash` into §5),
`tags`/`artifact_tags`, and `provenance` (derived blob → source version,
tool, tool version, `local`/`cloud` locality). Migration 0002 adds
`derived_text` (extraction outputs: one row per version × extractor ×
extractor-version, enabling skip-if-unchanged and re-run-on-upgrade).
Later milestones append chunks, embeddings (sqlite-vec virtual table),
lenses, sessions, and the receipts index. The database never contains
plaintext artifact content.

## 4. `keyslot.bin`

LUKS-style list of key slots. Each slot wraps the same randomly generated
256-bit Data Encryption Key (DEK) with XChaCha20-Poly1305 under a slot key
derived from a passphrase via Argon2id. KDF parameters are stored **per
slot** (the manifest's `crypto` object provides the defaults used when
creating new slots), so e.g. a recovery key may use different costs.
Adding/removing an unlock method touches only this file — never the blobs.
Removing the final slot is forbidden. Writes are atomic (temp file +
rename).

Binary layout (all integers little-endian):

```
offset  size  field
0       4     magic: ASCII "TSK1"
4       1     slot_count: u8
5       100×n slots, each:
        +0    4   kdf_m_cost_kib: u32
        +4    4   kdf_t_cost: u32
        +8    4   kdf_p_cost: u32
        +12   16  salt (random, per slot)
        +28   24  XChaCha20-Poly1305 nonce (random, per slot)
        +52   48  wrapped DEK: 32-byte ciphertext + 16-byte Poly1305 tag
```

File length MUST equal `5 + 100 × slot_count`; readers MUST reject anything
else. Unlock = try each slot in order (derive slot key, attempt AEAD open);
authentication failure on every slot means a wrong passphrase. Implemented
in `tessera-core/src/crypto/keys.rs`.

## 5. `blobs/`

Content-addressed store: a blob's identity is the lowercase hex BLAKE3 hash
of its **plaintext**, stored at `blobs/<first two hex chars>/<full hash>`.
Contents on disk are XChaCha20-Poly1305-encrypted with the DEK and a unique
random 24-byte nonce. Identical plaintext is stored once (deduplication).

On-disk container framing:

```
offset  size  field
0       24    XChaCha20-Poly1305 nonce (random, unique per blob write)
24      n+16  ciphertext + Poly1305 tag
```

The AEAD associated data (AAD) is the blob's address (the lowercase hex hash
string, ASCII bytes). This binds each container to its address: copying a
valid container to a different address fails authentication. Readers MUST
verify the AEAD tag and SHOULD additionally recompute the BLAKE3 hash of the
decrypted plaintext against the address (defense in depth; implemented).
Writes are atomic (temp file + rename). Implemented in
`tessera-core/src/blob/mod.rs`.

## 6. `receipts/`

One JSON file per finalized receipt, named by receipt id. Each finalized
receipt embeds the BLAKE3 hash of the previous finalized receipt, forming a
per-vault tamper-evident chain. Schema: `spec/receipt.schema.json`.

*Status: chain fields not yet implemented; completed in M5.*

## 7. `inbox/`

Plaintext staging area. Files here are **not part of the vault's data set**:
they are unencrypted, unindexed, and invisible to retrieval and lenses.
Ingestion encrypts an original into `blobs/` **before** any parsing, then
removes it from `inbox/`.

## Version history

| Version | Date | Changes |
|---|---|---|
| 1 | 2026-07-05 | Initial format: manifest with Argon2id/XChaCha20-Poly1305 parameters and embedding model registry; bundle layout reserved. |
