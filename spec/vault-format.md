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
| `dimensions` | integer | Vector dimensionality. Format v1 permits only the repository-pinned `all-MiniLM-L6-v2@onnx-1` 384-dimensional space. A reader that cannot verify and load it MUST fail closed and offer explicit provisioning or reindexing; it MUST NOT silently mix vector spaces. |

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
Migration 0003 adds `chunks` (byte ranges into the derived text, always on
UTF-8 char boundaries, with per-chunk content hash for citation integrity).
Migration 0005 adds vector storage: `chunk_embeddings` (a sqlite-vec `vec0`
virtual table, `float[384]`; readers MUST register the sqlite-vec extension
before opening) and `embeddings_map` (chunk ↔ vec rowid, producing model
version — mixed model versions in one vault are refused at query time).
Dimension changes are explicitly forbidden in format v1. Reindexing uses a
durable same-dimension shadow table and atomically replaces the active derived
index only after every chunk is complete; see `docs/model-supply-chain.md`.
Migrations 0006–0009 append lenses, summaries, pairings, and live sessions.
Migration 0010 adds `receipt_chain_state` (the singleton next-sequence/head)
and `receipts_index` (unique receipt id and sequence, predecessor/self hashes,
and final filename). Migration 0011 adds `processing_errors`, a bounded
per-artifact/stage error history used by owner quarantine review; resolved
errors remain auditable. Error messages are plaintext metadata and MUST NOT
contain source content, credentials, or secrets. The database never contains
plaintext artifact content or receipt JSON.

Migration 0016 adds `transcript_turns`, keyed to an encrypted derived-text
record. Each row preserves the turn index, exact byte range in normalized
derived text, and optional source-media start/end milliseconds. Transcript
content, speaker names, and source cue ids remain in encrypted blobs. Timestamps
and byte offsets are plaintext metadata and therefore fall under the
metadata-hardening work tracked separately for v0.1. Chunks over transcript
derivations pack whole turn ranges and do not split a speaker turn to meet the
target token count.

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

One JSON file per finalized receipt, named `<receipt_id>.json`. Each finalized
receipt embeds its contiguous `seq`, the BLAKE3 hash of the previous finalized
receipt (`prev_receipt_hash`), and a BLAKE3 hash of its own canonical JSON with
`self_hash` cleared. This is an internally consistent tamper-evident chain; it
is not a signature or an external trust anchor. Schema:
`spec/receipt.schema.json`.

New receipts use `schema_version: 2`. A v2 receipt binds the persisted Guardian
`session_id`, applicable `pairing_id`, and the complete effective lens-policy
snapshot plus its BLAKE3 hash. Every disclosed result records:

- access kind (`semantic_query` or `direct_item`), artifact and exact artifact
  version;
- exact encrypted evidence blob plus `[start, end)` byte range and BLAKE3 hash
  of the bytes actually returned;
- derived-text/chunk or summary identity and its provenance records;
- requested and applied disclosure modes, returned/source byte counts, and
  whether metadata/full disclosure were allowed;
- for semantic retrieval, rank, score, and embedding model
  name/version/dimensions.

`tessera receipts verify` recomputes the chain, policy hash, source
relationships, provenance references, embedding-model binding, and exact
disclosed-content hashes from the unlocked vault. Receipts without a
`schema_version` are legacy v1 records: they remain readable and their original
hash chain remains verifiable, but they cannot be upgraded into exact-disclosure
evidence because the missing source coordinates were never recorded.

### Concurrent finalization and crash boundary

Opening a receipt session does not reserve a chain position. Finalization uses
a brief SQLite `BEGIN IMMEDIATE` transaction to read and validate the durable
head, assign `seq` and `prev_receipt_hash`, and uniquely commit the receipt
index plus the next head. Agent session activity is never held under that
write lock.

The portable JSON file uses a recoverable two-phase boundary because SQLite
cannot transact a filesystem rename:

1. while holding the finalization transaction, write and `fsync` the complete
   receipt to `receipts/.<receipt_id>.prepared`;
2. commit the unique index and chain head;
3. atomically rename the prepared file to `<receipt_id>.json` and `fsync` the
   receipts directory.

An interruption before step 2 rolls back the database and exposes no JSON
receipt. An interruption after step 2 leaves a committed index and prepared
file; the next list, load, verify, or finalization completes the deterministic
rename before proceeding. A committed index with neither prepared nor final
file, duplicate id/sequence, inconsistent filename, or disagreement among the
head, index, and file chain fails closed. Existing pre-0010 file chains are
backfilled only after the entire chain verifies.

### HTTP OAuth metadata

Migration 0012 adds OAuth public-client registrations, one-time authorization
codes, and access-token bindings to `vault.db`, plus an optional
`pairings.oauth_client_id`. Authorization codes and access tokens are stored
only as BLAKE3 hashes. Each record binds the client, pairing/lens, exact
redirect or resource URI, expiry, and revocation/use state. These tables are
portable authorization metadata, not encrypted content; no source plaintext or
raw bearer credential is stored in them.

Migration 0013 adds `pairings.lens_updated_at`, backfills existing pairings to
the lens revision present at migration, and makes the grant fields immutable
with a database trigger. Only `revoked_at` may change. Guardian calls compare
the stored revision with the current lens before disclosure; an edited or
deleted lens requires a new owner-approved pairing.

Migration 0014 adds the singleton `guardian_lock_state` generation. An owner
`guardian lock` operation atomically revokes active sessions and advances that
generation. Running Guardians exit when it differs from the generation they
captured at unlock; this is process coordination metadata, not key material.

## 7. `inbox/`

Plaintext staging area. Files here are **not part of the vault's data set**:
they are unencrypted, unindexed, and invisible to retrieval and lenses.
Ingestion encrypts an original into `blobs/` **before** any parsing, then
removes it from `inbox/`.

## Version history

| Version | Date | Changes |
|---|---|---|
| 1 | 2026-07-05 | Initial format: manifest with Argon2id/XChaCha20-Poly1305 parameters and embedding model registry; bundle layout reserved. |
