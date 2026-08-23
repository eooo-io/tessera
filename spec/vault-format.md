# Tessera Vault Bundle Format

**Format version: 3** (see `FORMAT_VERSION` in `tessera-core/src/vault/manifest.rs`)

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
├── vault.db         # SQLCipher-protected SQLite database, WAL mode (§3)
├── keyslot.bin      # key slots wrapping the DEK (§4)
├── blobs/           # content-addressed encrypted blob store (§5)
├── receipts/        # protected, owner-authenticated access receipts (§6)
└── inbox/           # plaintext staging for content not yet ingested (§7)
```

Invariants that apply to the whole bundle:

- **I1 — Self-contained:** no file inside the bundle references data outside
  it, and no path stored inside the bundle is absolute.
- **I2 — Copy-is-move:** copying the directory to a new location/host yields
  a fully functional vault; nothing is keyed to machine identity. (The macOS
  Keychain may cache the DEK for convenience, but the passphrase path in
  `keyslot.bin` always works.)
- **I3 — Protected at rest:** content lives in authenticated blob containers;
  metadata, indexes, logical content hashes, receipt indexes, and model
  registries live in the SQLCipher-protected database. Plaintext content may
  appear only in the intentional `inbox/` staging boundary and explicit owner
  exports. Receipt payloads are protected separately as described in §6.
- **I4 — No public content verifier:** the logical BLAKE3 content hash remains
  protected metadata. Locked-visible blob paths use a vault-keyed opaque
  address and cannot be computed from guessed content without the vault DEK.

## 2. `tessera.json` — the manifest

UTF-8 JSON object, pretty-printed, trailing newline. Written by
`VaultManifest::save`, read by `VaultManifest::load`.

| Field | Type | Meaning |
|---|---|---|
| `format_version` | integer ≥ 1 | Bundle format version. Readers MUST refuse to open a bundle whose version is greater than the version they implement. |
| `crypto` | object | KDF and cipher parameters, see below. |

`created_at`, the embedding-model registry, and preserved private legacy
extensions are stored in the encrypted `vault_metadata` table. They MUST NOT
appear in a format-v3 public manifest.

`crypto` object:

| Field | Type | v1 value |
|---|---|---|
| `kdf` | string | `"argon2id"` |
| `kdf_m_cost_kib` | integer | `65536` (64 MiB) |
| `kdf_t_cost` | integer | `3` |
| `kdf_p_cost` | integer | `4` |
| `cipher` | string | `"xchacha20poly1305"` |

Protected `embedding_models[]` entry:

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Model name, e.g. `"all-MiniLM-L6-v2"`. |
| `version` | string | Implementation/version identifier. |
| `dimensions` | integer | Vector dimensionality. Format v1 permits only the repository-pinned `all-MiniLM-L6-v2@onnx-1` 384-dimensional space. A reader that cannot verify and load it MUST fail closed and offer explicit provisioning or reindexing; it MUST NOT silently mix vector spaces. |

**Forward compatibility:** legacy unknown top-level and crypto fields move to
encrypted `vault_metadata.manifest_extensions` during migration. A format-v3
writer does not echo them into the locked-visible manifest.

## 3. `vault.db`

SQLCipher 4 database in WAL mode with foreign keys enforced. Every database,
journal, and WAL page is protected under a raw 256-bit key derived from the
vault DEK with context `tessera database encryption key v1`. The build uses
SQLCipher's authenticated page format and forces SQLite temporary storage to
memory. Schema is defined by ordered append-only migrations in
`tessera-core/src/db/migrations/` and recorded in `schema_migrations`.

`open_database` installs the key before its first read, proves that an existing
file is readable, configures the connection, and applies pending migrations
transactionally. A wrong key, plaintext database, truncated file, or unreadable
protected database fails closed. An existing invalid file MUST NOT be treated
as an empty database.

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
errors remain auditable. Error messages MUST NOT contain source content,
credentials, or secrets even though format v3 protects the database at rest.
The database never contains plaintext artifact content or receipt JSON.

Migration 0016 adds `transcript_turns`, keyed to an encrypted derived-text
record. Each row preserves the turn index, exact byte range in normalized
derived text, and optional source-media start/end milliseconds. Transcript
content, speaker names, and source cue ids remain in encrypted blobs. Timestamps
and byte offsets are protected database metadata. Chunks over transcript
derivations pack whole turn ranges and do not split a speaker turn to meet the
target token count.

Migration 0017 adds `web_staging` and `web_sources`. `web_staging` is the
recoverable association between an explicitly fetched Markdown file in
`inbox/` and its requested/final URL, extracted title/publication date, and
fetch time. Intake moves that association transactionally to `web_sources`,
keyed to the exact artifact version, before removing the staged file. Fetched
HTML is bounded temporary input and is not retained; extracted Markdown follows
the normal encrypted-blob pipeline. URLs, titles, dates, fetch times, and
staging filenames are protected database metadata in format v3. The staged
Markdown file itself remains intentional inbox plaintext until ingestion.

Migration 0018 adds the conversation provenance graph:

- `conversation_archives` binds the exact encrypted source artifact version,
  encrypted full normal-form blob, BLAKE3 source identity, source product,
  parser/normalizer versions, locality, and processing time;
- `conversations` binds one source conversation to one ordinary artifact
  version. The artifact starts `pending`, and its existing artifact-level
  sensitivity is the v1 conversation sensitivity boundary;
- `conversation_source_records`, `conversation_nodes`,
  `conversation_node_source_records`, and `conversation_content_parts`
  preserve stable source ids, parent edges, selected-path order, source state,
  exact raw-record coordinates, tool pairing, and attachment
  identity/preservation state;
- `conversation_derivations` and `conversation_spans` bind an encrypted
  normalized transcript to renderer/chunker versions, derivation hash,
  locality, processing time, and exact node/content-part byte ranges; and
- `conversation_chunk_map` binds every derived chunk to its first/last source
  node and selected-branch endpoint. The chunk's own byte range plus overlapping
  spans reconstruct the included node, part, source-record, and timestamp
  coordinates.

Internal archive/conversation/node/part/record/derivation ids are deterministic
BLAKE3 mappings over length-delimited source identities. Re-rendering or
re-chunking creates new derivation and chunk ids but MUST NOT replace source
identities. Conversation chunking reuses `transcript_turns` with one contiguous
range per selected node, so it does not split a message merely to meet a token
target or cross into an alternate branch. Integrity diagnostics count the full
normal-form blob as a referenced derivation; the explicit owner derived-rebuild
path recreates conversation renderings and chunk mappings from the authenticated
canonical conversation artifact rather than treating them as generic text.

Content-bearing title/project/model/text/code/tool data, attachment filenames,
the full canonical conversation, and normalized transcript remain encrypted in
`blobs/`. Stable source ids, source states, attachment preservation/hash,
timestamps, byte/line coordinates, component versions, and processing metadata
are protected database metadata. Agent-facing code may expose content-free
citation coordinates only after the ordinary artifact lens permits the
conversation; reconstructing whole source messages is a separate unlocked-owner
operation.

The source-neutral conversation object used before persistence is versioned as
`tessera.conversation.v1` in `spec/conversation-normal-form.schema.json` and
documented in `docs/conversation-normal-form-v1.md`. It preserves source-record
coordinates, explicit parent-linked branches, one selected path, ordered typed
content parts, attachments, deleted/hidden/unsupported states, and parser plus
normalizer versions. Migration 0018 is its on-disk contract. Originals,
canonical per-conversation envelopes, the full archive normal form, and
content-bearing derivations are encrypted blobs rather than plaintext database
values.

Migration 0019 adds `conversation_ingestion_runs`,
`conversation_ingestion_items`, `conversation_ingestion_heads`, and
`conversation_ingestion_replacements`. The run/item tables form the durable
source-neutral checkpoint and content-free outcome ledger. Heads map a source
product plus source-native conversation id to its current persisted identity;
replacement rows preserve corrected-source, parser-upgrade, and
normalizer-upgrade lineage without deleting prior provenance. Run/item errors
are closed structural codes plus static safe summaries and MUST NOT contain
source content. The full state machine, idempotency decisions, CLI reporting,
and non-destructive rollback procedure are specified in
`docs/conversation-ingestion-runs-v1.md`.

Migration 0020 adds `conversation_source_metadata`, a deliberately whitelisted
filter index for source product, session, project/repository, working directory,
git branch/commit, source-file identity, models, and source timestamps. Message
text, tool inputs/results, patches, command output, errors, and attachment
content MUST remain in encrypted blobs and MUST NOT enter this table.

The v1 account-export adapters are source-isolated. The ChatGPT adapter maps
`mapping` nodes and `current_node` into explicit parent-linked branches; it
MUST NOT concatenate regenerated siblings. The Claude adapter maps each
`chat_messages`/`messages` entry and its ordered content blocks independently
from the Claude Code JSONL adapter. For top-level JSON arrays, source records
retain the exact enclosing conversation byte/line range plus source-native
node, message, block, attachment, and tool ids in the encrypted canonical
envelope. A wrapper-object export retains the authenticated whole-export range
when a narrower lexical range is unavailable. Syntax failure stops archive
enumeration; required-structure or field-type drift after enumeration is
recorded against only that source conversation. Attachment references are
preserved but external URLs MUST NOT be fetched by either parser.

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

The unlocked logical identity is the lowercase BLAKE3 hash of plaintext. It is
retained inside protected metadata for integrity, provenance, receipts, and
vault-local deduplication. The locked-visible address is keyed BLAKE3 over the
logical hash with a key derived using `tessera blob address key v1`, stored at
`blobs/<first two address chars>/<full opaque address>`. The same content in
two vaults therefore has different locked-visible addresses.

On-disk container framing:

```
offset  size  field
0       4     magic/version: ASCII "TSB2"
4       24    XChaCha20-Poly1305 nonce (random, unique per blob write)
28      n+16  ciphertext + Poly1305 tag
```

The AEAD associated data is `TSB2` followed by the complete opaque address.
This binds each container to its version and keyed path. Readers verify the
AEAD tag and recompute the protected logical BLAKE3 hash after decrypting.
Writes are atomic (temp file + rename). Implemented in
`tessera-core/src/blob/mod.rs`.

## 6. `receipts/`

Format v2 stores one protected binary container per finalized receipt, named
`<receipt_id>.trc`. The complete logical receipt JSON is encrypted and
authenticated with XChaCha20-Poly1305 under a receipt-encryption key derived
from the vault DEK. The logical JSON schema remains
`spec/receipt.schema.json` for owner review and explicit plaintext export; JSON
is not the format-v2 at-rest representation.

Each finalized receipt embeds its contiguous `seq`, the keyed BLAKE3 token of
the previous finalized receipt (`prev_receipt_hash`), and a keyed BLAKE3 token
over its own canonical JSON with `self_hash` cleared. The authentication key is
independently derived from the DEK. These tokens authenticate a local chain to
an unlocked owner. They are not signatures, public verification material,
non-repudiation, or an external trust anchor.

Domain-separated key derivation contexts are:

- `tessera receipt encryption key v1`
- `tessera receipt authentication key v1`

Protected-container layout:

```
offset  size  field
0       4     magic/version: ASCII "TSR1"
4       24    XChaCha20-Poly1305 nonce (random per write)
28      n+16  encrypted logical receipt JSON + Poly1305 tag
```

AAD is `TSR1`, followed by the receipt-id byte length as a little-endian `u32`,
followed by the UTF-8 receipt id. A container copied under another receipt id
therefore fails authentication. Receipt count, container sizes, opaque receipt
ids in filenames, filesystem timestamps, and access patterns remain visible
through the directory. Sequence positions, chain tokens, logical timestamps,
policy, pairings, sessions, and receipt indexes are protected inside SQLCipher
and the receipt containers.

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

`tessera receipts verify` first decrypts and authenticates every container,
then recomputes the keyed chain, policy hash, source
relationships, provenance references, embedding-model binding, and exact
disclosed-content hashes from the unlocked vault. It distinguishes malformed
containers, unauthenticated legacy storage, cryptographic authentication
failure, and a structurally broken internal chain. The command proves only
owner-keyed local authenticity.

Format-v1 `<receipt_id>.json` files are unauthenticated legacy storage.
Ordinary list, load, verify, and finalization refuse such a vault. The owner
must run `tessera receipts migrate --yes`, which verifies the complete legacy
chain and exact disclosures before protecting any replacement. Logical receipt
schema v1 records remain readable after migration, but absent source
coordinates cannot be invented or upgraded into v2 exact-disclosure evidence.

### Concurrent finalization and crash boundary

Opening a receipt session does not reserve a chain position. Finalization uses
a brief SQLite `BEGIN IMMEDIATE` transaction to read and validate the durable
head, assign `seq` and `prev_receipt_hash`, and uniquely commit the receipt
index plus the next head. Agent session activity is never held under that
write lock.

The protected container uses a recoverable two-phase boundary because SQLite
cannot transact a filesystem rename:

1. while holding the finalization transaction, write and `fsync` the complete
   protected container to `receipts/.<receipt_id>.prepared`;
2. commit the unique index and chain head;
3. atomically rename the prepared file to `<receipt_id>.trc` and `fsync` the
   receipts directory.

An interruption before step 2 rolls back the database and exposes no protected
receipt. An interruption after step 2 leaves a committed index and prepared
file; the next list, load, verify, or finalization completes the deterministic
rename before proceeding. A committed index with neither prepared nor final
file, duplicate id/sequence, inconsistent filename, or disagreement among the
head, index, and file chain fails closed. Existing pre-0010 file chains are
backfilled only after the entire legacy chain verifies.

Legacy migration prepares every encrypted replacement before a single SQLite
transaction changes all receipt index rows and the chain head. After that
commit, deterministic recovery renames prepared containers and deletes their
legacy JSON counterparts. Historical format-v1 receipt migration advances the
receipt representation to format 2 but never downgrades a format-v3 manifest.
Whole-bundle format-v3 migration performs this receipt transition before
committing the minimized manifest, so a successful locked vault cannot retain
plaintext legacy receipts.

### HTTP OAuth metadata

Migration 0012 adds OAuth public-client registrations, one-time authorization
codes, and access-token bindings to `vault.db`, plus an optional
`pairings.oauth_client_id`. Authorization codes and access tokens are stored
only as BLAKE3 hashes inside the protected database. Each record binds the
client, pairing/lens, exact
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
removes it from `inbox/`. Same-directory partial copies are owner-only and are
removed during bounded inbox recovery. Removing a directory entry is not a
secure-deletion guarantee on snapshots, journaling filesystems, SSDs, or
provider-retained copies.

## 8. Legacy metadata migration

Ordinary open refuses format-v1/v2 manifests and any bundle containing
`.metadata-migration-v3`, `.vault.db.v3.prepared`, or
`.vault.db.v2.retired`. The owner runs:

```bash
tessera --vault /path/V.tessera metadata migrate --yes
```

Migration authenticates every legacy blob before writing, syncing, reopening,
and verifying its TSB2 replacement. It checkpoints the plaintext WAL, exports
the logical database through `sqlcipher_export`, applies migration 0022, moves
private manifest fields into `vault_metadata`, compares table row inventories,
runs full integrity and foreign-key checks, and reopens the candidate with the derived
key before selection.

The fixed JSON marker contains only `version: 3` and one phase:
`started`, `blobs_protected`, `database_prepared`, `database_selected`, or
`manifest_committed`. Selection retains the last plaintext authority at
`.vault.db.v2.retired` until the protected database and minimized manifest
validate. Repeating any phase is safe; a missing authoritative source plus an
invalid replacement fails closed. Final cleanup removes legacy directory
entries and sidecars but makes no secure-deletion claim.

Migration 0022 adds `vault_metadata(key, value_json, updated_at)`. Its initial
keys are `created_at`, `embedding_models`, and `manifest_extensions`.

## Version history

| Version | Date | Changes |
|---|---|---|
| 1 | 2026-07-05 | Initial format: manifest with Argon2id/XChaCha20-Poly1305 parameters and embedding model registry; bundle layout reserved. |
| 2 | 2026-08-20 | Complete receipt payload encryption, owner-keyed chain authentication, explicit crash-safe legacy migration, and `.trc` protected containers. |
| 3 | 2026-08-23 | SQLCipher-protected metadata and indexes, minimized manifest, keyed opaque blob addressing with TSB2 containers, owner-only permissions, and explicit restart-safe v1/v2 migration. |
