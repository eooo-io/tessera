# Metadata Confidentiality Threat Model

**Scope**: Tessera vault format v3 and the format-v1/v2 migration boundary

**Status**: Issue #50 implementation contract

**Private-data rule**: This inventory is derived from repository schema and
synthetic fixtures. It does not inspect Ezra's private corpus.

## Assets and security objective

Tessera protects artifact content, derived content, owner policy, provenance,
access evidence, conversation context, and the metadata that describes them.
For a locked vault, an observer without a working keyslot must not learn those
values or confirm guessed exact document bytes from an exposed identifier.

The v0.1 objective is confidentiality and integrity of persistent metadata at
rest while retaining owner-controlled unlock, copy, backup, restore,
diagnostics, repair, and cross-platform operation. Availability, traffic
analysis, whole-bundle rollback detection, and protection from an attacker in
an unlocked owner process are separate concerns.

## Threat actors

| Actor | Capability | v0.1 protection | Residual capability |
|---|---|---|---|
| Stolen/offline-copy reader | Reads and copies every bundle byte indefinitely | Cannot read protected database, blob, or receipt content; cannot compute vault-keyed blob paths | Sees bundle structure, ciphertext counts and sizes, public unlock parameters, opaque names, timestamps exposed by the filesystem, and intentional inbox plaintext |
| Read-only filesystem observer | Reads the bundle while no authorized unlocked process is available | Same locked-at-rest protection as an offline copy | May observe changes, file sizes, modification times, and access patterns over time |
| Malicious same-user process | Reads owner-readable files and may inspect other owner processes where the OS permits | Locked persistent metadata remains encrypted | Can read intentional inbox plaintext; may read unlocked memory, open handles, pipes, or owner output; Unix mode bits do not isolate processes with the same uid |
| Vault-write attacker | Adds, removes, truncates, swaps, or rolls back files without keys | Authenticated pages and containers, keyed addresses, schema checks, and consistency diagnostics fail closed on detected damage | Can deny service, delete evidence, or roll back the complete bundle to a previously valid state; no external trusted head exists |
| Guessed-document confirmer | Knows candidate bytes and computes public hashes and legacy paths | Cannot derive the vault-keyed blob path or read the protected logical hash | May infer from size and timing if separately observed; intentional inbox plaintext is directly visible |
| Backup/sync provider | Stores versions and observes names, sizes, timing, and deletion | Receives the same encrypted bundle representation as a locked copy | Retains structural metadata and historical ciphertext or deleted plaintext staging according to provider policy |
| Forensic recovery actor | Examines filesystem journals, snapshots, unallocated blocks, SSD/controller remnants, or old provider versions | Tessera avoids or removes named plaintext working copies where practical | Tessera cannot guarantee secure deletion, snapshot expiration, SSD overwrite, or provider erasure |

## Trust boundaries

- The vault data-encryption key is trusted after a keyslot authenticates.
- Domain-separated database, blob-address, TSB2 blob-encryption,
  receipt-encryption, and receipt-authentication keys are trusted only inside
  the unlocked process.
- The public manifest, filesystem names, migration marker, database files,
  blob files, receipt files, inbox, backups, and all sidecars are attacker
  controlled while locked.
- SQLite schema, migration rows, indexes, vector tables, and diagnostics become
  trusted only after database keying and authenticated reads succeed.
- Blob and receipt paths are lookup hints. Their containers must authenticate
  against the owner-keyed expected identity before content is trusted.

## Current format-v2 plaintext baseline

The baseline at merge commit
`e655acec9c32d9ed3b1f42ad9d9bc68e9c2a4cd4` has an ordinary plaintext SQLite
database in WAL mode. SQLite's header, schema SQL, table and index names, every
row value, vector page, migration entry, freelist residue, WAL page, and
shared-memory coordination file are readable without unlocking. Deleted values
may persist in database free pages, WAL history, filesystem snapshots, and
storage-provider history.

### Database field inventory

Every field below is plaintext in format v2. Primary and foreign-key
relationships, uniqueness, ordering, row counts, and nullability add further
relationship metadata even when a value is an opaque generated id.

| Table or virtual table | Plaintext fields |
|---|---|
| `schema_migrations` | `version`, `name`, `applied_at` |
| `spaces` | `id`, `name`, `parent_id`, `created_at`, `updated_at` |
| `artifacts` | `id`, `space_id`, `filename`, `media_type`, `sensitivity`, `state`, `created_at`, `updated_at` |
| `artifact_versions` | `id`, `artifact_id`, `version`, `blob_hash`, `size_bytes`, `created_at` |
| `tags` | `id`, `name` |
| `artifact_tags` | `artifact_id`, `tag_id` |
| `provenance` | `id`, `derived_blob_hash`, `source_artifact_version_id`, `tool`, `tool_version`, `locality`, `created_at` |
| `derived_text` | `id`, `artifact_version_id`, `blob_hash`, `extractor`, `extractor_version`, `created_at` |
| `chunks` | `id`, `derived_text_id`, `chunk_index`, `byte_offset_start`, `byte_offset_end`, `token_count`, `content_hash`, `section_heading`, `created_at` |
| `state_transitions` | `id`, `artifact_id`, `from_state`, `to_state`, `actor`, `created_at` |
| `chunk_embeddings` and sqlite-vec shadow tables | 384-dimensional embedding bytes plus virtual-table row and chunk structure |
| `embeddings_map` | `chunk_id`, `vec_rowid`, `model_version`, `created_at` |
| `lenses` | `id`, `name`, `policy_json`, `created_at`, `updated_at` |
| `summaries` | `id`, `artifact_version_id`, `blob_hash`, `summarizer`, `summarizer_version`, `locality`, `created_at`, `updated_at` |
| `pairings` | `id`, `lens_id`, `purpose`, `agent_name`, `ttl_minutes`, `approved_at`, `revoked_at`, `oauth_client_id`, `lens_updated_at` |
| `sessions` | `id`, `pairing_id`, `lens_id`, `purpose`, `agent_name`, `started_at`, `expires_at`, `ended_at`, `status`, `receipt_id` |
| `receipt_chain_state` | `singleton`, `next_seq`, `head_hash`, `updated_at` |
| `receipts_index` | `receipt_id`, `seq`, `prev_receipt_hash`, `self_hash`, `file_name`, `committed_at` |
| `processing_errors` | `id`, `artifact_id`, `stage`, `message`, `occurred_at`, `resolved_at` |
| `oauth_clients` | `client_id`, `client_name`, `redirect_uris_json`, `created_at` |
| `oauth_authorization_codes` | `code_hash`, `client_id`, `pairing_id`, `redirect_uri`, `code_challenge`, `resource`, `expires_at`, `used_at` |
| `oauth_access_tokens` | `token_hash`, `client_id`, `pairing_id`, `lens_id`, `resource`, `created_at`, `expires_at`, `revoked_at` |
| `guardian_lock_state` | `singleton`, `generation`, `updated_at` |
| `reindex_chunk_embeddings` and sqlite-vec shadow tables | replacement 384-dimensional embedding bytes plus virtual-table row and chunk structure |
| `reindex_embeddings_map` | `chunk_id`, `vec_rowid`, `model_version`, `created_at` |
| `reindex_state` | `singleton`, `model_version`, `status`, `total_chunks`, `started_at`, `updated_at` |
| `transcript_turns` | `id`, `derived_text_id`, `turn_index`, `byte_offset_start`, `byte_offset_end`, `timestamp_start_ms`, `timestamp_end_ms` |
| `web_staging` | `staged_filename`, `source_url`, `final_url`, `title`, `published_at`, `fetched_at` |
| `web_sources` | `artifact_version_id`, `source_url`, `final_url`, `title`, `published_at`, `fetched_at` |
| `conversation_archives` | `id`, `source_artifact_version_id`, `schema_version`, `source_product`, `source_hash`, `normal_form_blob_hash`, `parser_name`, `parser_version`, `normalizer_name`, `normalizer_version`, `locality`, `processed_at` |
| `conversations` | `id`, `archive_id`, `artifact_version_id`, `source_conversation_id`, `source_created_at`, `source_updated_at`, `selected_branch_endpoint_id`, `canonical_hash`, `created_at` |
| `conversation_source_records` | `id`, `conversation_id`, `source_record_id`, `record_index`, `source_id`, `byte_start`, `byte_end`, `line_start`, `line_end` |
| `conversation_nodes` | `id`, `conversation_id`, `source_node_id`, `parent_id`, `role`, `source_state`, `source_timestamp`, `selected_order` |
| `conversation_node_source_records` | `node_id`, `source_record_id` |
| `conversation_content_parts` | `id`, `node_id`, `source_part_id`, `part_index`, `kind`, `tool_use_part_id`, `attachment_id`, `attachment_state`, `attachment_hash` |
| `conversation_derivations` | `id`, `conversation_id`, `derived_text_id`, `normalized_blob_hash`, `derivation_hash`, `renderer_name`, `renderer_version`, `chunker_name`, `chunker_version`, `target_tokens`, `overlap_tokens`, `locality`, `processed_at` |
| `conversation_spans` | `id`, `derivation_id`, `node_id`, `part_id`, `byte_offset_start`, `byte_offset_end` |
| `conversation_chunk_map` | `chunk_id`, `derivation_id`, `first_node_id`, `last_node_id`, `branch_endpoint_node_id`, `mapped_at` |
| `conversation_ingestion_runs` | `id`, `source_artifact_version_id`, `target_space_id`, `source_product`, `source_hash`, `parser_name`, `parser_version`, `normalizer_name`, `normalizer_version`, `status`, six outcome counts, `checkpoint_ordinal`, `retry_count`, `error_code`, `safe_error_summary`, `started_at`, `updated_at`, `completed_at`, `source_export_id` |
| `conversation_ingestion_items` | `id`, `run_id`, `ordinal`, `source_conversation_id`, `source_digest`, `status`, `persisted_conversation_id`, `previous_persisted_conversation_id`, `derived_text_id`, `derivation_hash`, `embedding_model_version`, `error_code`, `safe_error_summary`, `retry_count`, `attempted_at`, `completed_at` |
| `conversation_ingestion_heads` | `source_product`, `source_conversation_id`, `persisted_conversation_id`, `source_digest`, parser and normalizer names and versions, `run_id`, `item_id`, `updated_at` |
| `conversation_ingestion_replacements` | `id`, prior and replacement conversation ids, `run_id`, `item_id`, `relationship`, `created_at` |
| `conversation_source_metadata` | `conversation_id`, `source_product`, `session_id`, `project`, `repository`, `working_directory`, `git_branch`, `git_commit`, `source_file_identity`, `models_json`, `source_created_at`, `source_updated_at` |
| `image_derivations` | `id`, artifact and derived-text ids, thumbnail/OCR/caption blob hashes, media type, tool and model names and versions, `locality`, `cloud_opt_in`, `created_at` |

The following explicit index names and their indexed columns are also visible:
`idx_artifacts_space`, `idx_artifacts_state`, `idx_versions_artifact`,
`idx_provenance_blob`, `idx_derived_text_version`, `idx_chunks_derived`,
`idx_transitions_artifact`, `idx_embeddings_model`, `idx_lenses_name`,
`idx_summaries_version`, `idx_pairings_lens`, `idx_pairings_oauth_client`,
`idx_sessions_status`, `idx_receipts_index_seq`,
`idx_processing_errors_active`, `idx_oauth_tokens_pairing`,
`idx_transcript_turns_derived_range`, all conversation source, state, range,
run, item, replacement, and branch indexes, and
`idx_image_derivations_version`.

### Public manifest baseline

`tessera.json` exposes `format_version`, `created_at`, KDF algorithm and cost
parameters, cipher name, every embedding model `name`, `version`, and
`dimensions`, plus any unknown preserved top-level or crypto extension fields.
The file name, JSON syntax, byte length, modification time, and atomic
`.tessera.json.<ulid>.tmp` residue pattern are also visible.

### Filesystem and sidecar baseline

| Path class | Format-v2 visibility and risk |
|---|---|
| `vault.db` | Plain SQLite header, schema, rows, vectors, free pages, sizes, and modification time |
| `vault.db-wal` | Plain committed and historical database pages until checkpoint or reuse |
| `vault.db-shm` | Coordination structure and access activity; recreated from WAL |
| `tessera.json` | Manifest fields listed above |
| `keyslot.bin` | Slot count, KDF parameters, salts, nonces, wrapped-key sizes, file size, and modification time; no plaintext DEK or passphrase |
| `blobs/<hash-prefix>/<plaintext-hash>` | Public BLAKE3 hash of exact plaintext, enabling confirmation; shard/path, count, ciphertext size, and modification time |
| `blobs/<hash>.tmp.<ulid>` | Encrypted partial container, public content hash in path, and interrupted-write timing |
| `receipts/<receipt-id>.trc` | Opaque protected payload, but receipt ULID, count, size, and filesystem times are visible |
| `receipts/.<receipt-id>.prepared` | Opaque protected payload plus pending receipt id and crash boundary |
| legacy `receipts/<receipt-id>.json` | Complete plaintext legacy receipt until explicit receipt migration |
| `inbox/<source-name>` | Intentional full plaintext content, filename, type hint, size, and time before ingestion |
| `inbox/.<target>.<ulid>.partial` | Partial plaintext copy after interrupted or failed staging; current diagnostics retain it |
| web staging markdown | Plain title, byline, publication date, body, and source-derived slug while in inbox |
| web fetch temporary directory | Named `article.html` body and `headers.txt` response headers until cleanup |
| DOCX extraction temporary directory | Named plaintext original `input.docx` until the external converter returns and cleanup runs |
| sibling `.backup-staging-*` | Complete bundle snapshot in progress, including plaintext database and inbox, until rename or cleanup |
| completed backup | Same locked-visible properties as the source at backup time |
| model installation staging/backup | Model registry and model file names, versions, sizes, and trusted manifest; model assets are public supply-chain material, not private corpus content |
| manifest/keyslot temporary files | Public manifest or wrapped-key data under generated temporary names until synced rename or cleanup |

Directory names `blobs`, `receipts`, and `inbox`, bundle name and location,
directory entry count, allocation size, ownership, permissions, modification
times, access times where enabled, snapshots, and provider version history are
outside content encryption. Default creation currently relies on process umask
rather than explicitly enforcing owner-only modes on every path.

## Format-v3 protection matrix

| Category | Protection | Locked-visible residual |
|---|---|---|
| Complete SQLite schema, rows, indexes, vectors, migration ledger, free pages, WAL and statement-journal pages | Owner-keyed authenticated SQLCipher pages; non-transaction temp stores forced to memory | Ciphertext sizes, page count, SQLCipher framing, WAL/SHM existence and filesystem times |
| Logical plaintext hashes and dedup relationships | Retained inside protected database and protected receipts | None of the logical hashes |
| Blob filesystem address | Vault-keyed opaque token; authenticated v2 container binds token | Opaque token, shard, count, ciphertext size, modification time |
| Public manifest | Creation time, model registry, and private extensions moved to encrypted `vault_metadata` | Format version and portable public crypto/KDF parameters |
| Protected receipts | Existing encrypted/authenticated container plus encrypted database index | `rcpt_<ULID>` name, including its millisecond creation-time component; file count, size, prepared/final state, and filesystem time |
| Inbox | Restrictive owner-only mode, atomic staging, bounded stale-partial cleanup | Intentional plaintext staging content and name until ingestion; forensic deletion limits |
| Web fetch | Bounded body, HTTP status, and content type captured through one in-memory curl stream without a named body or header file | Process memory and pipe data while unlocked; network and endpoint observations |
| DOCX external-tool input | Decrypted DOCX bytes stream to pandoc over a bounded process pipe; no application-owned named plaintext file | Unlocked same-user/process access to process memory and pipe data while extraction runs |
| Backup | Keyed destination database, protected file copy, and copied-keyslot digest binding to the source unlock state before publication | Same structural residuals as source plus backup name and provider history |
| Migration and atomic residue | Fixed non-sensitive marker, authenticated staged containers, protected prepared database, one validated authoritative source | Fixed migration names; owner-derived inbox/backup temp prefixes; ULIDs in manifest, blob, and receipt temp names; staged/retired existence, sizes, and times; retired plaintext forensic residue after directory-entry removal |
| Permissions | New directories/files are created owner-only on Unix; opening strips group/other bits while preserving deliberately removed owner bits; best portable effort elsewhere | Same-user processes retain owner authority; filesystem ACL/provider behavior may differ |

## Security invariants

1. A database key is installed before the first database read, including
   backup, diagnostic, migration, and reopened Guardian connections.
2. New-vault creation accepts only an absent or empty real directory and
   refuses pre-seeded component paths before writing bundle data.
3. Migration repeats logical inventory validation under an exclusive SQLite
   writer boundary and retains it through legacy retirement.
4. Wrong key, plaintext-at-v3-path, malformed page, or unsupported format never
   falls through to empty-database creation.
5. Database, blob-address, TSB2 blob-encryption, receipt-encryption, and
   receipt-authentication keys use distinct derivation domains and are never
   serialized. Direct-DEK blob decryption is confined to the legacy reader.
6. Public blob paths cannot be computed from candidate content without the
   vault key. The same content in different vaults has different paths.
7. Logical content hashes remain protected and continue to authenticate
   decrypted bytes, deduplication, provenance, and receipts.
8. Migration authenticates and syncs each replacement before retiring its
   source, and ordinary operation refuses an in-progress bundle.
9. Public manifest fields are a pre-unlock portability allowlist, not a place
   for convenient domain metadata.
10. Synthetic locked-vault scans cover raw bytes and relative paths, including
    UTF-8 case forms, public hashes, and UTF-16LE/BE encodings, and fail on any
    protected sentinel or legacy public hash outside the intentional inbox.
11. Tessera makes no secure-deletion, unlocked-malware, traffic-analysis,
   same-uid isolation, or external rollback-detection claim.

## Verification topology

- Unit tests cover key separation, database key order, wrong-key behavior,
  keyed paths, container authentication, manifest minimization, and permissions.
- A crate-level synthetic fixture populates every protected metadata category,
  closes all handles, and recursively scans the complete bundle and a
  Tessera-created backup. The black-box scanner separately classifies every
  visible file and directory against the structural allowlist.
- Database WAL, blob/receipt prepared files, inbox partials, migration phases,
  and backup staging are covered by their focused fault/permission tests. The
  DOCX test exercises pandoc stdin, and code review verifies there is no named
  application plaintext path; the evidence matrix does not pretend one fixture
  can pause every operation at once.
- Confirmation tests compare at least 100 known candidate public hashes and
  legacy paths, including one present document, against locked bytes and paths.
- Migration fault tests inject interruption after every durable phase and
  compare logical inventories after resumption.
- Recovery tests cover copy, backup, restore, query, protected receipt
  verification and continuation, diagnostics, orphan handling, and derived
  repair.
- Ignored controlled tests record storage, migration, query, backup, restore,
  diagnostic, and repair timings and variance.
- Exact-head macOS and Ubuntu CI prove the supported platform build and test
  boundary. A chained workflow additionally transfers a macOS-created
  protected backup to Ubuntu, then an Ubuntu-created backup back to macOS, and
  verifies unlock, diagnostics, receipts, query, and source identity on each
  receiving host. It does not prove provider-specific deletion or
  private-corpus quality.
