# Issue #50 metadata-confidentiality evidence

**Evidence state:** local candidate evidence, 2026-08-23. Exact PR-head commit
and platform CI links are added only after the independently reviewed commit is
pushed. This report contains synthetic aggregate evidence only.

## Acceptance matrix

| Issue #50 criterion | Implemented contract | State-bound evidence |
|---|---|---|
| Inventory every plaintext field and path | Current v2 baseline and format-v3 target cover database tables, indexes, sidecars, manifest, blobs, receipts, inbox, backup, migration, and temporary residue | `docs/metadata-confidentiality-threat-model.md`; Spec Kit FR-001 through FR-003 |
| Remove exact-content confirmation | Public logical BLAKE3 hashes remain inside SQLCipher and protected receipts; locked paths use vault-keyed BLAKE3 tokens | `blob::tests::public_content_hash_is_absent_from_blob_path_and_container`; `locked_visible_address_is_keyed_and_cross_vault_unlinkable`; 100-candidate scanner test |
| Versioned metadata protections | Format v3 uses keyed SQLCipher, TSB2 opaque blobs, minimized manifest, encrypted model registry, and migration 0022 | `db::tests`; `vault::metadata::tests`; ADR-0002; `spec/vault-format.md` |
| Locked scans match exposure set | Recursive path-and-byte scanner uses only synthetic category sentinels and the real protected logical hash | `metadata_privacy::synthetic_metadata_inventory_and_confirmation_guesses_are_absent_when_locked` |
| Inbox and temp residue bounded | Owner-only atomic partials; abandoned inbox partials are removed; fetched bodies remain in bounded memory; unavoidable external-tool files use owner-only temporary directories | inbox/web/extract tests and `metadata_privacy::bundle_directories_and_files_are_owner_only`; no secure-deletion claim |
| Copy, backup, restore, cross-platform open | Keyed online backup creates a protected staging bundle, reopens and diagnoses it before publication; migrated fixture backs up, restores, unlocks, verifies, and extends its receipt chain | `vault::metadata::tests::legacy_migration_protects_database_manifest_and_blob_address`; `recovery::tests::backup_restores_same_source_identity_at_new_path`; `failed_backup_removes_private_staging_bundle`; exact-head platform CI required below |
| Measure performance and repair tradeoffs | Controlled synthetic migration, storage, semantic query, diagnostics, repair, and backup measurements | `metadata_performance.rs`; ignored migration measurement; results below |
| Format and security docs match | Format v3, ADR, threat model, Spec Kit artifacts, and recovery runbook describe the same boundary | `spec/vault-format.md`; `docs/adr/0002-metadata-confidentiality-v0.1.md`; `docs/recovery-runbook.md` |

## Locked-visible exposure matrix

| Path or property | Format-v3 locked visibility | Consequence |
|---|---|---|
| Bundle directory and stable component names | Visible | Reveals a Tessera vault and its structural components |
| `tessera.json` | Format version and public crypto/KDF parameters | Supports portable unlock; does not contain creation time, models, or private extensions |
| `keyslot.bin` | Magic, slot count, KDF costs, salts, nonces, wrapped-key sizes | Allows offline passphrase guessing subject to Argon2id cost; does not reveal the DEK without a valid passphrase |
| `vault.db`, WAL, SHM | File presence, lengths, filesystem timestamps, page-write/access patterns | SQLCipher protects page contents; size and activity remain traffic-analysis signals |
| `blobs/<shard>/<opaque-address>` | Count, keyed tokens, sizes, timestamps, shard distribution | Does not provide a public guessed-content verifier; same-vault equality and activity remain observable |
| `receipts/rcpt_<ULID>.trc` | Count, millisecond creation time encoded by ULID, container sizes, filesystem timestamps | Receipt content, chain, sessions, pairing, policy, and disclosures remain protected |
| `inbox/` final staged files | Names and plaintext content by owner intent | Explicitly outside locked-vault confidentiality until ingestion |
| Partial, prepared, and migration files | Fixed migration names; owner-derived inbox/backup prefixes; ULIDs in atomic manifest, blob, and receipt temp names; current existence | Owner-only; content is protected except intentional inbox partials and retained legacy authority during explicit migration |
| Backup/sync copies | Same structural, size, timestamp, and traffic exposure as source | Provider may retain old plaintext legacy copies or deleted blocks; Tessera cannot revoke provider snapshots |

The implementation does not protect an unlocked process from same-user
inspection or malware, hide whole-bundle rollback, conceal filesystem traffic,
or guarantee forensic deletion on journals, snapshots, SSDs, or providers.

## Test topology and current aggregates

- Database protection: 11 focused tests passed, covering key installation,
  wrong key, plaintext database, truncation, page tamper, locked byte scan, WAL,
  foreign keys, temporary memory, and migrations.
- Private registry and migration: 14 focused tests passed and 1 performance test
  was intentionally ignored in the ordinary run. The tests cover malformed
  rows/markers, staging collisions, capacity and permission failures, fatal
  source diagnostics, successful and repeated conversion, logical inventory,
  migrated backup/restore, receipt verification/continuation, and resume after
  all five durable boundaries including the retire-before-select crash window.
- Locked privacy and permissions: 4 integration tests passed. They inventory
  every stable path class and find zero locked-byte or path matches for the
  synthetic protected categories, real logical content hashes, and 100
  guessed-document hashes including one known-present candidate. Focused fault
  tests cover transient migration, backup, inbox, blob, receipt, and external
  tool paths that cannot all exist in one stable closed-bundle fixture.
- Blob protection: 17 focused unit tests cover TSB2 framing, address binding,
  cross-vault unlinkability, tamper, wrong key, deduplication, atomic writes,
  authenticated legacy conversion, orphan conversion, and unknown residue.
- CLI confirmation: 1 focused end-to-end test passed for explicit `--yes` and
  idempotent format-v3 operation.

The final local `cargo test --workspace --all-targets` run passed 360 tests
with 4 intentionally ignored performance tests and no failures. The required
ignored workspace run then passed all 4 ignored tests with no failures.

## Controlled performance

Host: local macOS development host, debug test profile, insecure-test Argon2id
fixture only. These are regression observations, not production benchmarks.

| Measurement | Run 1 | Run 2 | Variance |
|---|---:|---:|---:|
| Legacy migration | 605 ms | 595 ms | 1.7% |
| Legacy/protected database size | 675,840 / 688,128 bytes | same | 1.8% protected overhead |
| New protected vault creation | 116 ms | 119 ms | 2.6% |
| Ingest/extract/chunk 100 synthetic documents | 1,285 ms | 1,277 ms | 0.6% |
| Protected semantic query, top 10 | 1,570 us | 1,699 us | 8.2% |
| Diagnostics | 26 ms | 27 ms | 3.8% |
| No-fault derived repair path | 174 ms | 173 ms | 0.6% |
| Keyed backup including destination validation | 958 ms | 958 ms | 0.0% |
| Restore open, diagnostics, and receipt verification | 108 ms | 107 ms | 0.9% |
| Source / backup bundle size | 7,133,489 / 2,502,769 bytes | same | WAL and derived state explain non-equivalence |

No reported final-state pair varied by 10% or more. Exact values remain host-,
filesystem-, cache-, fixture-, and build-profile-dependent.

The final required ignored-suite observation remained inside those controlled
ranges: migration 603 ms; protected vault creation 112 ms; 100-document ingest
1,306 ms; top-10 semantic query 1,629 us; diagnostics 27 ms; repair 175 ms;
backup 949 ms; restore validation 108 ms. It measured the same database and
bundle byte counts shown above.

## Platform CI binding

- Required base commit `e655acec9c32d9ed3b1f42ad9d9bc68e9c2a4cd4`:
  [green macOS and Ubuntu workflow](https://github.com/eooo-io/tessera/actions/runs/32565765214).
- Exact PR-head macOS: pending publication.
- Exact PR-head Ubuntu: pending publication.

## Known limitations

- SQLCipher protects locked database pages, not data after the owner unlocks
  the process or deliberately prints/exports it.
- File counts, sizes, stable component names, filesystem timestamps, and access
  patterns remain observable.
- Receipt and several atomic temporary filenames contain ULIDs; receipt ULIDs
  persist and reveal millisecond generation time.
- `keyslot.bin` necessarily exposes salts and KDF parameters for portable
  passphrase unlocking.
- Inbox final files are intentional plaintext. Temp cleanup removes directory
  entries but cannot promise physical erasure.
- The migration requires temporary capacity for both database representations
  and, during conversion, old and new blob containers.
- Whole-bundle rollback cannot be detected without a trusted external state.
- Synthetic fixtures prove the implementation boundary, not private-corpus
  retrieval quality or production provider behavior.
