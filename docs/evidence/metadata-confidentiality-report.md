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
| Copy, backup, restore, cross-platform open | Keyed online backup creates a protected destination; migrated fixture backs up, restores, unlocks, verifies, and extends its receipt chain | `vault::metadata::tests::legacy_migration_protects_database_manifest_and_blob_address`; `recovery::tests::backup_restores_same_source_identity_at_new_path`; exact-head platform CI required below |
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
| `receipts/<receipt-id>.trc` | Count, opaque ids, container sizes, timestamps | Receipt content, chain, sessions, pairing, policy, and disclosures remain protected |
| `inbox/` final staged files | Names and plaintext content by owner intent | Explicitly outside locked-vault confidentiality until ingestion |
| Partial, prepared, and migration files | Fixed structural names and current existence | Owner-only; content is protected except retained legacy authority during explicit migration |
| Backup/sync copies | Same structural, size, timestamp, and traffic exposure as source | Provider may retain old plaintext legacy copies or deleted blocks; Tessera cannot revoke provider snapshots |

The implementation does not protect an unlocked process from same-user
inspection or malware, hide whole-bundle rollback, conceal filesystem traffic,
or guarantee forensic deletion on journals, snapshots, SSDs, or providers.

## Test topology and current aggregates

- Database protection: 11 focused tests passed, covering key installation,
  wrong key, plaintext database, truncation, page tamper, locked byte scan, WAL,
  foreign keys, temporary memory, and migrations.
- Private registry and migration: 9 focused tests passed and 1 performance test
  was intentionally ignored in the ordinary run. The tests cover malformed
  rows/markers, active sessions, successful and repeated conversion, logical
  inventory, migrated backup/restore, receipt verification/continuation, and
  resume after all four durable boundaries.
- Locked privacy and permissions: 3 integration tests passed, with zero matches
  for seven protected category sentinels, the real logical content hash, and
  100 guessed-document hashes.
- Blob protection: 17 focused unit tests cover TSB2 framing, address binding,
  cross-vault unlinkability, tamper, wrong key, deduplication, atomic writes,
  authenticated legacy conversion, orphan conversion, and unknown residue.
- CLI confirmation: 1 focused end-to-end test passed for explicit `--yes` and
  idempotent format-v3 operation.

The final pre-review `cargo test --workspace --all-targets` run passed 352 tests
with 4 intentionally ignored performance tests and no failures. The required
ignored workspace run then passed all 4 ignored tests with no failures.

## Controlled performance

Host: local macOS development host, debug test profile, insecure-test Argon2id
fixture only. These are regression observations, not production benchmarks.

| Measurement | Run 1 | Run 2 | Variance |
|---|---:|---:|---:|
| Legacy migration, controlled warm rerun | 522 ms | 529 ms | 1.3% |
| Legacy/protected database size | 675,840 / 688,128 bytes | same | 1.8% protected overhead |
| New protected vault creation | 123 ms | 122 ms | 0.8% |
| Ingest/extract/chunk 100 synthetic documents | 1,358 ms | 1,312 ms | 3.5% |
| Protected semantic query, top 10 | 1,602 us | 1,654 us | 3.2% |
| Diagnostics | 26 ms | 25 ms | 4.0% |
| No-fault derived repair path | 166 ms | 166 ms | 0.0% |
| Keyed backup | 817 ms | 854 ms | 4.5% |
| Source / backup bundle size | 7,133,489 / 2,502,769 bytes | same | WAL and derived state explain non-equivalence |

The first two migration observations after rebuilding were 723 ms and 606 ms,
a material 19.3% spread. Three immediate controlled reruns were 522, 529, and
528 ms, a 1.3% range across the reported pair; the cold-cache outliers are not
discarded. Exact values are host-, filesystem-, cache-, fixture-, and
build-profile-dependent.

The final required ignored-suite observation remained inside that controlled
range: migration 538 ms; protected vault creation 110 ms; 100-document ingest
1,274 ms; top-10 semantic query 1,601 us; diagnostics 25 ms; repair 167 ms;
backup 831 ms. It measured the same database and bundle byte counts shown
above.

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
- `keyslot.bin` necessarily exposes salts and KDF parameters for portable
  passphrase unlocking.
- Inbox final files are intentional plaintext. Temp cleanup removes directory
  entries but cannot promise physical erasure.
- The migration requires temporary capacity for both database representations
  and, during conversion, old and new blob containers.
- Whole-bundle rollback cannot be detected without a trusted external state.
- Synthetic fixtures prove the implementation boundary, not private-corpus
  retrieval quality or production provider behavior.
