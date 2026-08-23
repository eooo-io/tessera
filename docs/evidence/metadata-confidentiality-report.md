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
| Locked scans match exposure set | Recursive path-and-byte scanners use only synthetic category sentinels, the real protected logical hash, UTF-8 case variants, public hashes, and UTF-16LE/BE encodings | `vault::metadata::tests::complete_synthetic_metadata_category_inventory_is_absent_while_locked`; `metadata_privacy::synthetic_metadata_inventory_and_confirmation_guesses_are_absent_when_locked`; `metadata_privacy::locked_visible_paths_match_the_documented_structural_allowlist` |
| Inbox and temp residue bounded | Owner-only atomic partials; abandoned inbox partials are removed; web responses and DOCX source bytes stay in bounded process pipes without application-owned named plaintext files | inbox/web/extract tests and `metadata_privacy::bundle_directories_and_files_are_owner_only`; no secure-deletion claim for intentional inbox files |
| Copy, backup, restore, cross-platform open | Keyed online backup rechecks active sessions under its writer barrier, binds copied keyslots to the source unlock state, creates a protected staging bundle, reopens and diagnoses it before publication; migrated fixture backs up, restores, unlocks, verifies, and extends its receipt chain; CI transfers a synthetic protected backup macOS to Ubuntu and a newly generated Ubuntu backup back to macOS | `recovery::tests::{backup_rechecks_sessions_after_acquiring_its_writer_barrier,backup_refuses_a_structurally_valid_swapped_keyslot_file,keyslot_mutation_cannot_launder_a_foreign_file_into_backup_binding}`; `vault::metadata::tests::legacy_migration_protects_database_manifest_and_blob_address`; `metadata_portability.rs`; `.github/workflows/ci.yml`; exact-head platform CI required below |
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
- Private registry and migration: focused tests cover malformed
  rows/markers, staging collisions, capacity and permission failures, fatal
  source diagnostics, successful and repeated conversion, logical inventory,
  row fingerprints, stale-export detection, exclusive selection against a
  competing writer, late legacy-blob conversion/retry, exclusive post-manifest
  cleanup, migrated backup/restore,
  receipt verification/continuation, and resume after all five durable
  boundaries including the retire-before-select crash window. One performance
  test is intentionally ignored in the ordinary run. Bounded error-code tests
  also prove that internal failure payloads are not rendered.
- Locked privacy and permissions: 4 integration tests passed. They inventory
  every stable path class and find zero locked-byte or path matches for the
  synthetic protected categories, real logical content hashes, and 100
  guessed-document hashes including one known-present candidate. Focused fault
  tests cover transient migration, backup, inbox, blob, and receipt paths that
  cannot all exist in one stable closed-bundle fixture; web and DOCX tests bind
  the no-named-plaintext process-pipe boundary.
- Blob protection: 17 focused unit tests cover TSB2 framing, address binding,
  cross-vault unlinkability, tamper, wrong key, deduplication, atomic writes,
  authenticated legacy conversion, orphan conversion, and unknown residue.
- CLI confirmation: the focused end-to-end test covers explicit `--yes`,
  idempotent format-v3 operation, bounded malformed-state recovery guidance,
  and absence of the marker payload and vault path from stderr.
- Portable artifact interchange: 2 local integration tests passed. Exact-head
  CI additionally exports and locally verifies a synthetic protected backup on
  macOS, opens it on Ubuntu, exports a new Ubuntu backup, and opens that backup
  on macOS.

The final candidate's full `cargo test --workspace --all-targets` run passed
372 tests with 4 intentionally ignored performance tests and no failures. The
required ignored workspace run passed all 4 ignored tests with no failures.

## Controlled performance

Host: local macOS development host, debug test profile, insecure-test Argon2id
fixture only. These are regression observations, not production benchmarks.

| Measurement | Run 1 | Run 2 | Run 3 | Observed range |
|---|---:|---:|---:|---:|
| Legacy migration | 641 ms | 650 ms | 648 ms | 1.4% |
| Legacy/protected database size | 675,840 / 688,128 bytes | same | same | 1.8% protected overhead |
| New protected vault creation, 21-sample median | 101 ms | 102 ms | 104 ms | 3.0% |
| New protected vault creation, 21-sample p95 | 104 ms | 104 ms | 109 ms | 4.8% |
| Ingest/extract/chunk 100 synthetic documents | 1,251 ms | 1,220 ms | 1,227 ms | 2.5% |
| Per-document ingest median | 12,535 us | 12,154 us | 12,471 us | 3.1% |
| Per-document ingest p95 | 14,175 us | 14,198 us | 14,351 us | 1.2% |
| Protected semantic query top 10, 100-sample median | 1,142 us | 1,139 us | 1,145 us | 0.5% |
| Protected semantic query top 10, 100-sample p95 | 1,308 us | 1,317 us | 1,307 us | 0.8% |
| Diagnostics | 25 ms | 25 ms | 25 ms | 0.0% |
| No-fault derived repair path | 169 ms | 167 ms | 167 ms | 1.2% |
| Keyed backup including destination validation | 901 ms | 887 ms | 908 ms | 2.4% |
| Restore open, diagnostics, and receipt verification | 105 ms | 105 ms | 105 ms | 0.0% |
| Source / backup bundle size | 7,133,489 / 2,502,769 bytes | same | same | online-backup compaction and WAL/page layout explain non-equivalence |

No reported controlled final-state series varied by 10% or more. Reviewer
reruns exposed 27.1% variation in the former one-shot query measurement, a
later one-shot creation observation varied by 25.9%, and independent exact-
commit ingest reruns varied by 31.2% (967/1,032/1,269 ms). The test now reports
a warmed 100-query distribution, a 21-creation distribution, and per-document
ingest median/p95 instead of selecting favorable single observations. The
fresh controlled total-ingest series is also retained above. Exact values
remain host-, filesystem-, cache-, fixture-, and build-profile-dependent.

The final pre-review state's required ignored workspace run recorded: migration
702 ms; protected-vault creation median/p95 106/110 ms across 21 samples;
100-document ingest 1,297 ms with per-document median/p95 13,015/14,924 us;
top-10 semantic query median/p95 1,188/1,330 us across 100 samples; diagnostics
25 ms; repair 171 ms; backup 961 ms; restore validation 113 ms. Those results
remain within 10% of the fresh controlled series. Independent reruns of the
prior candidate found the wider ingest range disclosed above rather than being
discarded.

## Platform CI binding

- Required base commit `e655acec9c32d9ed3b1f42ad9d9bc68e9c2a4cd4`:
  [green macOS and Ubuntu workflow](https://github.com/eooo-io/tessera/actions/runs/32565765214).
- Exact PR-head macOS, Ubuntu, and protected-bundle interchange jobs:
  [branch-filtered CI workflow](https://github.com/eooo-io/tessera/actions/workflows/ci.yml?query=branch%3Askippy%2Fissue-50-metadata-privacy), pending publication.

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
- Metadata migration is an offline upgrade. All Tessera and Guardian processes
  and legacy-vault handles must be closed first. Commits completed before
  exclusive selection are detected and retained for retry; an already-running
  pre-upgrade process that violates this precondition cannot be forced to stop
  writing an open retired inode or arbitrary filesystem residue.
- Whole-bundle rollback cannot be detected without a trusted external state.
- Synthetic fixtures prove the implementation boundary, not private-corpus
  retrieval quality or production provider behavior.
