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
| Copy, backup, restore, cross-platform open | Keyed online backup binds copied keyslots to the source unlock state, creates a protected staging bundle, reopens and diagnoses it before publication; migrated fixture backs up, restores, unlocks, verifies, and extends its receipt chain; CI transfers a synthetic protected backup macOS to Ubuntu and a newly generated Ubuntu backup back to macOS | `recovery::tests::backup_refuses_a_structurally_valid_swapped_keyslot_file`; `vault::metadata::tests::legacy_migration_protects_database_manifest_and_blob_address`; `metadata_portability.rs`; `.github/workflows/ci.yml`; exact-head platform CI required below |
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
  competing writer, migrated backup/restore,
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
368 tests with 4 intentionally ignored performance tests and no failures. The
required ignored workspace run passed all 4 ignored tests with no failures.

## Controlled performance

Host: local macOS development host, debug test profile, insecure-test Argon2id
fixture only. These are regression observations, not production benchmarks.

| Measurement | Run 1 | Run 2 | Run 3 | Observed range |
|---|---:|---:|---:|---:|
| Legacy migration | 656 ms | 659 ms | 644 ms | 2.3% |
| Legacy/protected database size | 675,840 / 688,128 bytes | same | same | 1.8% protected overhead |
| New protected vault creation, 21-sample median | 102 ms | 102 ms | 103 ms | 1.0% |
| New protected vault creation, 21-sample p95 | 118 ms | 108 ms | 109 ms | 9.3% |
| Ingest/extract/chunk 100 synthetic documents | 1,263 ms | 1,236 ms | 1,262 ms | 2.2% |
| Protected semantic query top 10, 100-sample median | 1,160 us | 1,175 us | 1,171 us | 1.3% |
| Protected semantic query top 10, 100-sample p95 | 1,333 us | 1,334 us | 1,336 us | 0.2% |
| Diagnostics | 25 ms | 25 ms | 25 ms | 0.0% |
| No-fault derived repair path | 167 ms | 166 ms | 170 ms | 2.4% |
| Keyed backup including destination validation | 901 ms | 897 ms | 894 ms | 0.8% |
| Restore open, diagnostics, and receipt verification | 105 ms | 107 ms | 105 ms | 1.9% |
| Source / backup bundle size | 7,133,489 / 2,502,769 bytes | same | same | WAL and derived state explain non-equivalence |

No reported controlled final-state series varied by 10% or more. Reviewer
reruns exposed 27.1% variation in the former one-shot query measurement, and a
later one-shot creation observation varied by 25.9%. The test now reports a
warmed 100-query distribution and a 21-creation distribution instead of
selecting favorable single observations; median and p95 are retained. Exact
values remain host-, filesystem-, cache-, fixture-, and build-profile-dependent.

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
- Whole-bundle rollback cannot be detected without a trusted external state.
- Synthetic fixtures prove the implementation boundary, not private-corpus
  retrieval quality or production provider behavior.
