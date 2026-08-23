# ADR-0002: Metadata Confidentiality for Vault Format v3

**Status**: Accepted for issue #50 implementation

**Date**: 2026-08-23

## Context

Vault format v2 encrypts blob payloads and receipt payloads but stores the
complete SQLite schema, metadata rows, indexes, vector pages, model registry,
and content-derived blob paths in forms readable without unlocking. A reader
who guesses exact content can compute its public BLAKE3 hash and check the blob
tree. Conversation ingestion increases the sensitivity of the exposed titles,
projects, repositories, branches, sessions, timestamps, source identities, and
relationships.

The feature must close the highest-value locked-vault exposure before v0.1
without weakening local ownership, portable copy, backup, repair, provenance,
deduplication, quarantine, policy isolation, or protected receipts. The current
schema spans 21 migrations, sqlite-vec virtual tables, and hundreds of direct
queries across the core library.

## Decision

Tessera vault format v3 will:

1. encrypt and authenticate the complete SQLite database and journal pages with
   SQLCipher using a raw 256-bit key derived from the vault DEK under
   `tessera database encryption key v1`;
2. force non-transaction SQLite temporary storage to memory and key every
   primary, reopened, backup, diagnostic, and migration connection before its
   first database read;
3. retain the plaintext BLAKE3 content hash as protected logical integrity,
   deduplication, provenance, and receipt evidence;
4. derive a separate key under `tessera blob address key v1` and use a keyed
   BLAKE3 token as the only locked-visible blob path;
5. introduce blob container v2, authenticated against its opaque address, so
   tampering, cross-vault copying, and path relocation fail closed;
6. reduce the public manifest to format and pre-unlock portability parameters,
   moving creation time, embedding model registry, and private legacy extension
   fields into an encrypted `vault_metadata` table;
7. require explicit owner-confirmed migration from v1/v2, with an exclusive
   marker, authenticated blob conversion, plaintext WAL checkpoint, separately
   staged SQLCipher export, complete validation, fixed same-directory selection,
   protected legacy-receipt conversion, resumable phases, and cleanup only
   after format-v3 commit;
8. avoid named web-response body files, clean bounded inbox partial residue,
   use private temporary paths only when an external tool requires a filename,
   and explicitly enforce owner-only directory and file modes on Unix;
9. preserve existing logical database schema and unlocked domain behavior
   except for the encrypted metadata registry and connection keying.

The detailed exposure inventory and claim boundary are normative in
`docs/metadata-confidentiality-threat-model.md`. Binary and database layouts are
normative in `spec/vault-format.md`.

## Why SQLCipher is required here

Application-level encryption is attractive when a small number of independent
values need protection. Tessera's sensitive metadata is neither small nor
independent. It includes table and index structure, joins, foreign keys,
vectors, policy JSON, receipt indexes, conversation graphs, timestamps,
errors, source relationships, and model registries. Encrypting selected text
columns would still expose relationship topology and vectors, break indexed
queries, or require a broad storage rewrite in almost every module.

SQLCipher preserves the ordinary unlocked SQLite API while protecting database
and journal pages. The repository already uses bundled `rusqlite`; its reviewed
feature set supports a bundled SQLCipher build with vendored OpenSSL on the
required platforms. SQLCipher is open source and produces a documented SQLite
derivative, not a proprietary Tessera container. Primary documentation states
that standard plaintext databases must be converted with `sqlcipher_export`
rather than `rekey`, and that file-backed non-journal temporary stores require
separate control. The implementation and tests enforce both points.

## Why keyed paths retain a separate logical hash

Replacing the logical hash throughout the domain would change protected
receipt and provenance meaning. Random blob identifiers would preserve privacy
but weaken deterministic deduplication and require a second lookup map. Tessera
therefore separates identities:

- the logical plaintext hash stays protected and continues to prove what bytes
  the owner decrypted;
- the filesystem address is a vault-specific keyed token over that hash and
  cannot be computed from guessed content without the vault key.

This preserves existing exact-content evidence without publishing an
exact-content verifier.

## Migration authority and atomicity

Ordinary open does not silently rewrite a legacy vault. The owner runs an
explicit confirmed migration after making a verified offline copy. The
migration refuses active Guardian sessions and fatal source diagnostics.

Each blob replacement is authenticated and synced before the legacy path is
removed. The database replacement is written and validated separately. The
last plaintext authoritative database remains at a fixed retired path until
the protected database reopens with its key, its schema and logical inventory
match, all blob containers authenticate, and the public manifest commits v3.
An interruption marker blocks ordinary operation and permits only distrustful
resumption. No phase relies solely on the marker's claim.

This boundary is not destructive in the issue #50 sense: the last valid state
is retained until its replacement validates, no logical data is dropped, and
copy/backup/restore remain supported. Old binaries cannot open format v3, which
is the intended meaning of the major format version. An owner can preserve an
offline v2 copy before migrating; Tessera does not leave a plaintext rollback
copy inside a successfully migrated vault.

## Consequences

### Benefits

- The full current and future schema inherits locked-at-rest confidentiality
  without requiring every query author to remember field encryption.
- WAL pages, indexes, vectors, errors, source metadata, and model registry are
  protected under the same database boundary.
- Public guessed-document confirmation through blob paths is removed while
  integrity, deduplication, receipts, and provenance retain their semantics.
- Existing SQL queries, transactions, foreign keys, sqlite-vec use,
  diagnostics, repair, and online backup remain available after unlock.
- Database and blob formats remain portable and independently documented.

### Costs and risks

- The binary and build chain now include SQLCipher and OpenSSL. macOS and
  Ubuntu CI, exact dependency pinning, and cross-platform backup/restore tests
  become release gates.
- Every database connection must be keyed correctly and early. A missed
  connection is a blocking defect; tests enumerate all connection paths.
- Page encryption and keyed blob conversion add storage, migration, query, and
  repair cost that must be measured on controlled fixtures.
- Migration rewrites every blob container and the database. It may require
  temporary free space approximately equal to the database plus one blob at a
  time, and it can take linear time in total encrypted content.
- SQLCipher protects persistent pages, not plaintext in unlocked process
  memory, query results, or application pipes.

## Alternatives rejected

### Application-level sensitive-column encryption

Rejected because the metadata graph, indexes, vectors, schema, and hundreds of
queries make selective encryption incomplete or equivalent to a broad database
rewrite. Equality tokens would reintroduce confirmation and relationship
leakage unless individually threat-modeled.

### Encrypted snapshot with plaintext runtime database

Rejected because materializing SQLite to a named plaintext working file creates
forensic residue and an ambiguous crash boundary.

### Custom encrypted SQLite VFS

Rejected because it would create a new cryptographic storage subsystem with
greater pager, journal, concurrency, and platform risk than the selected
reviewed dependency.

### Random per-blob identifiers

Rejected because they either lose deterministic deduplication or require a new
mapping authority. Keyed deterministic paths meet the confirmation objective
with less domain change.

### Public model registry or second encrypted manifest

Rejected because model names and versions are explicitly sensitive and the
encrypted database is already the portable metadata authority. A second
protected manifest would create reconciliation and recovery complexity.

## Explicit residual risks

- File and directory names that define the bundle structure, ciphertext count
  and size, filesystem times, allocation behavior, opaque receipt ids, and
  migration phase remain visible.
- Intentional inbox files remain plaintext until ingestion. Tessera minimizes
  partial copies but cannot make plaintext staging encrypted without changing
  the owner workflow and vault boundary.
- A same-user process may inspect unlocked memory, handles, pipes, or owner
  output. Unix permissions protect against other accounts, not the same uid.
- Complete valid bundle rollback is not detectable without an external trusted
  head.
- File removal is not a secure-deletion guarantee on journaling filesystems,
  snapshots, SSD controllers, or backup/sync providers.
- Availability against a vault-write attacker is not provided. Authentication
  detects damage; it does not prevent deletion.

These risks are accepted as the bounded v0.1 residual set because they do not
preserve the issue's exact-content confirmation flaw, require a destructive
format choice, or compromise portable ownership and repair. Any implementation
finding outside this set reopens the decision and requires owner review.

## Validation obligations

- Synthetic sentinel and path scans cover every protected metadata category
  and every bundle, journal, backup, staging, and migration path.
- At least 100 public candidate hashes, including one present document, fail to
  match locked bytes or paths.
- Wrong key, wrong vault, plaintext-at-v3-path, malformed, truncated, tampered,
  relocated, and unsupported fixtures fail closed.
- Every durable migration phase is interrupted and resumed, with identical
  logical inventories and one authoritative state.
- Copy, backup, restore, unlock, query, receipt verification and continuation,
  diagnostics, orphan handling, and repair pass for new and migrated vaults.
- Storage, migration, query, backup, restore, diagnostic, and repair costs are
  measured and reported with variance.
- An independent reviewer challenges inventory completeness, confirmation
  resistance, key separation, migration atomicity, portability, data loss,
  temporary files, and claim boundaries on the exact final commit.
- macOS and Ubuntu CI pass on that exact pushed commit.

## References

- [SQLCipher security design](https://www.zetetic.net/sqlcipher/design/)
- [SQLCipher API and export guidance](https://www.zetetic.net/sqlcipher/sqlcipher-api/)
- [SQLite temporary files](https://www.sqlite.org/tempfiles.html)
- [SQLite secure-delete limitations](https://www.sqlite.org/pragma.html#pragma_secure_delete)
- [rusqlite 0.31 features](https://github.com/rusqlite/rusqlite/blob/v0.31.0/Cargo.toml)
