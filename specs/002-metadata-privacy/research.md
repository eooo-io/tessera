# Research: Locked-Vault Metadata Privacy

## Decision 1: Protect the complete SQLite store with SQLCipher

**Decision**: Use the existing `rusqlite` integration with its bundled
SQLCipher and vendored OpenSSL feature. Derive a 256-bit high-entropy database secret from
the vault data key with the context `tessera database encryption key v1`. Key
every connection before its first database read, verify the key immediately,
keep write-ahead logging, and force non-transaction temporary stores to memory.

**Rationale**: The baseline schema has 21 migrations and hundreds of direct
queries across artifacts, spaces, tags, lenses, sessions, OAuth, receipts,
errors, vectors, web sources, images, and conversation provenance. Sensitive
values participate in joins, indexes, constraints, virtual tables, recovery,
and diagnostics. Application-level column envelopes would either leave index
and relationship leakage or require a broad query and schema rewrite with a
large chance of inconsistent protection. Page encryption protects the schema,
rows, indexes, vectors, rollback pages, and WAL pages while preserving the
existing unlocked relational behavior and repair tools.

SQLCipher documents per-page AES-256-CBC encryption, random page IVs, and
HMAC-SHA512 page authentication. It also documents encryption of rollback,
WAL, and statement-journal pages, while warning that other SQLite temporary
stores must be memory-backed. The exact bundled `libsqlite3-sys` build used by
this repository compiles SQLCipher with `SQLITE_TEMP_STORE=2`; Tessera will
also set `temp_store=MEMORY` per connection and verify the effective value.

**Alternatives considered**:

- Application-level encryption of selected columns was rejected because it
  cannot coherently protect schema names, indexes, vectors, foreign-key
  relationships, and new tables without a pervasive storage-layer rewrite.
- A custom encrypted database container materialized to a plaintext temporary
  SQLite file was rejected because it creates recoverable working copies and
  weak crash semantics.
- A custom encrypted SQLite VFS was rejected as a new cryptographic storage
  subsystem with substantially higher correctness and maintenance risk.

**Primary sources**:

- [SQLCipher design](https://www.zetetic.net/sqlcipher/design/)
- [SQLCipher API and `sqlcipher_export`](https://www.zetetic.net/sqlcipher/sqlcipher-api/)
- [`rusqlite` 0.31 feature definitions](https://github.com/rusqlite/rusqlite/blob/v0.31.0/Cargo.toml)
- [`libsqlite3-sys` 0.28 feature definitions](https://github.com/rusqlite/rusqlite/blob/v0.31.0/libsqlite3-sys/Cargo.toml)

## Decision 2: Use a keyed filesystem address and retain the logical content hash

**Decision**: Preserve the lowercase BLAKE3 plaintext hash as the unlocked
logical `BlobHash` used for integrity, deduplication, provenance, and protected
receipt evidence. Derive a separate blob-address key with the context
`tessera blob address key v1` and expose only a keyed BLAKE3 token in the blob
path. Introduce a versioned blob container whose authentication data binds its
opaque address. The public hash remains only inside encrypted SQLite pages and
protected receipt payloads.

**Rationale**: A keyed path removes public guessed-document confirmation while
preserving the exact logical hashes and deduplication semantics already relied
on by receipts, conversations, diagnostics, and repair. Keeping these two
identities distinct avoids rewriting receipt meaning and lets an unlocked
owner continue to verify decrypted content against its original hash.

**Alternatives considered**:

- A random per-write identifier was rejected because it weakens deterministic
  deduplication and requires another mapping for every blob.
- Using the plaintext hash directly as the encryption key or address was
  rejected because guessed content would still be confirmable.
- Replacing the logical hash everywhere with a keyed hash was rejected because
  it would change receipt and provenance semantics and complicate integrity
  review without improving locked-path confidentiality.

## Decision 3: Minimize the public manifest

**Decision**: Format v3 keeps only the format version and public cryptographic
parameters needed to recognize and unlock the portable bundle. Vault creation
time, embedding model registry, and unknown private extension fields move into
an encrypted `vault_metadata` table. New code reads and updates the model
registry through that table.

**Rationale**: Model names and timestamps are explicitly within issue #50.
They are not required before keyslot unlock, so leaving them public would be an
avoidable exception. Storing them in the encrypted database keeps copy and
repair behavior ordinary.

**Alternatives considered**:

- Leaving the registry in JSON was rejected as a direct acceptance gap.
- Adding a second encrypted manifest file was rejected because the database is
  already the protected portable metadata store and a second authority would
  create reconciliation risk.

## Decision 4: Use an explicit recoverable format migration

**Decision**: Add an owner-confirmed migration command. It refuses active
Guardian sessions, records a fixed non-sensitive migration marker, converts
and authenticates each legacy blob before removing its old path, checkpoints
the plaintext database, exports it to a separately keyed staged database,
validates the complete replacement, atomically selects the protected database,
minimizes the manifest, and only then removes retired plaintext files. Re-entry
resumes from validated files and phases; ordinary vault open refuses a legacy
or in-progress bundle.

**Rationale**: Conversion needs exclusive intent, temporary disk capacity, and
clear recovery behavior. A fixed marker plus versioned files makes the
authoritative state explicit without storing secrets. The last authoritative
database remains until the replacement passes key, schema, and integrity
validation. SQLCipher explicitly recommends `sqlcipher_export` to encrypt a
standard SQLite database instead of `rekey`.

**Alternatives considered**:

- Silent automatic migration on ordinary open was rejected because a
  high-risk persistent-format rewrite needs explicit owner intent and useful
  disk-space errors.
- In-place rekey was rejected because SQLCipher states that it does not encrypt
  a standard plaintext database.
- Copying a live WAL database byte-for-byte was rejected because it can omit
  committed WAL state and is not the repository's supported backup boundary.

## Decision 5: Keep temporary content out of named working files where practical

**Decision**: Capture bounded web response bytes through a pipe rather than a
named body file. Use private runtime directories and restrictive files only
where an external program requires a path. Clean abandoned inbox partials at a
defined recovery boundary, strip all group/other permissions from bundle
directories and regular files on Unix without restoring owner bits that an
operator deliberately removed, and document that same-user malware,
snapshots, SSD remapping, journaling filesystems, and providers can defeat
deletion expectations.

**Rationale**: Avoiding a file is stronger than deleting one. Permissions
protect against other local accounts where supported but do not protect from a
malicious process running as the owner. Recovery must remove operational
residue without pretending to provide forensic erasure.

**Primary sources**:

- [SQLite temporary files](https://www.sqlite.org/tempfiles.html)
- [SQLite `secure_delete` limitations](https://www.sqlite.org/pragma.html#pragma_secure_delete)

## Decision 6: Residual locked-vault exposure budget

The v0.1 locked bundle may reveal only:

- the existence and public format version of a Tessera vault;
- KDF and cipher algorithm parameters needed for portable unlock;
- the number, sizes, directory topology, and modification times of ciphertext
  database, blob, receipt, keyslot, and migration files;
- opaque keyed blob path tokens and receipt identifiers;
- SQLite and SQLCipher non-content framing required by their formats;
- intentionally staged plaintext inbox files and their names until ingestion;
- operating-system, filesystem, snapshot, SSD, and provider observations that
  Tessera cannot suppress locally.

No filename, title, space, tag, sensitivity, source URL, project, repository,
branch, session, pairing, error, receipt index, conversation field, model
registry, plaintext content hash, or protected synthetic sentinel may appear
outside those explicit boundaries.
