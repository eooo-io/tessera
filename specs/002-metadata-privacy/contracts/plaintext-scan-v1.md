# Contract: Synthetic Locked-Vault Plaintext Scan

## Fixture

The scanner builds a disposable vault with unique synthetic sentinels for the
following categories. Schema-constrained enums such as sensitivity use an
allowed token attached to a uniquely identified synthetic row rather than an
invalid out-of-domain value:

- manifest-private fields and model registry;
- spaces, filenames, titles, tags, sensitivity, and timestamps;
- source URLs and web staging;
- projects, repositories, working directories, branches, commits, sessions,
  source-file identities, and model names;
- pairings, purposes, agent names, OAuth metadata, and live sessions;
- processing and ingestion error metadata;
- receipt index and protected receipt payload fields;
- conversation archive, node, part, attachment, provenance, and run metadata;
- original, derived, summary, image, and conversation blob content and hashes;
- synthetic representatives for database, blob, inbox, backup, and temporary
  path classes. Focused fault tests exercise each real interrupted boundary;
  web and DOCX response/source bytes use bounded process pipes and create no
  application-owned plaintext working file.

The fixture MUST NOT read, copy, enumerate, or derive sentinels from an owner
vault or private corpus.

## Scan

- Close every vault and database handle before the primary locked scan. A
  separate raw WAL assertion runs while a connection holds encrypted pages.
- Recursively inspect raw file bytes and relative path components.
- Search exact sentinel bytes, their lowercase and uppercase encodings, public
  BLAKE3 hashes, and category-specific normalized forms.
- Inventory every file, directory, non-empty durable-file size, permission mode
  where supported, and recognized container class. Bind interrupted residue to
  the focused blob, receipt, inbox, migration, and backup tests, and bind the
  no-named-plaintext external-tool boundary to web and DOCX process-pipe tests.
- Permit only intentional inbox plaintext created by the fixture and the exact
  structural exposure listed in the threat model.
- Treat any unexpected match as a test failure with a synthetic category and
  relative path, never with secret material.

## Guessed-content confirmation

For at least 100 deterministic candidate documents, the scanner computes each
public BLAKE3 hash and every legacy shard path. None may match a path component
or raw byte sequence in a protected locked bundle. The known-present candidate
must be indistinguishable from absent candidates without the vault key.

## Output

The report contains aggregate counts, category labels, allowed structural
classes, and timing; relative synthetic paths appear only in safe test failure
messages. It MUST NOT contain passphrases,
keys, private content, raw protected rows, bearer tokens, or sensitive receipt
payloads.
