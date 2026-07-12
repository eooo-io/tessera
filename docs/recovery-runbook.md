# Crash consistency, backup, restore, and repair boundaries

Tessera recovery begins with a boring rule: authenticated originals are the
authority. Derived text, chunks, summaries, and vectors may be rebuilt by an
owner action; missing keys or corrupted source ciphertext cannot be invented.

## Diagnose first

```bash
tessera --vault /path/V.tessera diag
tessera --vault /path/V.tessera diag --json > integrity-report.json
```

The JSON schema identifier is `tessera.integrity-report.v1`. It reports only
component names, classification, counts, and recovery actions—never content,
passphrases, keys, decrypted snippets, queries, or secret credentials.

- `ok`: the checked invariant holds.
- `repairable`: authenticated source evidence remains; an explicit derived
  rebuild or model reindex may recover service.
- `fatal`: source authentication, database referential integrity, lens/session
  policy, or receipt-chain evidence failed. Restore a verified backup and keep
  the damaged bundle for investigation.

Diagnostics do not delete, rewrite, or silently bless corrupt evidence.

## Owner-approved derived rebuild

Only after reviewing a repairable report:

```bash
tessera --vault /path/V.tessera repair-derived --yes
```

The command first authenticates every referenced original and refuses any
fatal finding or active Guardian session. It moves live artifacts back to
`pending`, clears only derived text/chunk/summary/vector database rows, and
recreates text, chunks, and summaries from the original encrypted blobs. It
does not delete old blob files, rewrite receipts, change source hashes or
artifact ids, or promote rebuilt items. The owner must run `tessera review` and
then `tessera model reindex` before restored content can be disclosed again.

## Consistent backup

```bash
tessera --vault /path/V.tessera backup /backups/V-2026-07-12.tessera
```

The destination must not exist and must be outside the source bundle. Tessera:

1. diagnoses the source and refuses fatal findings;
2. refuses while an unexpired Guardian session is active;
3. takes a dedicated SQLite `BEGIN IMMEDIATE` writer barrier;
4. copies the manifest, keyslots, immutable encrypted blobs, finalized receipts,
   and inbox state into a new sibling staging bundle;
5. uses SQLite online backup for `vault.db` instead of copying WAL/SHM files;
6. renames the completed staging bundle into place;
7. reopens it with the supplied key and runs the same integrity/receipt checks.

The barrier lets an idle Guardian remain running but blocks new writes briefly.
An active disclosure session fails loudly instead of producing a fuzzy snapshot.
Never use Finder, `cp -R`, or archive software against a live bundle and assume
that `vault.db`, `vault.db-wal`, receipts, and blobs describe the same instant.

## Restore on a new path or host

Copy the completed backup bundle, then run `diag` before starting Guardian.
Embedding assets are host-local; provision the exact model using
[`model-supply-chain.md`](model-supply-chain.md). Receipt verification and
artifact/blob identity do not depend on the original filesystem path.

```bash
tessera --vault /restore/V.tessera diag --json
tessera model install --source /media/verified/all-MiniLM-L6-v2  # if absent
tessera --vault /restore/V.tessera model reindex-status
```

On Linux, the default model root is
`${XDG_DATA_HOME:-~/.local/share}/tessera/models`; on macOS it is
`~/Library/Application Support/tessera/models`.

## Failure matrix

| Failure | Durable boundary | Owner action |
|---|---|---|
| inbox copy permission/disk failure | source file remains; incomplete target is not processed | fix storage/permissions, remove only the visibly partial staged copy, retry |
| encrypt crash | blob writes use same-directory temporary file + rename; inbox remains | retry processing; orphan ciphertext is never auto-deleted |
| extract/chunk/embed failure | encrypted original and pending artifact remain; processing error is durable | review error, retry stage or approve derived rebuild |
| promotion failure | review batch transaction rolls back | correct the blocked item and retry review |
| receipt finalization crash | prepared file + committed DB index recovery is deterministic | run `diag`/receipt verify; never edit the chain |
| disk full/permission failure | operation returns non-zero; completed source blobs are not deleted | restore capacity/permissions, diagnose, retry |
| missing/tampered original blob | fatal AEAD/content-address failure | restore backup; no fabricated repair exists |
| missing derived blob/chunk/vector | repairable if originals authenticate | explicit derived rebuild/model reindex |
| duplicate map or FK damage | schema constraints prevent normal creation; diagnostic failure is fatal | preserve bundle and restore backup |
| stale/missing WAL/SHM after ad-hoc copy | unsupported copy boundary | restore a Tessera-created backup |
| partial bundle copy | open/diag fails loudly on missing manifest, keyslot, DB, or blob | repeat from verified backup |
| schema migration interruption | each migration is transactional and recorded only after commit | reopen to retry; preserve bundle if migration remains failing |
| model corruption | pre-load SHA-256 verification fails | verified online/offline reinstall; active index remains |

The recovery tests run on the local macOS gate and the repository Linux CI
runner. Platform success means the same deterministic fixtures pass on both;
it does not pretend that every filesystem, power-loss mode, or disk firmware has
been physically fault-tested.

The exact scenario-to-test ledger is
[`evidence/recovery-fault-matrix.md`](evidence/recovery-fault-matrix.md).
