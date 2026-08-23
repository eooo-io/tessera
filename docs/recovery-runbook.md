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
component names, classification, counts, and recovery actions, never content,
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

## Legacy metadata migration

Make a complete offline bundle copy, stop Guardian writers, and then run:

```bash
tessera --vault /path/V.tessera metadata migrate --yes
```

Ordinary open refuses format-v1/v2 and in-progress migration state. Migration
first checks database integrity and active sessions, then authenticates legacy
blobs, checkpoints the plaintext WAL, prepares and validates a complete
SQLCipher export, and retains `.vault.db.v2.retired` until the protected
database and minimized format-v3 manifest reopen successfully. Rerun the same
command after interruption. Do not rename or delete `.metadata-migration-v3`,
`.vault.db.v3.prepared`, or `.vault.db.v2.retired` by hand.

The conversion temporarily requires space for both database representations
and converted blob containers. A capacity or permission failure retains the
last validated authority and returns non-zero. Cleanup removes legacy directory
entries only after commit. Filesystem journals, snapshots, SSD translation
layers, and provider retention can preserve deleted plaintext; Tessera makes no
secure-deletion claim. Legacy receipt JSON, when present, is authenticated and
converted inside the same whole-bundle migration before format v3 commits.

## Consistent backup

```bash
tessera --vault /path/V.tessera backup /backups/V-2026-07-12.tessera
```

The destination must not exist and must be outside the source bundle. Tessera:

1. diagnoses the source and refuses fatal findings;
2. refuses while an unexpired Guardian session is active;
3. takes a dedicated SQLCipher/SQLite `BEGIN IMMEDIATE` writer barrier;
4. copies the manifest, keyslots, immutable encrypted blobs, finalized receipts,
   and inbox state into a new sibling staging bundle;
5. uses the keyed SQLite online backup API for `vault.db` instead of copying
   WAL/SHM files;
6. requires the copied keyslot bytes to match the keyslot state that unlocked
   the source, reopens the staging bundle with that source DEK, and runs the
   same integrity and receipt checks;
7. renames the verified staging bundle into place and syncs its parent
   directory.

If copying or destination verification fails, Tessera removes the private
staging directory and does not publish a destination bundle. Directory-entry
cleanup is not a secure-deletion guarantee.

Backup refuses a structurally valid keyslot file swapped after source unlock.
This prevents the library API from reporting success for a destination whose
copied unlock methods are unrelated to the copied encrypted data. The backup
still cannot prove that an owner remembers any particular passphrase; restore
validation with the intended passphrase remains an owner operation.

Format-v2 receipt containers are encrypted and owner-authenticated, but they
still depend on the copied `keyslot.bin` and DEK. Losing every usable keyslot
loses the receipts as well as the encrypted source evidence. A logical receipt
export is plaintext and is not a substitute for a restorable vault backup.

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
| legacy receipt migration interruption | before the index commit, the verified legacy chain remains authoritative; after commit, restart completes prepared-file renames and legacy deletion | rerun `tessera receipts migrate --yes`, then `tessera receipts verify`; do not mix or hand-edit `.json` and `.trc` files |
| receipt migration while Guardian is active | migration refuses before writing replacements | close or revoke active Guardian sessions, make an offline bundle copy, then retry |
| metadata migration interruption | fixed prepared/retired paths and a content-free marker retain one validated authority | rerun `tessera metadata migrate --yes`; do not operate on or hand-edit the bundle |
| metadata migration capacity/permission failure | the last validated legacy database remains authoritative until the protected replacement validates | restore capacity/permissions and rerun; preserve the offline copy |
| malformed marker, protected database, or unsupported format | ordinary open and migration fail closed without creating an empty database | preserve the bundle and restore a verified backup or investigate the fixed migration files |
| lost last usable keyslot | protected receipts and encrypted sources are unrecoverable | restore a backup with a working keyslot; Tessera cannot regenerate the DEK |
| disk full/permission failure | operation returns non-zero; completed source blobs are not deleted | restore capacity/permissions, diagnose, retry |
| missing/tampered original blob | fatal AEAD/content-address failure | restore backup; no fabricated repair exists |
| missing derived blob/chunk/vector | repairable if originals authenticate | explicit derived rebuild/model reindex |
| duplicate map or FK damage | schema constraints prevent normal creation; diagnostic failure is fatal | preserve bundle and restore backup |
| stale/missing WAL/SHM after ad-hoc copy | unsupported copy boundary | restore a Tessera-created backup |
| partial bundle copy | open/diag fails loudly on missing manifest, keyslot, DB, or blob | repeat from verified backup |
| schema migration interruption | each migration is transactional and recorded only after commit | reopen to retry; preserve bundle if migration remains failing |
| model corruption | pre-load SHA-256 verification fails | verified online/offline reinstall; active index remains |

Receipt verification distinguishes malformed containers, unauthenticated
legacy storage, cryptographic authentication failure, and internal chain
breakage. All are owner-action failures; none authorizes automatic evidence
rewriting.

The recovery tests run on the local macOS gate and the repository Linux CI
runner. Exact-head CI also uploads a synthetic macOS-created protected backup,
opens and verifies it on Ubuntu, then uploads an Ubuntu-created backup and
opens and verifies it on macOS. This proves the documented bundle interchange
for the tested formats; it does not pretend that every filesystem, power-loss
mode, or disk firmware has been physically fault-tested.

The exact scenario-to-test ledger is
[`evidence/recovery-fault-matrix.md`](evidence/recovery-fault-matrix.md).
