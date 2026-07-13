# Conversation ingestion runs v1

The source-neutral ingestion API is `tessera_core::conversation::ingest`.
Source adapters implement `ConversationSourceParser`; they discover and
normalize source records but never write vault state or decide deduplication,
replacement, quarantine, retry, or checkpoint semantics.

## Run state machine

A run authenticates one immutable encrypted source artifact version and target
space, records the source product/hash and exact parser/normalizer versions,
then creates one ordered item per discovered source conversation.

Run states are:

- `running` while an attempt owns the checkpoint;
- `interrupted` when one or more items remain `pending` after an intentional
  processing limit or process interruption;
- `completed` when every item has a terminal outcome, including explicitly
  quarantined or failed siblings; and
- `failed` when the parser cannot enumerate the archive safely at all.

Item states are `pending`, `imported`, `unchanged`, `updated`, `quarantined`,
or `failed`. The run ledger stores content-free counts, the next pending
ordinal, attempt/retry counts, safe structural error codes, persisted
conversation/derivation identities, and any prior conversation identity.

`tessera conversation runs` lists run summaries. `tessera conversation show
<run-id>` reports every item and the resume/correction action; `--json` emits
the same machine-readable report without source content.

## Idempotency and replacement

The current logical head is keyed by source product plus source-native
conversation id.

- Identical content under identical parser/normalizer versions is `unchanged`;
  no conversation, source-record, node, part, derived-text, chunk, or embedding
  row is duplicated.
- Logical heads are vault-wide. If the current identity already belongs to a
  different target space, the item fails with `target_space_conflict`; Tessera
  does not duplicate, move, or reclassify the existing artifact implicitly.
- A superset archive compares every discovered source id and persists only new
  or changed conversations. The encrypted normal-form archive still represents
  all valid discovered conversations.
- Changed source content creates an `updated` pending artifact and an explicit
  `corrected_source` replacement edge to the prior persisted conversation.
- A parser or normalizer upgrade creates a new derivation lineage and an
  explicit `parser_upgrade` or `normalizer_upgrade` edge. Prior source and
  provenance rows remain immutable.
- A resumed run reparses the authenticated source and verifies target space,
  ordinal, source-id, and digest equality before continuing. Drift fails closed
  without changing the interrupted status or retry counter.
- A fresh restart is also safe: committed heads are `unchanged`, only the
  remaining delta is persisted, and the older checkpoint may later reconcile
  those heads without duplicating graph or chunk rows.
- Conversation persistence is idempotent at the exact archive,
  conversation, canonical-blob, renderer, and chunker configuration. A process
  that dies after committing the conversation but before updating the run
  ledger can reconcile the committed derivation on retry.

## Format drift and error privacy

Adapters return per-conversation structural issues whenever the source can
still be enumerated. Missing structure, changed types, orphan/cyclic branches,
invalid timestamps, unsupported parts, duplicate source ids, and normal-form
violations quarantine only the affected conversation. A top-level parser
failure fails the run because safe item boundaries are unknown.
Failed parser runs remain immutable evidence and cannot be resumed; after an
adapter correction or upgrade, the operator starts a new run.

Error codes and summaries come from the closed `IngestionIssue` enum. They are
bounded static descriptions and never interpolate source text, titles,
filenames, tool data, credentials, or secrets. The immutable raw source remains
the encrypted artifact blob and is never replaced or rewritten by retry.

No run promotes a conversation artifact. Every imported or updated
conversation starts `pending` and must pass ordinary owner review.

## Migration and rollback

Migration 0019 is append-only and applied transactionally by the existing
schema ledger. If any statement fails, the migration transaction rolls back and
no partial run tables or schema-ledger row remain.

There is no destructive down migration. Rolling application code back does not
delete run, item, head, replacement, source, or provenance rows; operators must
retain the newer vault and return to a build that understands migration 0019
before resuming conversation ingestion. Interrupted application work is
recovered through the run checkpoint, not by editing database rows or reverting
the vault bundle.

Background watching, account sync, and automatic promotion are deliberately
out of scope.
