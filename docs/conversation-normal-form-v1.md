# Conversation normal form v1

Identifier: `tessera.conversation.v1`. The machine-readable contract is
`spec/conversation-normal-form.schema.json`; the typed implementation is
`tessera_core::conversation`.

This is the implementation-first normal form for Claude Code, Claude, and
ChatGPT archives. It is source-neutral by design. Source parsers may recognize
different fields, but they must preserve the same identities, tree semantics,
content-part ordering, and exact source-record coordinates.

Private archive validation is deliberately sequenced after implementation
freeze under the 2026-07-13 owner decision recorded on issue #45. Until that
validation passes, source adapters and field assumptions are provisional and
must fail narrow rather than silently reinterpret format drift. This sequencing
does not waive the private evaluation or release gates.

## Identity and provenance

- The immutable encrypted original is authoritative. `source_hash` is its
  lowercase BLAKE3 identity; parser and normalizer versions bind the derived
  result.
- `conversation_id`, `node_id`, `part_id`, `record_id`, and attachment ids are
  stable source-derived identities within one source archive. Deterministic
  internal mappings are added by the persistence layer; parsers must not
  generate random replacement identities on re-import.
- Every node names one or more source records. Records retain source ids and,
  when the format exposes them, exact byte, line, or record-index coordinates.
- Unknown source fields remain in the encrypted original. Semantically useful
  non-core values may also be copied into explicit `extensions`; they never
  acquire instruction authority.

## Branch model

Messages are nodes in a parent-linked tree. `selected_path` identifies exactly
one contiguous root-to-node path. Alternate children, regenerated responses,
deleted nodes, and hidden nodes remain separate nodes. A renderer must never
append mutually exclusive siblings into one transcript.

Cycles, orphan parents, duplicate ids, unknown selected nodes, and branch jumps
fail validation. A deleted or hidden node is represented, not erased. A
malformed or unsupported record is represented at the narrowest safe scope and
keeps its source-record reference.

## Content parts

Part ordering is source ordering. V1 kinds are text, code, tool use, tool
result, attachment, file, image, compaction, error, and unsupported.

- Tool results reference the exact tool-use part id. Import never replays a
  command or tool.
- Compaction summaries are marked `compaction`; they are derived context and
  never presented as original dialogue.
- Attachments record `preserved`, `missing`, `external_unfetched`, or
  `unsupported`. Import never silently downloads an external URL.
- Source text, code, tool arguments/results, filenames, and attachment content
  are untrusted evidence. Production persistence encrypts them before they can
  leave the quarantine pipeline.

## Deterministic rendering and chunking

The v1 renderer emits only the selected path. Each node begins with a stable
role/node/state boundary and each content part begins with a stable
kind/part-id boundary. JSON data uses compact deterministic serialization.

Conversation chunking must pack whole node/content-part events. It may combine
adjacent events on one selected path, but it must never split a part merely to
hit a target size and must never cross into an alternate branch. Every derived
chunk records its first/last node ids, included part ids, normalized byte range,
source record ids, branch endpoint, renderer/chunker versions, and derivation
hash. Migration 0018 and `tessera_core::conversation::persist_archive`
implement that persistence contract. `citation_for_chunk` and
`citation_for_disclosed_range` return content-free exact coordinates;
`reconstruct_cited_nodes` is the separate unlocked-owner reconstruction path.

Each persisted conversation is an ordinary pending Tessera artifact with the
conversation's sensitivity. Existing quarantine and lens checks therefore
remain the only disclosure boundary; conversation retrieval has no bypass.
Re-chunking creates a new derivation and chunk identities while stable source
conversation, node, content-part, and raw-record identities remain unchanged.

## Sensitivity boundary

V1 assigns sensitivity at conversation granularity. This avoids making an
entire multi-year archive unusable because one conversation is restricted while
also avoiding unsupported per-message policy semantics. An importer may raise a
conversation's sensitivity from an archive default; it may not silently lower
an explicit source or owner classification. Any future message-level policy is
a new format decision, not an incidental parser feature.

## Format drift

Missing required structure, changed field types, orphan nodes, cycles, invalid
timestamps, mismatched tool events, and unknown content kinds must be preserved
or quarantined per conversation. A parser must not flatten, discard, fabricate,
or reorder content just to keep an archive batch green. Source-specific
assumptions become accepted only after the post-freeze private archive matrix in
#46/#55 exercises representative real exports.
