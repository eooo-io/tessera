# Claude Code JSONL importer v1

`tessera conversation import-claude-code <session.jsonl> --space <id>`
encrypts the supplied JSONL as a restricted pending source artifact and feeds
`ClaudeCodeParser` into the shared ingestion-run API. `--max-items` creates an
intentional checkpoint; `tessera conversation resume-claude-code <run-id>`
reuses the authenticated encrypted source and exact source-file identity.

## Preserved evidence

The parser recognizes source session/record ids, parent UUIDs, roles,
timestamps, models, text/code blocks, tool-use inputs, tool results, structured
errors, attachments, compaction markers, side-chain/meta records, source
version, working directory, project/repository, and git branch/commit when
present. Tool events remain typed, ordered content parts and are never
executed. Thinking/redacted-thinking blocks remain in the encrypted original
but are explicitly withheld from the retrieval rendering.

Every non-empty source line receives a deterministic record id plus exact byte
and line coordinates. `reconstruct_cited_source_records` is the separate
unlocked-owner path that authenticates the original blob and returns the exact
bytes named by a conversation citation. It is not exposed through Guardian
metadata or ordinary disclosure results.

Malformed JSONL lines become `malformed` source nodes with a static error
marker; their bytes remain only in the encrypted original. Unknown record or
content-block types become explicit `unsupported` evidence. Missing parents
are marked `partial` and retain the unresolved source parent id in encrypted
canonical extensions. Cycles, duplicate node identities, and unrepresentable
normal-form violations quarantine the session instead of fabricating a green
transcript.

The existing conversation renderer and turn chunker remain authoritative.
Chunks pack complete source nodes/tool events, never split one merely to meet a
token target, and retain exact first/last node, part, source-record, and byte
ranges.

## Filter metadata boundary

Migration 0020 stores only whitelisted operational metadata: source product,
session, project/repository, working directory, git branch/commit,
source-file identity, models, and source timestamps. It is queryable with
`tessera conversation metadata`. Messages, prompts, tool arguments/results,
patches, command output, errors, and attachment content are forbidden from this
plaintext index and remain encrypted.

## Validation boundary

The checked-in fixture is synthetic and sanitised. It covers tool pairing,
command/result evidence, compaction, a structured error, and malformed JSONL.
No private session or source text is committed.

Field assumptions remain provisional until the owner-controlled post-freeze
private-session matrix required by issue #25. Per the 2026-07-13 sequencing
decision, that test comes after the importer implementation stabilizes. This
does not waive the private import, retrieval, leakage, provenance, or release
gates, and issue #25 must remain open until that evidence exists.
