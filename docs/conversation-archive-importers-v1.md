# Claude and ChatGPT archive importers v1

Tessera has separate adapters for Claude account exports and ChatGPT account
exports. Both feed the versioned `tessera.conversation.v1` model and the same
durable ingestion runner; neither adapter writes directly to the vault or
decides replacement semantics.

## Commands and custody

- `tessera conversation import-claude <conversations.json> --space <id>`
- `tessera conversation resume-claude <run-id>`
- `tessera conversation import-chatgpt <conversations.json> --space <id>`
- `tessera conversation resume-chatgpt <run-id>`

Import encrypts the original JSON immediately as a restricted, pending source
artifact. Normalized conversations and transcript derivations also remain
encrypted, restricted, and pending. `--max-items` creates a clean checkpoint;
resume authenticates and decrypts the recorded source artifact rather than
trusting a path supplied later. No tool is replayed and no referenced
attachment URL is downloaded.

## ChatGPT preservation

The v1 parser accepts a top-level conversation array or an object containing a
`conversations` array. Each conversation requires a source id and an object
`mapping`. Mapping ids, message ids, parent/children edges, `current_node`,
roles, timestamps, status, model metadata, multipart text/code/image/file
parts, metadata attachments, and supported tool call/result identifiers are
preserved when present.

The selected transcript is the exact parent chain ending at `current_node`.
Regenerated sibling responses stay as separate canonical nodes and are not
rendered into that path. Hidden roots, deleted messages, partial messages,
empty nodes, and unknown content objects remain explicit states or unsupported
parts. A missing or wrongly typed mapping quarantines only that conversation.

## Claude preservation

The Claude adapter accepts the same archive containers and reads each
conversation's `chat_messages` or `messages` array. It preserves message ids,
roles/senders, timestamps, model and project/workspace associations, ordered
content blocks, tool-use/result pairing, attachments/files, deleted/hidden or
partial state, and unsupported blocks. Thinking and redacted-thinking values
remain in the authenticated encrypted original but are withheld from retrieval
rendering.

Claude account exports and Claude Code JSONL sessions deliberately use separate
parsers. Similar-looking fields are not evidence that the products share a
stable schema.

## Provenance and drift

For a top-level JSON array, every canonical source record names the exact byte
and line range of its enclosing source conversation. Source-native node,
message, content-part/block, attachment, and tool identifiers remain in the
encrypted canonical envelope. `reconstruct_cited_nodes` returns those exact
identifiers to an unlocked owner; `reconstruct_cited_source_records`
authenticates the original blob and returns the exact enclosing JSON bytes.
Wrapper-object exports conservatively cite the authenticated whole export when
a narrower lexical range is unavailable.

Invalid UTF-8 or invalid archive JSON stops enumeration with a content-free
parser error because a safe conversation boundary cannot be proven. Once
enumerated, a missing required field or changed field type quarantines only the
affected conversation. Unknown but valid content is preserved as unsupported
data rather than silently discarded. Identical re-imports are unchanged;
changed source conversations or parser versions create explicit replacement
lineage without deleting prior evidence.

## Metadata and validation boundary

Only the existing migration-0020 whitelist may enter the plaintext metadata
index: source product, session id, project/repository, working directory, git
branch/commit, source-file identity, models, and source timestamps. Prompts,
responses, tool data, attachment names/content, and unsupported source data
remain encrypted.

The checked-in fixtures are synthetic and sanitized. They prove ChatGPT branch
separation, selected-path rendering, hidden/deleted/unsupported structures,
Claude block ordering, tool pairing, attachments, partial state, exact source
reconstruction, checkpoints, narrow quarantine, idempotent re-import, and
changed-conversation lineage.

They do not substitute for issue #26's representative private-archive matrix.
Per the implementation-first sequencing decision on #45, private import,
retrieval, leakage, provenance, and format-assumption calibration run after the
implementation freeze. Issue #26 remains open until that evidence exists.
