# Guardian untrusted-content boundary

Tessera controls which evidence bytes may leave a vault. It does not promote
those bytes into instructions, policy, authorization, or verified truth.

Every successful Guardian tool result follows the versioned
`tessera.guardian.tool-result.v1` envelope and returns both:

- `structuredContent`: the canonical JSON object; and
- `content[0].text`: a serialized copy of that same object for MCP clients
  that do not consume structured results.

This follows the
[MCP `2025-11-25` structured-tool result contract](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).
Each tool definition publishes an `outputSchema`; emitted structured results
must match it.

## Trust zones

The Guardian generates the envelope keys, schema version, status enums, trust
classification, and authorization binding. The following values are always
data and must be treated as untrusted even when they came from an
owner-curated vault:

- `evidence[*].title` and `evidence[*].content.text`;
- every value under `evidence[*].citation` and `evidence[*].disclosure` except
  the structural field names/enums;
- space names and identifiers under `spaces`;
- owner-entered lens names and purpose strings;
- error `diagnostic` text, which may include caller-controlled identifiers.

The fixed `trust.instruction_authority` value is `none`. Retrieved text cannot
change the active lens, pairing, purpose, TTL, disclosure mode, MCP framing, or
tool dispatch. Tessera never executes, fetches, installs, or follows anything
found in an artifact.

JSON serialization is the delimiter. Tessera does not rely on XML tags,
Markdown fences, indentation, or sentinel strings that source content can
spoof. Quotes, newlines, fake JSON-RPC messages, fake system prompts, tool-call
markup, and delimiter-looking text remain ordinary JSON string values. The
compatibility text block reparses to exactly one object equal to
`structuredContent`.

## Evidence records

Each `evidence` item includes:

- `classification: untrusted_evidence`;
- `content_kind`;
- artifact id and policy-permitted title;
- provenance classification identifying the Tessera artifact, confirming exact
  receipt evidence exists, and explicitly declining to mark source claims as
  verified facts;
- citation artifact id, exact disclosed byte range when verbatim, BLAKE3 hash
  of the returned content, and a marker that exact source evidence is recorded
  in the receipt;
- requested/applied disclosure mode, byte count, and full-disclosure flag;
- a typed content object.

`status: no_result` returns an empty evidence array. Policy/source failures
return `status: error`, `isError: true`, and an
`untrusted_diagnostic` object; source-controlled error text never becomes
JSON-RPC framing.

Summary and excerpt evidence is capped at 65,536 UTF-8 bytes per item. The cap
is applied in the core disclosure path before receipt recording, so the
receipt and returned bytes remain identical. Full disclosure is a separate
owner capability and is disabled for Guardian sessions in v0.1.

## Conversation evidence types

The v1 schema reserves explicit data classifications for:

- `historical_message`;
- `historical_code`;
- `historical_tool_call`;
- `historical_tool_result`.

Conversation importers must preserve those types instead of flattening them
into executable-looking prose. “Historical tool call” means evidence that a
tool request appeared in an archive; it is never a request for the current
consumer to run that tool.

## Consumer responsibilities

A downstream consumer must:

1. validate `outputSchema`/`schema_version` and fail cleanly on incompatibility;
2. keep the trust envelope separate from source-controlled values;
3. never insert evidence into a higher-trust instruction channel;
4. require its own authorization before executing any action suggested by
   evidence;
5. preserve citation and receipt correlation when presenting claims;
6. apply its own retention, logging, model-provider, and prompt-injection
   controls after disclosure.

Tessera cannot guarantee how a compromised or incorrectly designed consumer
behaves after receiving permitted content. It can make the boundary explicit,
typed, reviewable, and difficult to blur accidentally; it cannot sprinkle a
magic “ignore prompt injection” incantation over another system.
