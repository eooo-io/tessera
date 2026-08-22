# Guardian consumer contract v1

Contract identifier: `tessera.guardian.v1`. This identifier is independent of
the Tessera Cargo/package version. The contract is not stable-release evidence
until issues #44 and #56 pass; this document and its schemas are the versioned
surface being exercised in preparation for that release.

## Discovery and negotiation

Guardian implements MCP `2025-11-25` over newline-delimited stdio and
OAuth-protected Streamable HTTP. An initialize result advertises
`capabilities.experimental["tessera.guardian"]` with the contract version,
tool-result schema version, and one-message byte limit.

A consumer may request an exact contract through initialize params:

```json
{
  "capabilities": {
    "experimental": {
      "tessera.guardian": { "contractVersion": "tessera.guardian.v1" }
    }
  }
}
```

An absent request enters v1 compatibility mode. An unsupported explicit value
fails initialize with JSON-RPC `-32602`; a consumer must not continue by
guessing at field compatibility.

## Stable surface

- Tools: `vault_query`, `vault_get_item`, `vault_list_spaces`.
- Canonical result: `structuredContent` conforming to
  `spec/guardian/tool-result.v1.schema.json`. `content[0].text` is exactly one
  serialized copy of that object.
- Result status: `results`, `no_result`, or `error`. No answer is a successful
  `no_result` with no synthetic evidence, not an error and not a nearest-match
  fallback.
- Authorization comes only from the immutable owner pairing and lens revision.
  Tool arguments cannot replace lens, identity, purpose, TTL, or disclosure
  mode. Purpose is an audit declaration, not semantic enforcement.
- Revocation, expiry, lens deletion/edit, and owner lock take effect before the
  next disclosing call. They cannot retract prior bytes.
- `summary`, `excerpt`, and `full` are requested modes. Guardian v1 disables
  full disclosure and records any downgrade as `applied_mode`.
- Semantic query uses the pinned model and calibrated relevance floor. An
  unavailable/uncalibrated model fails closed.
- Request messages are at most 1 MiB. Evidence text is at most 65,536 UTF-8
  bytes per item. Pagination and server streaming are not supported in v1;
  `top_k` is bounded by the tool schema.

## Field policy

| Field zone | Confidentiality | Stability | Provenance/trust |
|---|---|---|---|
| envelope keys, schema/status enums | protocol metadata | fixed for v1 | Guardian-generated |
| authorization | may identify owner policy/task | names may change only with a new pairing; field shapes fixed | owner-approved metadata, not attestation |
| evidence content/title | potentially private | content is not stable across corpus/version/policy changes | untrusted source data |
| citation | potentially private metadata | field shapes fixed; identifiers/ranges bind the disclosure | exact receipt evidence exists; source claims are not verified |
| spaces | potentially private metadata | field shapes fixed; values owner-controlled | untrusted metadata |
| error diagnostic | may contain caller/source identifiers | prose unstable; code stable | untrusted diagnostic |

Consumers may branch on versioned enums and error codes, never on diagnostic
prose. All values beneath evidence, spaces, citation, and diagnostic remain
untrusted even when the vault owner curated them.

Stable tool-result error codes are:

| Code | Meaning | Retry guidance |
|---|---|---|
| `authorization_ended` | pairing/lens/session authorization is no longer valid | owner action required |
| `policy_denied` | the active lens forbids the requested disclosure or metadata; unknown direct-item ids use this same code to avoid an existence oracle | do not retry unchanged |
| `model_unavailable` | the pinned model is absent, invalid, or uncalibrated | provision/repair model first |
| `corrupt_evidence` | authenticated evidence, ranges, or receipt linkage failed integrity checks | stop disclosure; owner recovery required |
| `source_unavailable` | the requested artifact or required derived evidence does not exist | refresh identifier or owner processing |
| `rate_limited` | the session exceeded its lens-bound rolling limit | retry after the advertised window |
| `session_ended` | the live session expired or was revoked | establish fresh authorization |
| `session_unavailable` | Guardian could not re-open the bound live session | owner/runtime repair required |
| `tool_failed` | bounded internal/tool-input failure not covered above | inspect diagnostic; do not assume retry safety |

`no_result` is a successful status, not an error code. JSON-RPC parse,
invalid-request, method, and incompatible-contract failures remain protocol
errors (`-32700`, `-32600`, `-32601`, and `-32602`) outside the tool envelope.

## Compatibility and deprecation

- Additive optional fields may appear only where the v1 schema permits them.
- Adding an enum value, required field, tool, or changed meaning requires a new
  contract version unless explicitly capability-negotiated.
- A v1 implementation must keep the v1 schemas and golden interactions passing
  throughout all compatible Tessera minor releases.
- A future major contract must be advertised alongside v1 for at least one
  stable minor release before v1 removal. Explicit v1 requests must either
  receive v1 or fail `-32602`; silent reinterpretation is forbidden.
- SQLite tables, Rust types, blob layout, model implementation, and receipt file
  layout are not consumer APIs.

## Privacy, logging, and post-disclosure limits

Guardian does not place protocol output on stdout except JSON-RPC framing and
does not log passphrases, bearer tokens, raw receipt bodies, or source content.
Receipt payloads are encrypted and their local chain is owner-authenticated
under vault-derived keys. This is not an external signature, public
verification mechanism, non-repudiation, or identity attestation. Logical
receipt exports are plaintext owner-review artifacts and must be protected by
the exporting consumer.

After a permitted disclosure Tessera cannot control consumer prompts, logs,
caches, model providers, retention, actions, or deletion. Consumers must keep
evidence out of instruction channels, retain citations/receipt correlation,
apply their own authorization before acting, and treat revocation as stopping
future access rather than erasing prior knowledge.
