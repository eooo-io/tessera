# MCP Streamable HTTP and OAuth

Tessera targets the latest published MCP revision, `2025-11-25`. The issue
tracker's earlier “MCP 2026” label did not correspond to a published revision
when this transport was implemented.

Normative references:

- [MCP 2025-11-25 Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP 2025-11-25 authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [RFC 9728 protected-resource metadata](https://www.rfc-editor.org/rfc/rfc9728)
- [RFC 8414 authorization-server metadata](https://www.rfc-editor.org/rfc/rfc8414)
- [RFC 8707 resource indicators](https://www.rfc-editor.org/rfc/rfc8707)
- [RFC 7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636)

## Trust model

Remote access requires two distinct acts:

1. A public OAuth client registers its exact redirect URI at `/register`.
2. The owner binds that client ID to one existing lens, agent name, purpose,
   and TTL with `tessera pair add --oauth-client`.

Registration alone grants nothing. Authorization succeeds only for the exact
`lens:<lens_id>` scope backed by that owner approval. A second lens requires a
separate pairing/new consent. Pairing revocation invalidates existing tokens
on their next use.

The pairing is also bound to the exact approved lens revision. Editing the
lens makes existing pairings and tokens stale; the owner must approve a new
pairing rather than silently expanding or changing an old grant. Purpose is an
immutable audit declaration, not semantic query enforcement. The complete
authorization semantics and downstream limits are in
[`authorization-model.md`](authorization-model.md).

Authorization codes are one-time, expire after five minutes, require S256
PKCE, and are bound to the client, exact redirect URI, and exact MCP resource.
Access tokens are opaque, short-lived according to the pairing TTL, and bound
to the client, pairing/agent, lens, and resource. Codes and tokens are stored
only as BLAKE3 hashes.

## Start the server

The guardian binds loopback by default. MCP requires HTTPS authorization
endpoints; terminate TLS at a local/reverse proxy and pass its canonical HTTPS
origin:

```bash
TESSERA_PASSPHRASE='...' cargo run -p tessera-guardian -- \
  --vault /private/Vault.tessera \
  --http \
  --bind 127.0.0.1:8787 \
  --public-url https://tessera.example
```

For a non-loopback listener, both the explicit flag and HTTPS public origin are
required:

```bash
... --http --bind 0.0.0.0:8787 --allow-non-loopback \
    --public-url https://tessera.example
```

The cleartext listener must not be exposed directly; the HTTPS terminator is
the external security boundary. Configure `--allow-origin` for each additional
browser origin. Requests with an unapproved `Origin` receive HTTP 403, which
prevents DNS-rebinding access to a local guardian.

## Client and owner flow

The MCP client discovers:

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-authorization-server`

It registers at `/register`, then shows the returned client ID to the owner.
The owner grants one lens:

```bash
cargo run -p tessera-cli -- --vault /private/Vault.tessera pair add \
  --lens lens_... \
  --purpose 'answer project questions' \
  --agent 'Remote MCP Client' \
  --ttl 30 \
  --oauth-client client_...
```

The client requests authorization code + S256 PKCE with:

- `scope=lens:<approved-lens-id>`
- `resource=https://tessera.example/mcp`
- its exact registered redirect URI and a non-empty `state`

It exchanges the code at `/token`, then sends
`Authorization: Bearer <token>` to `/mcp`. POST requests must accept both
`application/json` and `text/event-stream`; Tessera currently returns one JSON
response. GET is authenticated and returns 405 because the guardian does not
offer a server-initiated SSE stream.

Each disclosing HTTP tool call creates a persisted live session and finalizes
an exact receipt. This keeps HTTP requests stateless while preserving lens,
purpose, agent, artifact-version, and disclosure evidence.

## Current boundary

The v0.1 transport supports public clients, authorization code + S256 PKCE,
dynamic registration, opaque access tokens, revocation through the pairing,
and JSON Streamable HTTP responses. Refresh tokens, native TLS termination,
Client ID Metadata Documents, and server-initiated SSE are not claimed here;
the broader lifecycle/error suite tracks those follow-ups in #35.
