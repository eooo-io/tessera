# Guardian authorization model

Tessera authorizes an MCP disclosure with an owner-created **pairing**. A
pairing is an immutable grant snapshot containing:

- an exact lens id and lens revision;
- a human-readable agent name;
- a declared purpose;
- a session TTL;
- for HTTP, one registered OAuth client id.

Changing any grant field or editing the lens requires a new pairing. Existing
sessions and HTTP tokens fail closed on their next vault tool call when the
pairing is revoked, the lens is deleted, or the lens revision changes. Pairing
rows cannot be edited in place; revocation is the only supported mutation.
Revoke a stale pairing before approving the same OAuth client for the changed
lens; `tessera pair list` reports stale grants explicitly.

## What purpose means

Purpose is an owner-approved **audit declaration**, not a semantic policy
engine. Tessera records it in the live session and exact receipt and shows it
to the consumer. Tessera does not decide whether a natural-language query is
"really" for that purpose. A free-text slogan is not an authorization
firewall, however earnestly phrased.

Use a narrow lens and a task-specific pairing when the task boundary matters.
A pairing may be reused concurrently until revoked, but every reuse gets a
new live session, TTL, and receipt under the same immutable grant. A materially
different task, identity label, TTL, OAuth client, disclosure policy, or lens
revision requires a new owner-approved pairing.

## Identity by transport

| Transport | Identity claim | What it does not prove |
|---|---|---|
| stdio | Possession of a local pairing id plus the owner-entered `agent_name`; the MCP launcher/configuration is the trust boundary. | No process, user, device, or model attestation. Another same-user process that obtains the pairing id can present it. |
| HTTP/OAuth | Registered public-client id, S256 PKCE authorization flow, exact resource, and an owner pairing binding that client to one lens revision. | Dynamic registration is not organizational identity or remote attestation. The display name is owner/audit metadata. |

The Guardian never accepts lens, purpose, TTL, agent name, or disclosure mode
from a tool call. It resolves those values from the pairing and exact approved
lens revision. HTTP scope is exactly `lens:<lens_id>` and cannot switch lenses
without another owner pairing and authorization flow.

## Revocation and expiry

- Revoking a live session blocks its next vault tool call.
- Revoking a pairing blocks the next vault tool call of every stdio session
  and invalidates every HTTP token bound to it.
- TTL expiry blocks the next vault tool call. It does not erase the session or
  receipt history.
- Editing or deleting a lens makes its existing pairings stale; it does not
  silently upgrade their authority.
- Revocation cannot retract bytes already disclosed. It cannot control a
  downstream model, MCP host, log, cache, or provider after disclosure.

Authorization is checked before every tool call. Non-disclosing protocol
messages such as `ping` do not extend the TTL or create new authority.

## Disclosure capability

The lens controls spaces, filters, sensitivity ceiling, operations, metadata,
relevance floor, rate limit, and requested disclosure mode. The Guardian may
further reduce capability. In the current v0.1 contract, full-content
disclosure is disabled for agent sessions even when a lens requests `full`;
the applied mode and downgrade are recorded in the receipt.

## Audit evidence and limits

Every disclosing session snapshots the pairing id, agent label, purpose, exact
effective lens policy and policy hash, TTL-derived session timestamps, and
disclosure evidence. This proves what Tessera recorded and disclosed under the
selected receipt-integrity design; it does not prove the agent obeyed the
declared purpose or deleted prior context.

The receipt confidentiality/authenticity guarantees are defined separately by
issue #39. Until that baseline lands, do not describe the current unkeyed hash
chain as a signature, immutable record, non-repudiation, or proof against a
vault writer who can regenerate the entire chain.

## Operator rules

1. Create a narrow lens for the task.
2. Create a pairing with an explicit purpose, recognizable agent label, and
   shortest practical TTL.
3. For HTTP, bind the exact registered OAuth client id.
4. Treat pairing reuse as reuse of the same grant, not blanket agent trust.
5. Revoke the pairing when the task ends or any grant field should change.
6. Assume already disclosed content may persist downstream.
