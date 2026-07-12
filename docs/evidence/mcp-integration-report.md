# MCP integration evidence

This report records the safe, automated evidence for issue #35. It contains no
private corpus content, passphrases, bearer tokens, authorization codes, or raw
receipts.

## Versions and topology

- Tessera workspace version: `0.1.0` (pre-`0.2.0` development)
- Guardian MCP protocol: `2025-11-25`
- Rust toolchain: `1.97.0`
- CI runtimes: `macos-latest` and `ubuntu-latest`
- Embedding model: manifest-pinned `all-MiniLM-L6-v2@onnx-1`, provisioned and
  verified before the CI test gate

The real-binary stdio fixture creates two spaces, two live artifacts, summaries,
chunks, embeddings, two materially different lenses, and two pairings with
different purposes, TTLs, and per-session query limits. Two Guardian processes
are open concurrently. Each lists only its permitted space, directly retrieves
only its own item, and runs a semantic query through the production ONNX model.
The processes close in reverse open order.

The real-binary HTTP fixture starts Guardian on an ephemeral loopback port and
uses `curl` as an external scripted client. It performs dynamic client
registration, owner approval bound to that client, OAuth authorization-code
flow with PKCE S256, token exchange, MCP initialize, permitted direct retrieval,
cross-space guessed-ID denial, live pairing revocation, and explicit owner lock.
The configured public URL represents the TLS-terminating reverse-proxy boundary;
the test listener itself remains loopback HTTP.

## Automated coverage

| Requirement | Evidence | Result |
|---|---|---|
| Real stdio binary, initialize, ping, tools/list, notifications, malformed input, oversized input, disconnect | `mcp_stdio::{initialize_handshake_succeeds_for_approved_pairing, tools_list_and_ping_after_initialize, malformed_and_oversized_requests_fail_cleanly_without_killing_stdio_session}` | Pass |
| Concurrent clients, two lenses, scoped metadata, direct retrieval, semantic isolation, per-session limits, distinct purpose/TTL | `mcp_stdio::concurrent_stdio_clients_preserve_two_lens_isolation_and_reverse_finalization` | Pass |
| Unknown/revoked pairing; deleted/modified lens; expiry; immediate next-call enforcement | `mcp_stdio::{session_refused_for_unknown_pairing, session_refused_for_revoked_pairing, session_refused_when_lens_deleted, lens_change_makes_existing_stdio_credential_stale_on_next_call, expired_session_refuses_tool_calls, pairing_revocation_blocks_an_existing_stdio_session_on_next_call}` | Pass |
| Explicit lock and idle lock | `mcp_stdio::{explicit_guardian_lock_exits_stdio_without_waiting_for_another_call, stdio_idle_timeout_exits_and_drops_the_unlocked_vault}` and `routes::tests::explicit_lock_signal_blocks_http_immediately_and_idle_server_exits` | Pass |
| Model unavailable without session crash | `mcp_stdio::unavailable_model_is_a_bounded_tool_error_and_session_can_disconnect_cleanly` | Pass |
| Receipt-finalization failure closes the live session and preserves the valid prefix | `mcp_stdio::receipt_finalization_permission_failure_closes_session_and_preserves_valid_chain` | Pass on Unix CI runtimes |
| Exact v2 disclosure ranges, hashes, provenance, policy/model binding, and live-session identity | `receipt::tests::{v2_receipt_binds_exact_disclosure_policy_model_and_live_session, v2_covers_summary_direct_access_and_full_downgrade, finalized_v2_receipt_satisfies_the_shipped_json_schema}` | Pass |
| Reverse-order and concurrent finalization; interruption recovery | `receipt::tests::{two_sessions_open_together_finalize_in_completion_order, twenty_concurrent_finalizers_produce_one_contiguous_chain, interrupted_finalization_recovers_only_committed_receipts}` plus the real stdio concurrency test | Pass |
| Quarantined content fails closed | `disclosure::tests::permits_refuses_quarantined_artifact` | Pass at the shared disclosure boundary used by both transports |
| Real Streamable HTTP/OAuth client lifecycle | `mcp_http::real_http_binary_runs_pkce_lens_revocation_and_receipt_lifecycle` | Pass |
| PKCE, token/lens binding, scope escalation denial, unsupported refresh behavior, origin/auth failures, stale lens, oversized body | `routes::tests::oauth_pkce_client_is_lens_bound_and_queries_over_streamable_http` | Pass |
| Non-loopback bind owner opt-in | `mcp_stdio::http_non_loopback_bind_requires_explicit_owner_opt_in` | Pass |
| One tool/disclosure implementation for stdio and HTTP | `mcp::tools` shared handler and its contract tests | Pass |

## Aggregate result

The pinned local release gate is:

```text
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

GitHub Actions runs the same formatting, lint, build, model-provisioning, and
test path on macOS and Linux. Counts and CI run links belong in the issue/PR
evidence because they change as the suite grows; this file names the durable
test topology and assertions.

## Known limitations and open dependency

- Issue #39 remains an explicit dependency of #35. Receipt v2 integrity and
  chain verification are covered, but the owner has not selected the receipt
  confidentiality/authenticity trust model. This report therefore does **not**
  claim that #35 is complete or that stored receipts satisfy #39.
- Purpose is an owner-approved audit declaration and receipt binding. Tessera
  does not infer whether a natural-language purpose semantically justifies a
  query.
- Stdio agent identity is local configuration trust, not remote attestation.
- The HTTP integration test exercises the documented loopback-to-TLS-proxy
  boundary, not deployment of a production reverse proxy or certificate stack.
- Quarantine and crash-recovery assertions are enforced and tested in the
  shared disclosure/receipt layers rather than reproduced through every
  transport permutation. Both transports call those same paths.
- Synthetic fixtures prove isolation mechanics. The owner-reviewed private
  retrieval-quality gate remains separate under issue #43.
