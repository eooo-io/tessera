# MCP integration evidence

This report records the safe, state-bound acceptance evidence for issue #35. It
contains no private corpus content, passphrases, bearer tokens, authorization
codes, protected-container bytes, or raw receipts.

## State binding

- Audited baseline: `560aa87e01bfa144822ca5a64900bd416db9814b`, the
  `origin/main` merge commit for [PR #87](https://github.com/eooo-io/tessera/pull/87)
- Baseline CI: [run 32563732317](https://github.com/eooo-io/tessera/actions/runs/32563732317),
  green on [Ubuntu](https://github.com/eooo-io/tessera/actions/runs/32563732317/job/97009177507)
  and [macOS](https://github.com/eooo-io/tessera/actions/runs/32563732317/job/97009177533)
- Dependency state: issues #34, #37, #38, and #39 are closed
- Closure audit date: 2026-08-22
- Tessera workspace version: `0.1.0` (unreleased development)
- Guardian MCP protocol: `2025-11-25`
- Rust toolchain: `1.97.0`
- CI runtimes: `macos-latest` and `ubuntu-latest`
- Embedding model: manifest-pinned `all-MiniLM-L6-v2@onnx-1`, provisioned and
  verified before the CI test gate

The final issue comment and draft PR bind this report to the exact closure
commit and its two-platform CI run. The baseline links above remain stable
inside the repository instead of creating a commit that points to its own
not-yet-created CI run.

## Real client topology

The real-binary stdio fixture creates two spaces, two live artifacts, summaries,
chunks, embeddings, two materially different lenses, and two pairings with
different purposes, TTLs, and per-session query limits. Two Guardian processes
are open concurrently. Each lists only its permitted space, directly retrieves
only its own item, and runs a semantic query through the production ONNX model.
The processes close in reverse open order.

The real-binary HTTP fixture starts Guardian on an ephemeral loopback port and
uses `curl` as an external scripted client. It performs dynamic client
registration, owner approval bound to that client, OAuth authorization-code
flow with PKCE S256, token exchange, MCP initialization, permitted direct
retrieval, cross-space guessed-ID denial, live pairing revocation, and explicit
owner lock. The configured public URL represents the TLS-terminating
reverse-proxy boundary; the test listener itself remains loopback HTTP.

## Criterion-by-criterion acceptance matrix

| Issue #35 criterion | Current state-bound evidence | Result |
|---|---|---|
| Real Guardian binary and scripted stdio client | `mcp_stdio::checked_in_stdio_reference_client_passes_against_real_guardian` | Pass |
| Initialize and consumer-contract negotiation | `mcp_stdio::{initialize_handshake_succeeds_for_approved_pairing, incompatible_consumer_contract_fails_initialize_cleanly}` | Pass |
| Ping, `tools/list`, `tools/call`, and initialized notification handling | `mcp_stdio::{tools_list_and_ping_after_initialize, concurrent_stdio_clients_preserve_two_lens_isolation_and_reverse_finalization}` | Pass |
| Malformed requests and malformed/oversized tool arguments without killing the live stdio session | `mcp_stdio::malformed_and_oversized_requests_fail_cleanly_without_killing_stdio_session` | Pass |
| Clean disconnect and reverse completion order | `mcp_stdio::{unavailable_model_is_a_bounded_tool_error_and_session_can_disconnect_cleanly, concurrent_stdio_clients_preserve_two_lens_isolation_and_reverse_finalization}` | Pass |
| Two concurrent clients with distinct lenses, purposes, TTLs, and per-session limits | `mcp_stdio::concurrent_stdio_clients_preserve_two_lens_isolation_and_reverse_finalization` | Pass |
| Each client sees only permitted metadata and tools | `mcp_stdio::concurrent_stdio_clients_preserve_two_lens_isolation_and_reverse_finalization`; the shared `mcp::tools` handler applies the same contract to both transports | Pass |
| Direct retrieval obeys the approved lens | `mcp_stdio::concurrent_stdio_clients_preserve_two_lens_isolation_and_reverse_finalization` and `mcp_http::real_http_binary_runs_pkce_lens_revocation_and_receipt_lifecycle` | Pass |
| Semantic retrieval obeys the approved lens, including a blocked-space perfect vector match | `mcp_stdio::concurrent_stdio_clients_preserve_two_lens_isolation_and_reverse_finalization` and `policy_enforcement::adversarial_blocked_space_never_surfaces` | Pass |
| Guessed cross-lens artifact IDs fail closed | Both real-client lifecycle tests above | Pass |
| Unknown and revoked pairings fail closed | `mcp_stdio::{session_refused_for_unknown_pairing, session_refused_for_revoked_pairing, pairing_revocation_blocks_an_existing_stdio_session_on_next_call}` | Pass |
| Deleted or modified lenses invalidate authorization | `mcp_stdio::{session_refused_when_lens_deleted, lens_change_makes_existing_stdio_credential_stale_on_next_call}` and `routes::tests::oauth_pkce_client_is_lens_bound_and_queries_over_streamable_http` | Pass |
| Quarantined artifacts fail closed | `disclosure::tests::permits_refuses_quarantined_artifact` at the shared disclosure boundary used by both transports | Pass |
| Pairing/session expiry is enforced | `mcp_stdio::expired_session_refuses_tool_calls` and `oauth::tests::access_token_expiry_is_bound_to_pairing_ttl_and_enforced` | Pass |
| Rate limits are isolated per live session | `mcp_stdio::concurrent_stdio_clients_preserve_two_lens_isolation_and_reverse_finalization` | Pass |
| Model failure is bounded and does not prevent clean session closure | `mcp_stdio::unavailable_model_is_a_bounded_tool_error_and_session_can_disconnect_cleanly` | Pass |
| Receipt-finalization failure closes the live session and preserves the valid chain prefix | `mcp_stdio::receipt_finalization_permission_failure_closes_session_and_preserves_valid_chain` | Pass on Unix CI runtimes |
| Exact disclosure ranges, hashes, provenance, policy/model binding, and live-session identity | `receipt::tests::{v2_receipt_binds_exact_disclosure_policy_model_and_live_session, v2_covers_summary_direct_access_and_full_downgrade, finalized_v2_receipt_satisfies_the_shipped_json_schema}` | Pass |
| Concurrent sessions finalize into one contiguous chain and correlate to their persisted session records | The real stdio concurrency test plus `receipt::tests::{two_sessions_open_together_finalize_in_completion_order, twenty_concurrent_finalizers_produce_one_contiguous_chain}` | Pass |
| Interruption recovery accepts only committed receipts | `receipt::tests::interrupted_finalization_recovers_only_committed_receipts` and the protected-container migration interruption tests | Pass |
| Real Streamable HTTP lifecycle through an external scripted client | `mcp_http::real_http_binary_runs_pkce_lens_revocation_and_receipt_lifecycle` | Pass |
| OAuth 2.1 authorization code flow with PKCE S256 | The real HTTP test above and `routes::tests::oauth_pkce_client_is_lens_bound_and_queries_over_streamable_http` | Pass |
| Token authorization is bound to client, pairing, exact lens revision, resource, and expiry | `oauth::tests::{code_is_one_time_and_token_is_bound_to_client_lens_resource_and_revocation, access_token_expiry_is_bound_to_pairing_ttl_and_enforced}` plus the HTTP route test | Pass |
| Agent identity, purpose, and TTL remain bound through the immutable approved pairing; each HTTP request creates a correlated live Guardian session | `oauth::tests::code_is_one_time_and_token_is_bound_to_client_lens_resource_and_revocation`, `GuardianSession::bind`, and the HTTP route receipt assertions | Pass |
| Scope escalation requires a new owner-approved pairing/consent | `routes::tests::oauth_pkce_client_is_lens_bound_and_queries_over_streamable_http` | Pass |
| Refresh is unsupported and fails explicitly; live revocation rejects the next request | The same HTTP route test and `mcp_http::real_http_binary_runs_pkce_lens_revocation_and_receipt_lifecycle` | Pass |
| Missing authentication, hostile origin, malformed flow, and oversized HTTP input fail closed | `routes::tests::oauth_pkce_client_is_lens_bound_and_queries_over_streamable_http` | Pass |
| Non-loopback HTTP binding requires explicit owner opt-in | `mcp_stdio::http_non_loopback_bind_requires_explicit_owner_opt_in` | Pass |
| Explicit owner lock and idle lock terminate access | `mcp_stdio::{explicit_guardian_lock_exits_stdio_without_waiting_for_another_call, stdio_idle_timeout_exits_and_drops_the_unlocked_vault}` and `routes::tests::explicit_lock_signal_blocks_http_immediately_and_idle_server_exits` | Pass |

## Protected receipt guarantees inherited from issue #39

PR #87 moved complete finalized receipt payloads into versioned authenticated
encrypted containers. The owner-unlocked vault derives the receipt-protection
key; stored payload fields are not plaintext; container metadata is
authenticated; verification rejects malformed containers, cryptographic
tampering, missing middle receipts, and attempted keyless plaintext
regeneration. Interrupted legacy migration is recoverable, active sessions are
preserved, and copied-vault verification is covered.

Those guarantees are exercised by:

- `receipt::tests::protected_container_hides_receipt_fields_and_round_trips`
- `receipt::tests::malformed_and_cryptographically_invalid_containers_are_distinct`
- `receipt::tests::missing_middle_receipt_and_keyless_plaintext_regeneration_fail`
- the receipt migration interruption and active-session tests
- the real stdio and HTTP lifecycle tests, which run protected
  `receipt::verify` against receipts finalized by the real Guardian binary

This is authenticated local storage, not a public signature, external
timestamp, non-repudiation mechanism, or defense against a process that already
holds the unlocked data-encryption key.

## Fresh closure validation

The following commands are rerun on the final issue-closure state:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --workspace --all-targets
cargo test -p tessera-guardian --test mcp_stdio -- --nocapture
cargo test -p tessera-guardian --test mcp_http -- --nocapture
cargo test -p tessera-guardian --test consumer_contract -- --nocapture
cargo test -p tessera-core receipt::tests -- --nocapture
cargo test --workspace --all-targets
git diff --check
```

Fresh local result on 2026-08-22:

- formatting, Clippy with warnings denied, and the all-target build: pass
- real-binary stdio integration: 20 passed, 0 failed
- real-binary Streamable HTTP integration: 1 passed, 0 failed
- consumer contract: 5 passed, 0 failed
- receipt-focused core suite: 21 passed, 0 failed, 242 filtered out
- full workspace, all targets: 328 passed, 0 failed, 2 ignored performance
  budget checks
- whitespace/error-marker validation with `git diff --check`: pass

The final two-platform PR CI links are recorded in the draft PR and issue
comment because those checks are created only after the closure commit is
pushed.

## Known limitations

- Purpose is an owner-approved audit declaration and receipt binding. Tessera
  does not infer whether a natural-language purpose semantically justifies a
  query.
- Stdio agent identity is local configuration trust, not remote attestation.
- The HTTP integration test exercises the documented loopback-to-TLS-proxy
  boundary, not deployment of a production reverse proxy or certificate stack.
- Quarantine, blocked-perfect-match, cryptographic container, and crash-recovery
  assertions are enforced and tested in the shared policy, disclosure, and
  receipt layers rather than duplicated through every transport permutation.
  Both transports call those same paths.
- The checked-in consumer-contract fixture can validate schemas and synthetic
  chain shape, but cannot authenticate with synthetic credentials. Real
  Guardian integration tests provide the protected-receipt verification proof.
- Synthetic fixtures prove isolation mechanics. The owner-reviewed private
  retrieval-quality gate remains separate under issue #43.
