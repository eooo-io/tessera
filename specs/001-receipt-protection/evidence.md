# Evidence: Protected Receipt Baseline

**Verified**: 2026-08-22

**Branch**: `skippy/issue-39-receipt-protection`

**Base commit**: `35385c3172ac4c97184d54fd19e9b6c5375a943d`

This evidence covers the receipt-protection branch rebased onto the current
`origin/main`, including merged image-understanding work from PR #85. The slice
does not tag or release Tessera.

## Issue #39 Acceptance Audit

| Requirement | Fresh evidence | Result |
|---|---|---|
| Explicit protected and unprotected threats | `docs/adr/0001-receipt-protection-v0.1.md` threat matrix and consequences | Pass |
| Honest product language | README, authorization model, consumer contract, historical v0.0 report, schema, and format spec distinguish local owner authentication from signatures and non-repudiation | Pass |
| Receipt confidentiality | Format-v2 `TSR1` XChaCha20-Poly1305 container plus a whole-bundle scan over 20 unique receipt-only sentinels | Pass |
| Authenticity and tamper evidence | Domain-separated keyed BLAKE3 chain tokens; edits, swaps, insertion, middle deletion, plaintext regeneration, and wrong-key regeneration fail | Pass |
| Distinct verification outcomes | Dedicated malformed, internally inconsistent, unauthenticated legacy, and cryptographically invalid errors | Pass |
| Reviewable owner export | JSON and HTML paths remain complete and emit explicit plaintext warnings | Pass |
| Key loss and rotation documented | ADR, format spec, and recovery runbook state key loss is unrecoverable, keyslot changes retain the DEK, and full DEK rotation is unsupported | Pass |
| No mandatory external service | Receipt protection and verification are entirely local | Pass |
| Copy portability | Complete copied vault decrypts, verifies, appends, and verifies the continued chain | Pass locally; not cross-OS release evidence |
| Crash-safe legacy migration | Full legacy verification before replacement, one index/head commit, deterministic file recovery, active-session exclusion, atomic manifest update, and failpoints before commit, after commit, and after file completion | Pass |

## Verification Results

- `cargo test -p tessera-core receipt::tests -- --nocapture`: 21 passed.
- `cargo test -p tessera-cli --test cli receipts -- --nocapture`: 1 passed.
- `cargo fmt --all -- --check`: passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passed.
- `cargo test --workspace --all-targets`: 327 passed, 0 failed, 2 ignored performance tests.
- `git diff --check`: passed.
- Spec Kit prerequisite/task discovery: passed.
- `cargo test --workspace --all-targets -- --ignored --nocapture`: both explicit
  performance budgets passed on the rebased state; embedding measured
  18.71401 ms against its 50 ms budget and artifact listing completed below
  its 100 ms assertion. Earlier runs showed host-load variance, so exact-release
  evidence must still be rerun on the release candidate.

## Remaining Release Blockers

- **#35 MCP integration suite** is open. This slice supplies its #39 receipt
  dependency, and the real stdio/HTTP workspace tests pass locally. After #39
  merges, closure still needs a checklist audit and exact-head CI evidence.
- **#50 metadata confidentiality** is open and intentionally outside this
  slice. Receipt ids, counts, sizes, timing, SQLite receipt index fields, other
  vault metadata, and unkeyed content-address confirmation risk remain visible
  as documented.
- **#43 private-corpus evaluation** is open. The required 30 to 50
  owner-reviewed private questions and final PROCEED/ITERATE/STOP run were not
  supplied or executed. Synthetic tests cannot close that gate.
- **#44 v0.1.0 release** is open. It remains blocked by the wider release issue
  set, including #43 and #50, accepted/public #39 and #35 evidence, real
  macOS-to-Linux portability proof, reconciliation and release notes, stable
  performance evidence, green CI at the exact release commit, and Ezra's exact
  authorization to tag or publish. No release action was taken.
