# GOAL.md — Autonomous Build Goal: Tessera v0.1.0

This document is the standing instruction set for autonomous work sessions.
To start or resume work, tell Claude: **"Execute GOAL.md."**

## Mission

Work through the GitHub milestones continuously until **v0.1.0** — the first
stable version — exists: an encrypted, portable personal context vault with
policy-gated semantic retrieval over a text corpus, hash-chained access
receipts, and agent access via an MCP guardian. The owner workbench is the
Tauri 2 + React app at `apps/tessera-desktop/`: live workflow is open a
current format-v3 vault, view a sanitized aggregate, and explicitly lock.
Other owner screens are labeled previews. `mac/` is a preserved dormant
SwiftUI placeholder, not the app. CI and protected-bundle interchange run
on macOS and Ubuntu.

**v0.1.0 = all issues in milestones M1 through M6 closed**, the v0.0 decision
gate passed, and the release checklist (below) green. M7 (multimodal) is
v0.2.0 — do not start it under this goal.

## Sources of truth (in precedence order)

1. `docs/superpowers/specs/2026-07-04-tessera-guardian-vault-design.md` — the design (2026-07-04 "Mac app deferred" / macOS-only-dev notes are historical; current desktop is `docs/desktop-owner-workbench.md`)
2. GitHub issues/milestones on `eooo-io/tessera` — the work breakdown; each issue's acceptance criteria are its definition of done
3. `CLAUDE.md` — conventions (error handling, IDs, no-unwrap rule, test placement)
4. `Tessera-MVP-Plan-v3.md` — reference only for crypto params, lens semantics, sensitivity levels, performance budgets; superseded elsewhere

If the spec and an issue conflict, the spec wins; note the conflict in an
issue comment and adjust the issue.

## Milestone order

M1 → M2 → M3 → M4 → M5 → **v0.0 gate** → M6 → release v0.1.0

## Work loop (per issue)

1. Pick the lowest-numbered open issue in the current milestone (respect
   in-body dependencies; if blocked, take the next unblocked one).
2. Comment on the issue that work is starting.
3. TDD: write the failing test that encodes the acceptance criteria first,
   then implement.
4. Quality gate before every commit — all must pass locally:
   `cargo fmt --check` · `cargo clippy --all-targets -- -D warnings` ·
   `cargo test --workspace`
5. Commit directly to `main` (solo project, keep it simple). One issue may be
   several commits; the final commit body includes `Closes #<n>`. Push after
   each issue; verify CI stays green — a red main is the top-priority issue.
6. Move to the next issue. At milestone completion, leave a short summary
   comment on the milestone's last issue: what shipped, deviations, metrics.

## The v0.0 gate (end of M5)

Run `tessera eval` against the golden set on a realistic fixture corpus and
write the gate report to `docs/gate-report-v0.0.md`.

- **Pass** (Recall@10 > 0.70, policy-filtering degradation < 10%, every query
  produced a verifiable receipt): commit the report and proceed to M6.
- **Fail**: iterate on chunking/embedding/policy — at most 3 documented
  attempts. Still failing → STOP and report to Ezra with findings. Do not
  grind past the gate: it exists to invalidate the approach cheaply.

## Standing rules

- **Never weaken a security invariant to make a test pass.** The quarantine
  invariant, space isolation, receipt completeness, and encrypt-first
  ordering are inviolable; if one blocks progress, stop and report.
- No new runtime dependencies beyond the workspace `Cargo.toml` without a
  note in the issue explaining why; prefer what's already pinned.
- Update `spec/vault-format.md` in the same commit as any format change.
- Performance budgets are exit criteria, not suggestions — benchmark before
  closing issues that carry them (bench code may live outside CI).
- Keep `PLAN.md` checkboxes in sync as milestones complete.
- Scope discipline: no features that aren't in an issue. If an idea is good,
  open an issue for it (label it, leave it in the backlog) and move on.

## Stop and ask Ezra when

- A design ambiguity requires a decision that would be expensive to reverse
  (format changes, schema semantics, crypto choices beyond the spec).
- The v0.0 gate fails after 3 iterations.
- An external credential, paid service, or non-local model would be needed.
- Anything would be published, deleted, or force-pushed.
- A security invariant and an acceptance criterion genuinely conflict.

Otherwise: decide, document the decision in the issue, and keep moving.

## Release checklist for v0.1.0

- [ ] All M1–M6 issues closed; CI green on `main`
- [ ] `docs/gate-report-v0.0.md` committed with passing metrics
- [ ] Quarantine, isolation, receipt-chain, and revocation invariant tests all present and passing
- [ ] A vault created on macOS opens and answers queries when the bundle is copied to a Linux host running the guardian (portability proof; document the run)
- [ ] Claude Code connects to `tessera-guardian` via stdio MCP, queries under a lens, and the session yields a verifiable receipt (document the run)
- [ ] `spec/vault-format.md` accurate to the shipped format
- [ ] Tag `v0.1.0` and write `CHANGELOG.md`

## Session hygiene

At the start of each autonomous session: `git pull`, check CI status, read
open issue comments for anything Ezra added since last session — his comments
override this document.
