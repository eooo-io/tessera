# Running the private-corpus v0.1 gate

This workflow is local-only. The private vault, plan, raw queries, source IDs,
and raw receipts stay outside Git. Only the reviewed sanitized aggregate report
may be copied into `docs/evidence/` after the run.

## 1. Prepare an evaluation copy

Copy the representative vault bundle to a private local path. Use a copy so
the 30–50 evaluation receipts remain a self-contained evidence chain rather
than cluttering a daily-use vault. Unlock it and ensure derived indexes are
current:

```bash
cargo run -p tessera-cli -- --vault /private/Eval.tessera index
```

## 2. Create and review the private plan

Create `/private/tessera-private-eval.json` against
`spec/private-eval-plan.schema.json`. The plan must contain 30–50 questions and
use opaque safe IDs such as `q-001`; do not encode a secret, client name, or
query text in the ID.

Each question records:

- the private raw query;
- the exact expected artifact and artifact-version IDs, or an empty
  `expected_sources` array for an explicit no-answer question;
- the allowed lens and blocked-space controls;
- category, expected disclosure mode, severity, rationale, and review date.

Copy the thresholds exactly from
`docs/evidence/private-eval-thresholds-v0.1.md`. Changing a threshold after a
run requires a new plan checksum and a separately preserved report.

The reviewed corpus should include technical/project material, overlapping
allowed and blocked topics, stale versions, exact identifiers and dates,
sensitive/restricted artifacts, near-duplicates, adversarial distractors, and
genuinely unanswerable questions. A synthetic-only plan is not release
evidence.

## 3. Run without raw-output capture

```bash
cargo run -p tessera-cli -- \
  --vault /private/Eval.tessera \
  eval \
  --golden /private/tessera-private-eval.json \
  --report /private/tessera-private-eval-report.json
```

The runner executes every query through a recording lens-bound `Session` and
finalizes a receipt even for no-result or failed queries. It verifies exact
disclosure reconstruction and the full receipt chain. The report contains no
query text, source title, source ID, lens ID, or raw result. It contains:

- exact plan, corpus-manifest, and lens-set checksums;
- corpus artifact/version/chunk counts;
- model/index identity and runtime OS/architecture;
- aggregate retrieval, no-answer, leakage, stale-source, citation, receipt,
  and latency metrics;
- opaque question IDs plus failure categories only;
- a fixed `PROCEED`, `ITERATE`, or `STOP` recommendation.

The command exits non-zero for `ITERATE` and `STOP`. Do not edit the report to
turn that into a pass. Metrics are evidence, not a mood ring.

## 4. Review before committing the aggregate

Inspect the report locally. Confirm question IDs are opaque and that no private
identifier entered metadata. If it is safe, copy only the aggregate report to
`docs/evidence/`. Keep the plan and evaluation vault private. Record the report
checksum and recommendation on issue #43.
