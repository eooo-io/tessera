# Bounded hybrid retrieval experiment

Date: 2026-07-12

Issue: #42

Decision: **retain vector-only production retrieval**. The measured FTS5 and
hybrid candidates produced no quality improvement, did not improve zero-result
precision, and added latency and index cost. No production migration or
reindex is justified by this evidence.

## Reproduce

Install the exact production embedding model, then run:

```bash
cargo run -p tessera-core --example benchmark_hybrid
```

The benchmark creates a temporary encrypted Tessera vault and an in-memory
FTS5 candidate. It uses `all-MiniLM-L6-v2@onnx-1` and the production calibrated
cosine floor (`0.20`). The committed fixture contains 30 documents and queries
covering:

- semantic paraphrase;
- exact error identifier;
- acronym;
- filename;
- date plus version;
- lexical hard negative;
- unrelated-but-ambiguous wording;
- a quarantined-only token.

One private-space decoy repeats the exact target terms so the benchmark also
measures the effect of policy filtering.

## Candidate designs

1. **Vector baseline:** production sqlite-vec search, fixed live-state and lens
   constraints, then the calibrated cosine floor.
2. **Lexical candidate:** SQLite FTS5 over normalized tokens transformed with
   keyed BLAKE3 before insertion. The benchmark SQL fixes live-state, space,
   tag include/exclude, media type, and sensitivity constraints inside the FTS
   query. Plaintext is never stored in FTS.
3. **Hybrid candidate:** reciprocal-rank fusion with `k = 60`. Lexical results
   may rerank only documents already admitted by the policy-filtered vector
   path and cosine floor; they cannot add a new disclosure.

The candidate RRF value is `1 / (60 + vector_rank) + 1 / (60 +
lexical_rank)` when both ranks exist. It is an ordering score, not cosine,
probability, confidence, or factuality. Production continues to return the
documented cosine relevance score because the hybrid candidate was rejected.

## Recorded result

The final clean arm64/macOS 26.5.1 run produced:

| Path | Recall@5 | Recall@10 | MRR | exact @ 1 | correct zero | p50 | p95 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Vector | 1.000 | 1.000 | 1.000 | 4/4 | 1/3 | 98.59 ms | 218.66 ms |
| FTS5 | 1.000 | 1.000 | 1.000 | 4/4 | 1/3 | 1.77 ms | 3.54 ms |
| Hybrid RRF | 1.000 | 1.000 | 1.000 | 4/4 | 1/3 | 99.41 ms | 222.23 ms |

Index/ingestion observations for 30 one-chunk documents:

- vector indexing: 3606.51 ms;
- keyed FTS5 indexing: 24.22 ms;
- in-memory FTS5 allocation: 94,208 bytes.

These are one-run engineering measurements, not stable hardware benchmarks.
The query latency percentiles contain only nine observations per path and
should be read as directional. The quality outcome is deterministic on the
fixture and was reproduced across three clean runs.

## Policy and minimization evidence

- Work-space Recall@10 remained 1.000 for vector and FTS5, equal to the owner
  view: measured policy degradation was 0%.
- The private-space exact decoy did not surface under the work constraint.
- The pending-only token returned no result from vector, FTS5, or fusion.
- The benchmark asserts the FTS payload does not contain the original exact
  identifier, demonstrating keyed rather than plaintext terms.
- Existing production vector tests continue to cover fixed live-state, space,
  tag, media-type, sensitivity, and lens isolation. No new production
  retrieval path was added.

## Why hybrid lost

The vector baseline already ranked every semantic and exact target first. RRF
therefore had no recall or ranking headroom to recover. It also could not fix
the remaining false disclosures:

- “replace a rusted physical door lock” matched the Rust `Cargo.lock` document;
- “blue whale migration acoustics” matched release notes that discuss schema
  migration.

Those are semantic ambiguity and evidence-sufficiency failures, not missing
lexical recall. FTS reproduced them. Shipping a second index would add moving
parts while preserving the actual bug—a particularly pure form of engineering
theater.

## Reindex and migration decision

None. Existing vault format and `tessera index` behavior remain unchanged.
There is no FTS table, keyed-token version, background rebuild, or receipt
schema change in production. If a larger, representative corpus later shows a
material exact-query regression, rerun this fixture plus that corpus and demand
a measurable Recall@5/10 or MRR improvement before reconsidering hybrid.

## Limitations

The committed corpus is sanitized and deliberately bounded; it is not a
population estimate or a substitute for an owner-approved private-corpus run.
It is sufficient for the current decision because the candidate has zero gain
even on the query classes it was expected to help. The benchmark does not test
a local cross-encoder reranker because the first three paths were already tied
on all positive quality metrics, making additional reranking outside the
issue's minimum-design rule unjustified.
