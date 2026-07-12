# Relevance-floor calibration: `all-MiniLM-L6-v2@onnx-1`

Date: 2026-07-12

Implementation: ONNX Runtime, 384-dimensional L2-normalized embeddings

Score: cosine similarity, computed as `1 - squared_l2_distance / 2` by search

Selected system floor: **0.20**, inclusive

## Method

The reproducible program at
`crates/tessera-core/examples/calibrate_relevance.rs` embeds 22 sanitized pairs:

- 10 relevant pairs across safety, food, storage, authentication, OCR,
  transcripts, horticulture, invoicing, and Rust dependency management;
- 6 hard negatives that share ambiguous words but not meaning;
- 6 unrelated pairs from distinct domains.

This is intentionally broader than the five-document v0.0 gate corpus. Run it
with the locally installed model:

```bash
cargo run -p tessera-core --example calibrate_relevance
```

The recorded run used macOS 26.5.1 on arm64. Observed ranges were:

| Class | Count | Minimum | Maximum |
|---|---:|---:|---:|
| Relevant | 10 | 0.253212 | 0.784041 |
| Hard negative | 6 | 0.205508 | 0.416910 |
| Unrelated | 6 | -0.094846 | 0.108959 |

The full relevant scores were `0.661241`, `0.536008`, `0.253212`, `0.784041`,
`0.538629`, `0.640937`, `0.760662`, `0.750703`, `0.715820`, and `0.730725`.

## Selection and tradeoff

At the selected `0.20` floor, all 10 relevant pairs pass and all 6 unrelated
pairs fail: relevant-pair recall is 1.00 and unrelated rejection is 1.00 on
this dataset. All six hard negatives also pass, yielding precision 0.625,
recall 1.00, and F1 0.769 when both negative classes are counted together.

The threshold that maximizes F1 on these pairs is `0.536008`, with precision
1.00, recall 0.90, and F1 0.947. We did not select it: it drops the legitimate
technical query “atomic sqlite transaction recovery” at `0.253212`, which is
too aggressive for a first fail-closed minimization floor. The conservative
`0.20` floor preserves all measured strongly relevant golden pairs and rejects
all measured unrelated pairs without tuning solely for the best headline
metric.

## Runtime contract

- The floor belongs to the exact model version. An uncalibrated model fails
  before vector lookup or disclosure.
- A lens may raise the floor with `min_relevance_score`; it cannot lower it.
- The boundary is inclusive: a score equal to the effective floor passes.
- Filtering occurs after policy-constrained retrieval and before rendering,
  returned-byte accounting, or artifact access recording.
- CLI owner queries, CLI lens queries, evaluation, and MCP lens queries all use
  the thresholded core search API. Direct item lookup remains separate.
- Receipts record outcomes and aggregate diagnostics, but never list rejected
  candidates as disclosed artifacts.

## Limitations and recalibration rule

Cosine relevance is not factuality, entailment, authorization, or an answer
quality guarantee. Lexically ambiguous hard negatives can score above the
floor, as this dataset demonstrates. Downstream evidence sufficiency and
citation checks must handle that problem; lowering recall here to manufacture
certainty would be cargo-cult safety.

The dataset is small and sanitized, so these figures are calibration evidence,
not a population estimate. Any change to model identity, weights, tokenizer,
pooling, normalization, or score conversion requires a new report and explicit
floor. There is no automatic fallback to `0.20` for an unknown version.
