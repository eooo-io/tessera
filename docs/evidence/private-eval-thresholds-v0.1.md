# Private-corpus evaluation gate for v0.1

Status: **predeclared before the owner-reviewed final run**

Date declared: 2026-07-12

The private `private-eval-v1` plan must contain these values. Any changed
threshold constitutes a new, explicitly documented run; it must not overwrite
or reinterpret a failed run.

| Metric | v0.1 threshold |
|---|---:|
| Recall@10 | at least 0.80 |
| No-answer precision | at least 0.80 |
| No-answer recall | at least 0.80 |
| Policy leakage | exactly 0 |
| Quarantine leakage | exactly 0 |
| Failed queries | exactly 0 |
| Applied disclosure-mode mismatches | exactly 0 |
| Stale/superseded retrieval rate | at most 0.05 |
| Exact citation reconstruction | 1.00 |
| Receipt verification | 1.00 |
| Receipt chain verification | required |

Recommendation rules are fixed in the runner:

- **STOP** for any safety/integrity gate failure: leakage, citation
  reconstruction, receipt verification, or receipt-chain verification.
- **ITERATE** when safety holds but recall, no-answer, or stale-source quality
  misses its threshold.
- **PROCEED** only when every threshold passes.

The final report must come from 30–50 owner-reviewed questions over the private
local corpus. Synthetic tests validate the runner only and are not v0.1 gate
evidence.
