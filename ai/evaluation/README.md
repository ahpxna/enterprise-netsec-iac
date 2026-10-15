# Scientific evaluation

| Module | Role |
|---|---|
| `labels.py` | `labels-v1`: scenario labels bound to vectors by canonical hash; never produced by a model |
| `detectors.py` | one `score(vector, history)` contract for static rules, models and hybrids (hybrid = static OR model) |
| `threshold.py` / `benchmark.py` | threshold selection on **validation only**, then one evaluation of the frozen test partition |
| `metrics.py` | Precision, Recall, F1, PR-AUC, false positives/hour, MTTD, p95 inference latency; accuracy is deliberately absent |
| `compare.py` | the five-detector protocol on one dataset: static, Isolation Forest, static+IF, LSTM, static+LSTM |

`compare.py` re-verifies both candidate artifacts against their provenance and refuses a
candidate built from a different dataset than the one supplied, so the table cannot mix datasets.
Its `comparison.json` is bound to both artifact digests, the manifest, the labels and the
validation/test vector digests, and may be carried into the approved registry by
`promote --comparison`. Live control AI-04 verifies that the registry carries it.

Evaluation produces evidence for model provenance; it never decides containment. Metrics
computed from the synthetic test data are unit-test artifacts, not research results.
