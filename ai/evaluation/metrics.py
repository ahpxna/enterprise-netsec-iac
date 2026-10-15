"""Metrics for the temporally held-out SOC experiment protocol.

Accuracy is intentionally absent. SOC anomaly streams are imbalanced, so this
module records Precision, Recall, F1, PR-AUC, false positives/hour, MTTD, and
p95 inference latency instead.
"""

from __future__ import annotations

from math import ceil, isfinite
from typing import Iterable, Sequence


class EvaluationError(ValueError):
    """Raised when an experiment does not supply comparable held-out evidence."""


def _p95(values: Sequence[float]) -> float:
    if not values:
        raise EvaluationError("p95 inference latency requires at least one sample")
    ordered = sorted(float(value) for value in values)
    return ordered[max(0, ceil(0.95 * len(ordered)) - 1)]


def evaluate_detector(
    *,
    labels: Sequence[bool | int],
    scores: Sequence[float],
    threshold: float,
    observation_seconds: float,
    detection_delays_seconds: Iterable[float],
    inference_latencies_ms: Sequence[float],
    require_detection: bool = True,
) -> dict[str, float | None]:
    """Evaluate one detector on the same isolated final test period.

    ``labels`` and ``scores`` preserve event order from the temporal test
    partition. ``detection_delays_seconds`` contains only labelled scenarios
    that were actually detected, making missing detections visible in Recall
    instead of disguising them as a zero-delay result.  ``require_detection``
    keeps the strict behaviour (no detected scenario is an error); comparison
    benchmarks pass ``False`` so a detector that misses everything is reported
    with ``mttd_seconds = None`` instead of aborting the whole table.
    """

    if len(labels) != len(scores) or not labels:
        raise EvaluationError("labels and scores must be non-empty and equal length")
    if not 0.0 <= threshold <= 1.0:
        raise EvaluationError("threshold must be in [0, 1]")
    if not isfinite(observation_seconds) or observation_seconds <= 0:
        raise EvaluationError("observation duration must be positive")
    if any(type(label) not in (bool, int) or label not in (0, 1) for label in labels):
        raise EvaluationError("labels must be binary booleans or integers")
    if any(not isfinite(score) or not 0 <= score <= 1 for score in scores):
        raise EvaluationError("scores must be finite and within [0, 1]")
    if len(inference_latencies_ms) != len(scores) or any(
        not isfinite(value) or value < 0 for value in inference_latencies_ms
    ):
        raise EvaluationError("one finite non-negative latency is required per prediction")
    try:
        from sklearn.metrics import average_precision_score, precision_recall_fscore_support
    except ImportError as exc:  # pragma: no cover - deployment dependency error
        raise EvaluationError("scikit-learn is required for scientific metrics") from exc

    binary_labels = [1 if bool(label) else 0 for label in labels]
    predictions = [1 if float(score) >= threshold else 0 for score in scores]
    precision, recall, f1, _ = precision_recall_fscore_support(
        binary_labels, predictions, average="binary", zero_division=0
    )
    false_positives = sum(
        1 for label, prediction in zip(binary_labels, predictions) if label == 0 and prediction == 1
    )
    delays = [float(delay) for delay in detection_delays_seconds]
    if any(not isfinite(delay) or delay < 0 for delay in delays):
        raise EvaluationError("detection delays must be finite and non-negative")
    if not delays and require_detection:
        raise EvaluationError("MTTD requires at least one detected labelled scenario")
    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "pr_auc": float(average_precision_score(binary_labels, [float(score) for score in scores])),
        "false_positives_per_hour": false_positives / (observation_seconds / 3600.0),
        "mttd_seconds": (sum(delays) / len(delays)) if delays else None,
        "p95_inference_ms": _p95(inference_latencies_ms),
    }
