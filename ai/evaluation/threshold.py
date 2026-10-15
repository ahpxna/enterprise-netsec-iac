"""Threshold selection on the validation partition only.

The operating threshold is chosen where it is legitimate to tune: the validation
partition.  The held-out test partition is then scored once with that frozen
threshold.  The policy is explicit and reproducible: maximise F1 subject to a
false-positive budget (alerts per hour on benign traffic), because an analyst's
capacity, not accuracy, is the binding constraint.
"""

from __future__ import annotations

from typing import Sequence

from .metrics import EvaluationError


def _f1(tp: int, fp: int, fn: int) -> float:
    denominator = 2 * tp + fp + fn
    return (2 * tp / denominator) if denominator else 0.0


def select_threshold(
    labels: Sequence[int],
    scores: Sequence[float],
    *,
    observation_seconds: float,
    max_false_positives_per_hour: float,
) -> float:
    """Return the threshold maximising F1 within the false-positive budget.

    Candidates are the observed score values (a vector fires when
    ``score >= threshold``).  Ties prefer the higher threshold, i.e. the more
    conservative detector.  If no observed value satisfies the budget, the
    threshold just above the highest benign score is used when it is still a
    valid probability; otherwise selection fails loudly instead of returning a
    detector that violates the budget.
    """

    if len(labels) != len(scores) or not labels:
        raise EvaluationError("labels and scores must be non-empty and equal length")
    if observation_seconds <= 0 or max_false_positives_per_hour < 0:
        raise EvaluationError("observation duration must be positive and the budget non-negative")
    if not any(labels) or all(labels):
        raise EvaluationError("threshold selection needs both attack and benign vectors")
    hours = observation_seconds / 3600.0
    attack_total = sum(1 for label in labels if label)
    best: tuple[float, float] | None = None  # (f1, threshold)
    for threshold in sorted({float(score) for score in scores}):
        tp = sum(1 for label, score in zip(labels, scores) if label and score >= threshold)
        fp = sum(1 for label, score in zip(labels, scores) if not label and score >= threshold)
        if fp / hours > max_false_positives_per_hour:
            continue
        candidate = (_f1(tp, fp, attack_total - tp), threshold)
        if best is None or candidate >= best:
            best = candidate
    if best is not None:
        return best[1]
    highest_benign = max(float(score) for label, score in zip(labels, scores) if not label)
    if highest_benign >= 1.0:
        raise EvaluationError("no threshold satisfies the false-positive budget on validation")
    return min(1.0, highest_benign + 1e-9)
