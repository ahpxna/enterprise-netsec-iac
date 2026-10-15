"""Leakage-safe comparison of detectors on identical validation/test partitions.

Order required by the research protocol: static rules, Isolation Forest, static +
Isolation Forest, LSTM autoencoder, static + LSTM.  Thresholds are fitted on the
validation partition only, then frozen and applied once to the held-out test
partition.  Sequence models receive history from earlier windows of the *same*
partition (zeros before the partition starts), so no information crosses the
temporal boundary.  Accuracy is never reported.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import resource
import sys
from time import perf_counter, process_time
from typing import Mapping, Sequence

from ai.features.sequences import entity_history, index_vectors_by_window_end

from .detectors import Detector, HybridDetector, ModelDetector, StaticRuleDetector
from .labels import Label
from .metrics import evaluate_detector
from .threshold import select_threshold


@dataclass
class PartitionData:
    name: str
    vectors: Sequence[Mapping[str, object]]
    labels: Sequence[Label]
    observation_seconds: float

    def __post_init__(self) -> None:
        if len(self.vectors) != len(self.labels) or not self.vectors:
            raise ValueError(f"{self.name}: vectors and labels must be non-empty and aligned")
        self.index = index_vectors_by_window_end(self.vectors)


@dataclass
class Scored:
    scores: list[float]
    latencies_ms: list[float]
    cpu_seconds: float
    peak_rss_mb: float


def _peak_rss_mb() -> float:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024


def score_partition(detector: Detector, data: PartitionData) -> Scored:
    length = int(getattr(detector, "sequence_length", 1))
    scores: list[float] = []
    latencies: list[float] = []
    cpu_start = process_time()
    for vector in data.vectors:
        history = entity_history(vector, data.index, length) if length > 1 else []
        started = perf_counter()
        value = detector.score(vector, history)
        latencies.append((perf_counter() - started) * 1000.0)
        scores.append(float(value))
    return Scored(scores, latencies, process_time() - cpu_start, _peak_rss_mb())


def detection_delays(
    data: PartitionData, scores: Sequence[float], threshold: float
) -> tuple[list[float], int, int]:
    """Per-scenario time from onset to the end of the first firing window."""

    first_fire: dict[str, float] = {}
    scenarios: set[str] = set()
    for vector, label, score in zip(data.vectors, data.labels, scores):
        if not label.attack or label.scenario_id is None or label.scenario_start is None:
            continue
        scenarios.add(label.scenario_id)
        if score >= threshold:
            end = datetime.fromisoformat(str(vector["window_end"]).replace("Z", "+00:00"))
            delay = max(0.0, (end - label.scenario_start).total_seconds())
            first_fire[label.scenario_id] = min(delay, first_fire.get(label.scenario_id, delay))
    return list(first_fire.values()), len(first_fire), len(scenarios)


def evaluate(
    detector: Detector, data: PartitionData, threshold: float, *, require_detection: bool
) -> dict[str, object]:
    scored = score_partition(detector, data)
    delays, detected, total = detection_delays(data, scored.scores, threshold)
    metrics = evaluate_detector(
        labels=[1 if item.attack else 0 for item in data.labels],
        scores=scored.scores,
        threshold=threshold,
        observation_seconds=data.observation_seconds,
        detection_delays_seconds=delays,
        inference_latencies_ms=scored.latencies_ms,
        require_detection=require_detection,
    )
    events = sum(int(vector["source_event_count"]) for vector in data.vectors)  # type: ignore[arg-type]
    return {
        **metrics,
        "threshold": threshold,
        "scenarios_detected": detected,
        "scenarios_total": total,
        "event_rate_eps": events / data.observation_seconds,
        "cpu_ms_per_vector": scored.cpu_seconds * 1000.0 / len(data.vectors),
        "peak_rss_mb": scored.peak_rss_mb,
    }


def tune_threshold(
    detector: Detector, validation: PartitionData, *, max_false_positives_per_hour: float
) -> float:
    if detector.default_threshold is not None:
        return float(detector.default_threshold)
    scored = score_partition(detector, validation)
    return select_threshold(
        [1 if item.attack else 0 for item in validation.labels],
        scored.scores,
        observation_seconds=validation.observation_seconds,
        max_false_positives_per_hour=max_false_positives_per_hour,
    )


def build_detectors(
    *, isolation_forest: object | None = None, lstm: object | None = None
) -> list[Detector]:
    """The five detectors of the protocol, in protocol order (missing models are skipped)."""

    static = StaticRuleDetector()
    detectors: list[Detector] = [static]
    if isolation_forest is not None:
        forest = ModelDetector("isolation-forest", isolation_forest)
        detectors += [forest, HybridDetector(static, forest)]
    if lstm is not None:
        recurrent = ModelDetector("lstm-autoencoder", lstm)
        detectors += [recurrent, HybridDetector(static, recurrent)]
    return detectors


def run_benchmark(
    detectors: Sequence[Detector],
    validation: PartitionData,
    test: PartitionData,
    *,
    max_false_positives_per_hour: float,
) -> list[dict[str, object]]:
    rows = []
    for detector in detectors:
        threshold = tune_threshold(
            detector, validation, max_false_positives_per_hour=max_false_positives_per_hour
        )
        row = evaluate(detector, test, threshold, require_detection=False)
        row["detector"] = detector.name
        rows.append(row)
    return rows


COLUMNS = (
    ("detector", "Detector"), ("precision", "P"), ("recall", "R"), ("f1", "F1"),
    ("pr_auc", "PR-AUC"), ("false_positives_per_hour", "FP/h"), ("mttd_seconds", "MTTD s"),
    ("p95_inference_ms", "p95 ms"), ("event_rate_eps", "events/s"),
    ("cpu_ms_per_vector", "CPU ms/vec"), ("peak_rss_mb", "RSS MB"),
)


def markdown_table(rows: Sequence[Mapping[str, object]]) -> str:
    """Render the benchmark exactly as generated; accuracy has no column."""

    def cell(value: object) -> str:
        if value is None:
            return "n/a"
        return f"{value:.3f}" if isinstance(value, float) else str(value)

    lines = [
        "| " + " | ".join(title for _, title in COLUMNS) + " |",
        "|" + "|".join("---" for _ in COLUMNS) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(cell(row.get(key)) for key, _ in COLUMNS) + " |")
    return "\n".join(lines) + "\n"
