"""Shared, artifact-bound candidate pipeline for every model family.

``load_dataset`` re-validates the whole dataset (manifest schema, partition
order, vector hashes, session isolation, label digest) before any model sees a
vector.  ``write_candidate`` then fits nothing itself: it receives a fitted model
object, selects the operating threshold on validation, scores the frozen test
partition once, and writes a registry directory whose provenance, metrics and
``evaluation.json`` binding are all derived from the written artifact bytes.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from ai.evaluation.benchmark import (
    PartitionData,
    build_detectors,
    evaluate,
    markdown_table,
    run_benchmark,
    tune_threshold,
)
from ai.evaluation.detectors import ModelDetector
from ai.evaluation.labels import Label, labels_for, load_labels
from ai.evaluation.metrics import EvaluationError
from ai.features.contracts import feature_schema_path, feature_schema_sha256, sha256_file
from ai.models.isolation_forest import ModelProvenanceError
from ai.training.partitions import validate_partitions

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PARTITION_NAMES = ("train", "validation", "test")
METRIC_FIELDS = (
    "precision", "recall", "f1", "pr_auc", "false_positives_per_hour", "mttd_seconds", "p95_inference_ms",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_jsonl(path: Path) -> list[Mapping[str, Any]]:
    rows: list[Mapping[str, Any]] = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ModelProvenanceError(f"invalid JSONL in {path}:{number}") from exc
        if not isinstance(payload, Mapping):
            raise ModelProvenanceError(f"JSONL row in {path}:{number} is not an object")
        rows.append(payload)
    if not rows:
        raise ModelProvenanceError(f"feature vector file is empty: {path}")
    return rows


@dataclass
class Dataset:
    manifest: Mapping[str, Any]
    manifest_path: Path
    labels_path: Path
    paths: Mapping[str, Path]
    partitions: Mapping[str, list[Mapping[str, Any]]]
    labels: Mapping[str, list[Label]]

    def data(self, name: str) -> PartitionData:
        bounds = self.manifest["split"][name]
        start = datetime.fromisoformat(bounds["start"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(bounds["end"].replace("Z", "+00:00"))
        return PartitionData(name, self.partitions[name], self.labels[name], (end - start).total_seconds())


def add_dataset_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--train-vectors", type=Path, required=True)
    parser.add_argument("--validation-vectors", type=Path, required=True)
    parser.add_argument("--test-vectors", type=Path, required=True)
    parser.add_argument("--session-assignments", type=Path, required=True)
    parser.add_argument("--dataset-manifest", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--feature-schema", choices=("network-window-v1", "endpoint-window-v1"), required=True)


def add_provenance_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--random-seed", type=int, required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--runtime-image-digest", required=True)
    parser.add_argument("--library-lock-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--max-false-positives-per-hour", type=float, default=6.0,
        help="analyst alert budget used to select the operating threshold on validation",
    )


def check_provenance_arguments(arguments: argparse.Namespace) -> None:
    if arguments.random_seed < 0:
        raise ModelProvenanceError("random seed must be non-negative")
    if not arguments.runtime_image_digest.startswith("sha256:") or len(arguments.runtime_image_digest) != 71:
        raise ModelProvenanceError("runtime image must be an immutable sha256 digest")
    if len(arguments.library_lock_sha256) != 64:
        raise ModelProvenanceError("library lock must be identified by SHA-256")
    if arguments.max_false_positives_per_hour < 0:
        raise ModelProvenanceError("the false-positive budget must be non-negative")
    if arguments.output_dir.exists() and any(arguments.output_dir.iterdir()):
        raise ModelProvenanceError("output directory must be absent or empty")


def load_dataset(arguments: argparse.Namespace) -> Dataset:
    manifest = yaml.safe_load(Path(arguments.dataset_manifest).read_text(encoding="utf-8"))
    if not isinstance(manifest, Mapping) or manifest.get("schema_version") != "dataset-manifest-v1":
        raise ModelProvenanceError("dataset manifest must be dataset-manifest-v1")
    if manifest.get("feature_schema") != arguments.feature_schema:
        raise ModelProvenanceError("dataset manifest feature schema does not match training request")
    if manifest.get("raw_data_committed") is not False:
        raise ModelProvenanceError("raw datasets must not be committed")
    if manifest.get("split", {}).get("strategy") != "temporal_session_isolated":
        raise ModelProvenanceError("dataset split must be temporal_session_isolated")
    expected_hash = feature_schema_sha256(arguments.feature_schema, REPOSITORY_ROOT)
    if manifest.get("feature_schema_sha256") != expected_hash:
        raise ModelProvenanceError("dataset manifest feature schema digest does not match source")
    paths = {
        "train": arguments.train_vectors,
        "validation": arguments.validation_vectors,
        "test": arguments.test_vectors,
    }
    partitions = {name: load_jsonl(path) for name, path in paths.items()}
    validate_partitions(manifest, partitions, paths, arguments.session_assignments)
    for name, rows in partitions.items():
        if {row.get("feature_schema") for row in rows} != {arguments.feature_schema}:
            raise ModelProvenanceError(f"{name} must contain only {arguments.feature_schema} vectors")
    try:
        labels = load_labels(arguments.labels, expected_sha256=manifest["label_source"]["sha256"])
        per_partition = {name: labels_for(rows, labels) for name, rows in partitions.items()}
    except ValueError as exc:
        raise ModelProvenanceError(str(exc)) from exc
    if any(item.attack for item in per_partition["train"]):
        raise ModelProvenanceError("the training partition must not contain attack vectors")
    for name in ("validation", "test"):
        flags = {item.attack for item in per_partition[name]}
        if flags != {True, False}:
            raise ModelProvenanceError(f"the {name} partition needs both benign and attack vectors")
    return Dataset(manifest, Path(arguments.dataset_manifest), Path(arguments.labels), paths,
                   partitions, per_partition)


def write_candidate(
    *,
    arguments: argparse.Namespace,
    dataset: Dataset,
    model: object,
    algorithm: str,
    artifact_name: str,
    artifact_format: str,
    artifact_bytes: bytes,
    hyperparameters: Mapping[str, Any],
    started_at: str,
    completed_at: str,
) -> Path:
    """Evaluate a fitted model on the frozen splits and write the candidate registry."""

    validation, test = dataset.data("validation"), dataset.data("test")
    detector = ModelDetector(algorithm, model)
    threshold = tune_threshold(
        detector, validation, max_false_positives_per_hour=arguments.max_false_positives_per_hour
    )
    try:
        validation_metrics = evaluate(detector, validation, threshold, require_detection=False)
        test_metrics = evaluate(detector, test, threshold, require_detection=True)
    except EvaluationError as exc:
        raise ModelProvenanceError(f"candidate cannot be evaluated: {exc}") from exc
    benchmark = run_benchmark(
        build_detectors(
            isolation_forest=model if algorithm == "IsolationForest" else None,
            lstm=model if algorithm == "LSTMAutoencoder" else None,
        ),
        validation, test,
        max_false_positives_per_hour=arguments.max_false_positives_per_hour,
    )

    out = arguments.output_dir
    out.mkdir(parents=True, exist_ok=True)
    artifact_path = out / artifact_name
    artifact_path.write_bytes(artifact_bytes)
    schema_hash = feature_schema_sha256(arguments.feature_schema, REPOSITORY_ROOT)
    (out / "feature_schema.json").write_bytes(
        feature_schema_path(arguments.feature_schema, REPOSITORY_ROOT).read_bytes()
    )
    evaluation = {name: float(test_metrics[name]) for name in METRIC_FIELDS}
    metadata: dict[str, Any] = {
        "schema_version": "model-provenance-v1",
        "model_id": arguments.model_id,
        "algorithm": algorithm,
        "created_at": completed_at,
        "status": "candidate",
        "artifact": {
            "path": artifact_name,
            "sha256": sha256_file(artifact_path),
            "size_bytes": artifact_path.stat().st_size,
            "format": artifact_format,
        },
        "dataset": {
            "id": dataset.manifest["dataset_id"],
            "sha256": dataset.manifest["sha256"],
            "manifest_sha256": sha256_file(dataset.manifest_path),
            "train_partition": "train",
            "validation_partition": "validation",
            "test_partition": "test",
        },
        "feature_schema": {"id": arguments.feature_schema, "sha256": schema_hash},
        "git_sha": arguments.git_sha,
        "training": {
            "random_seed": arguments.random_seed,
            "started_at": started_at,
            "completed_at": completed_at,
            "hyperparameters": dict(hyperparameters),
        },
        "threshold": threshold,
        "evaluation": evaluation,
        "runtime": {
            "image_digest": arguments.runtime_image_digest,
            "library_lock_sha256": arguments.library_lock_sha256,
        },
    }
    binding = {
        "schema_version": "evaluation-binding-v1",
        "model_sha256": metadata["artifact"]["sha256"],
        "feature_schema_sha256": schema_hash,
        "dataset_manifest_sha256": metadata["dataset"]["manifest_sha256"],
        "labels_sha256": sha256_file(dataset.labels_path),
        "validation_vectors_sha256": sha256_file(dataset.paths["validation"]),
        "test_vectors_sha256": sha256_file(dataset.paths["test"]),
        "threshold_policy": {
            "selected_on": "validation",
            "objective": "max_f1_within_false_positive_budget",
            "max_false_positives_per_hour": arguments.max_false_positives_per_hour,
        },
        "threshold": threshold,
        "validation_metrics": {
            name: validation_metrics[name] for name in (*METRIC_FIELDS, "scenarios_detected", "scenarios_total")
        },
        "test_metrics": {
            **{name: test_metrics[name] for name in METRIC_FIELDS},
            "scenarios_detected": test_metrics["scenarios_detected"],
            "scenarios_total": test_metrics["scenarios_total"],
            "event_rate_eps": test_metrics["event_rate_eps"],
        },
        "evaluated_at": utc_now(),
    }
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "metrics.json").write_text(json.dumps(evaluation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "evaluation.json").write_text(json.dumps(binding, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "benchmark.json").write_text(json.dumps(benchmark, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "benchmark.md").write_text(markdown_table(benchmark), encoding="utf-8")
    return out
