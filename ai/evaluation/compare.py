#!/usr/bin/env python3
"""Compare the Isolation Forest and LSTM candidates against static rules and the hybrids.

Each training CLI evaluates only its own family (plus the static baseline and that
family's hybrid).  The protocol compares all of them on the SAME frozen partitions, so
this command re-verifies both candidates, refuses candidates built from a different
dataset than the one supplied, runs the five detectors with thresholds tuned on the
validation partition only, and writes ``comparison.json`` / ``comparison.md`` bound to
both artifacts and to the dataset, labels and vector digests.  Nothing is trained,
promoted or loaded for serving here.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
from typing import Any, Mapping

from ai.evaluation.benchmark import build_detectors, markdown_table, run_benchmark
from ai.features.contracts import sha256_file
from ai.models.isolation_forest import (
    ARTIFACT_BY_ALGORITHM,
    ModelProvenanceError,
    SocIsolationForest,
    _validate_provenance,
)
from ai.training.pipeline import REPOSITORY_ROOT, add_dataset_arguments, load_dataset

COMPARISON_SCHEMA = "benchmark-comparison-v1"
EXPECTED_DETECTORS = [
    "static-rules", "isolation-forest", "static+isolation-forest", "lstm-autoencoder", "static+lstm-autoencoder",
]


def _candidate_model(directory: Path, algorithm: str, manifest_sha256: str) -> tuple[object, Mapping[str, Any]]:
    metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
    _validate_provenance(metadata, REPOSITORY_ROOT)
    if metadata.get("algorithm") != algorithm or metadata.get("status") != "candidate":
        raise ModelProvenanceError(f"{directory.name} must be a {algorithm} candidate")
    if metadata["dataset"]["manifest_sha256"] != manifest_sha256:
        raise ModelProvenanceError(f"{directory.name} was built from a different dataset than the one supplied")
    _, name = ARTIFACT_BY_ALGORITHM[algorithm]
    data = (directory / metadata["artifact"]["path"]).read_bytes()
    if metadata["artifact"]["path"] != name or sha256(data).hexdigest() != metadata["artifact"]["sha256"]:
        raise ModelProvenanceError(f"{directory.name} artifact digest does not match its provenance")
    if algorithm == "IsolationForest":
        import joblib

        model = joblib.load(BytesIO(data))              # only after the digest above was verified
        if not isinstance(model, SocIsolationForest):
            raise ModelProvenanceError("joblib artifact is not a CompanyXYZ Isolation Forest")
    else:
        from ai.models.lstm_autoencoder import SocLstmAutoencoder

        model = SocLstmAutoencoder.from_safetensors(data)
    return model, metadata


def compare(arguments: argparse.Namespace) -> Path:
    dataset = load_dataset(arguments)
    manifest_sha = sha256_file(dataset.manifest_path)
    forest, forest_meta = _candidate_model(arguments.isolation_forest_candidate, "IsolationForest", manifest_sha)
    recurrent, lstm_meta = _candidate_model(arguments.lstm_candidate, "LSTMAutoencoder", manifest_sha)
    rows = run_benchmark(
        build_detectors(isolation_forest=forest, lstm=recurrent),
        dataset.data("validation"), dataset.data("test"),
        max_false_positives_per_hour=arguments.max_false_positives_per_hour,
    )
    if [row["detector"] for row in rows] != EXPECTED_DETECTORS:
        raise ModelProvenanceError("comparison did not cover the five protocol detectors")
    report = {
        "schema_version": COMPARISON_SCHEMA,
        "feature_schema": arguments.feature_schema,
        "dataset_manifest_sha256": manifest_sha,
        "labels_sha256": sha256_file(dataset.labels_path),
        "validation_vectors_sha256": sha256_file(dataset.paths["validation"]),
        "test_vectors_sha256": sha256_file(dataset.paths["test"]),
        "models": {
            "isolation-forest": {"model_id": forest_meta["model_id"], "model_sha256": forest_meta["artifact"]["sha256"]},
            "lstm-autoencoder": {"model_id": lstm_meta["model_id"], "model_sha256": lstm_meta["artifact"]["sha256"]},
        },
        "threshold_policy": {
            "selected_on": "validation",
            "max_false_positives_per_hour": arguments.max_false_positives_per_hour,
        },
        "rows": rows,
    }
    out = Path(arguments.output_dir)
    if out.exists() and any(out.iterdir()):
        raise ModelProvenanceError("output directory must be absent or empty")
    out.mkdir(parents=True, exist_ok=True)
    (out / "comparison.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "comparison.md").write_text(markdown_table(rows), encoding="utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_dataset_arguments(parser)
    parser.add_argument("--isolation-forest-candidate", type=Path, required=True)
    parser.add_argument("--lstm-candidate", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-false-positives-per-hour", type=float, default=6.0)
    arguments = parser.parse_args()
    try:
        print(compare(arguments))
    except ModelProvenanceError as exc:
        raise SystemExit(f"refused: {exc}") from exc
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
