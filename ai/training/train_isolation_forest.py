#!/usr/bin/env python3
"""Train a candidate Isolation Forest from temporally isolated, labelled vectors.

The script fits only on the benign training partition.  The operating threshold
is selected on the validation partition and the frozen test partition is scored
once; provenance, metrics and ``evaluation.json`` are all computed from the
artifact written here, so no externally supplied number can enter the registry.
It never promotes a model: it writes ``status: candidate`` and the loader refuses
that status until ``python -m ai.training.promote`` records a governed approval.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ai.models.isolation_forest import ModelProvenanceError, SocIsolationForest
from ai.training.pipeline import (
    add_dataset_arguments,
    add_provenance_arguments,
    check_provenance_arguments,
    load_dataset,
    utc_now,
    write_candidate,
)


def _contamination(value: str) -> float | str:
    if value == "auto":
        return value
    parsed = float(value)
    if not 0.0 < parsed <= 0.5:
        raise argparse.ArgumentTypeError("contamination must be auto or in (0, 0.5]")
    return parsed


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    add_dataset_arguments(parser)
    add_provenance_arguments(parser)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--contamination", type=_contamination, default="auto")
    return parser


def train(arguments: argparse.Namespace) -> Path:
    check_provenance_arguments(arguments)
    if arguments.n_estimators < 2:
        raise ModelProvenanceError("n-estimators must be >= 2")
    dataset = load_dataset(arguments)
    started_at = utc_now()
    model = SocIsolationForest.fit(
        arguments.feature_schema,
        dataset.partitions["train"],
        random_seed=arguments.random_seed,
        n_estimators=arguments.n_estimators,
        contamination=arguments.contamination,
    )
    completed_at = utc_now()
    try:
        import joblib
    except ImportError as exc:  # pragma: no cover - deployment dependency error
        raise ModelProvenanceError("joblib is required to write the model artifact") from exc
    from io import BytesIO

    buffer = BytesIO()
    joblib.dump(model, buffer)
    return write_candidate(
        arguments=arguments,
        dataset=dataset,
        model=model,
        algorithm="IsolationForest",
        artifact_name="model.joblib",
        artifact_format="joblib",
        artifact_bytes=buffer.getvalue(),
        hyperparameters={
            "n_estimators": arguments.n_estimators,
            "contamination": arguments.contamination,
            "scaler": "StandardScaler",
            "calibration": "training_decision_function_q01_q99",
        },
        started_at=started_at,
        completed_at=completed_at,
    )


def main() -> int:
    args = build_argument_parser().parse_args()
    try:
        output = train(args)
    except ModelProvenanceError as exc:
        raise SystemExit(f"training refused: {exc}") from exc
    print(f"candidate model written to {output}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
