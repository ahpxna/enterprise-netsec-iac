#!/usr/bin/env python3
"""Train a candidate LSTM autoencoder over consecutive-window sequences.

Same contract as ``train_isolation_forest``: benign-only fitting, threshold on
validation, one frozen test evaluation, artifact-bound provenance.  Training
sequences use only earlier windows of the *same* partition (zeros before it
starts), so no information crosses a temporal boundary.  Requires the optional
``requirements-soc-lstm.txt`` dependencies.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ai.features.sequences import entity_history, index_vectors_by_window_end, sequence_matrix
from ai.models.isolation_forest import ModelProvenanceError
from ai.models.lstm_autoencoder import SEQUENCE_LENGTH, LstmModelError, SocLstmAutoencoder
from ai.training.pipeline import (
    add_dataset_arguments,
    add_provenance_arguments,
    check_provenance_arguments,
    load_dataset,
    utc_now,
    write_candidate,
)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    add_dataset_arguments(parser)
    add_provenance_arguments(parser)
    parser.add_argument("--sequence-length", type=int, default=SEQUENCE_LENGTH)
    parser.add_argument("--epochs", type=int, default=60)
    parser.add_argument("--hidden-size", type=int, default=16)
    parser.add_argument("--latent-size", type=int, default=4)
    parser.add_argument("--learning-rate", type=float, default=0.01)
    parser.add_argument("--batch-size", type=int, default=64)
    return parser


def training_sequences(vectors, schema: str, length: int):
    index = index_vectors_by_window_end(vectors)
    return [
        sequence_matrix(schema, entity_history(vector, index, length), vector["features"])
        for vector in vectors
    ]


def train(arguments: argparse.Namespace) -> Path:
    check_provenance_arguments(arguments)
    if not 2 <= arguments.sequence_length <= 288 or arguments.epochs < 1:
        raise ModelProvenanceError("sequence length must be 2..288 and epochs >= 1")
    dataset = load_dataset(arguments)
    started_at = utc_now()
    try:
        model = SocLstmAutoencoder.fit(
            arguments.feature_schema,
            training_sequences(dataset.partitions["train"], arguments.feature_schema, arguments.sequence_length),
            random_seed=arguments.random_seed,
            epochs=arguments.epochs,
            hidden_size=arguments.hidden_size,
            latent_size=arguments.latent_size,
            learning_rate=arguments.learning_rate,
            batch_size=arguments.batch_size,
            sequence_length=arguments.sequence_length,
        )
        artifact = model.to_safetensors()
    except LstmModelError as exc:
        raise ModelProvenanceError(str(exc)) from exc
    completed_at = utc_now()
    return write_candidate(
        arguments=arguments,
        dataset=dataset,
        model=model,
        algorithm="LSTMAutoencoder",
        artifact_name="model.safetensors",
        artifact_format="safetensors",
        artifact_bytes=artifact,
        hyperparameters={
            "sequence_length": arguments.sequence_length,
            "epochs": arguments.epochs,
            "hidden_size": arguments.hidden_size,
            "latent_size": arguments.latent_size,
            "learning_rate": arguments.learning_rate,
            "batch_size": arguments.batch_size,
            "preprocessing": "log1p_counts_standardized",
            "calibration": "training_reconstruction_error_q01_q99",
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
