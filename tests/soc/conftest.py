"""Shared fixtures: one synthetic, leakage-safe dataset per test session."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from ai.training.build_dataset import build, load_scenarios, write_dataset

import synthetic_soc as synthetic

ROOT = Path(__file__).resolve().parents[2]
GIT = "0123456789abcdef0123456789abcdef01234567"


@pytest.fixture(scope="session")
def dataset_dir(tmp_path_factory):
    work = tmp_path_factory.mktemp("lifecycle")
    scenarios = work / "scenarios.json"
    scenarios.write_text(json.dumps(synthetic.scenario_file_payload()))
    result = build(
        events=synthetic.generate_events(), scenarios=load_scenarios(scenarios),
        schema="network-window-v1", boundaries=synthetic.boundaries(), git_sha=GIT,
    )
    write_dataset(
        result, output_dir=work / "dataset", dataset_id="synthetic-lab-001", schema="network-window-v1",
        boundaries=synthetic.boundaries(), git_sha=GIT, sources=["suricata", "opnsense"],
        events_sha256="c" * 64, collector_config_sha256="d" * 64, normalization_schema_sha256="e" * 64,
        raw_data_location_class="local_ignored", created_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
        repository_root=ROOT,
    )
    return work / "dataset"


@pytest.fixture()
def relaxed_policy(tmp_path):
    policy = yaml.safe_load((ROOT / "ai/training/promotion-policy.yaml").read_text())
    policy["minimum"] = {key: 0.2 for key in policy["minimum"]}
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(policy))
    return path


@pytest.fixture(scope="session")
def approved_registry(dataset_dir, tmp_path_factory):
    """An approved Isolation Forest registry that carries the five-detector comparison."""

    pytest.importorskip("torch")
    pytest.importorskip("safetensors")
    import argparse

    from ai.evaluation.compare import compare
    from ai.training import promote as promotion
    from ai.training.train_isolation_forest import train as train_forest
    from ai.training.train_lstm_autoencoder import train as train_lstm
    from synthetic_soc import training_arguments

    work = tmp_path_factory.mktemp("registry")
    forest = train_forest(training_arguments(dataset_dir, work / "forest", model_id="synthetic-if-live"))
    args = training_arguments(dataset_dir, work / "lstm", model_id="synthetic-lstm-live")
    args.sequence_length, args.epochs, args.hidden_size = 6, 15, 12
    args.latent_size, args.learning_rate, args.batch_size = 4, 0.02, 64
    lstm = train_lstm(args)
    base = training_arguments(dataset_dir, work / "cmp")
    names = ("train_vectors", "validation_vectors", "test_vectors", "session_assignments", "dataset_manifest",
             "labels", "feature_schema")
    report = compare(argparse.Namespace(**{n: getattr(base, n) for n in names}, isolation_forest_candidate=forest,
                                        lstm_candidate=lstm, output_dir=work / "cmp",
                                        max_false_positives_per_hour=1.0))
    policy = yaml.safe_load((ROOT / "ai/training/promotion-policy.yaml").read_text())
    policy["minimum"] = {key: 0.2 for key in policy["minimum"]}
    policy_path = work / "relaxed.yaml"
    policy_path.write_text(yaml.safe_dump(policy))
    result = promotion.promote(forest, work / "active", approver="reviewer", policy_path=policy_path,
                               comparison=report)
    from types import SimpleNamespace

    return SimpleNamespace(path=work / "active", digest=result["metadata_sha256"])
