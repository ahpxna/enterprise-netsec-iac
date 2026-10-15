"""Five-detector comparison: bound to both artifacts, the dataset, and carried by promotion."""

import argparse
import json
from pathlib import Path

import pytest

pytest.importorskip("torch")
pytest.importorskip("safetensors")

from ai.evaluation.compare import EXPECTED_DETECTORS, compare  # noqa: E402
from ai.models.isolation_forest import ModelProvenanceError  # noqa: E402
from ai.training import promote as promotion  # noqa: E402
from ai.training.train_isolation_forest import train as train_forest  # noqa: E402
from ai.training.train_lstm_autoencoder import train as train_lstm  # noqa: E402

from synthetic_soc import training_arguments  # noqa: E402

REQUIRED_METRICS = {"precision", "recall", "f1", "pr_auc", "false_positives_per_hour", "mttd_seconds", "p95_inference_ms"}


@pytest.fixture(scope="module")
def candidates(dataset_dir, tmp_path_factory):
    work = tmp_path_factory.mktemp("compare")
    forest = train_forest(training_arguments(dataset_dir, work / "forest", model_id="synthetic-if-cmp"))
    args = training_arguments(dataset_dir, work / "lstm", model_id="synthetic-lstm-cmp")
    args.sequence_length, args.epochs, args.hidden_size = 6, 20, 12
    args.latent_size, args.learning_rate, args.batch_size = 4, 0.02, 64
    return forest, train_lstm(args)


def comparison_arguments(dataset_dir, forest, lstm, output):
    values = training_arguments(dataset_dir, output)
    return argparse.Namespace(**{
        key: getattr(values, key) for key in (
            "train_vectors", "validation_vectors", "test_vectors", "session_assignments", "dataset_manifest",
            "labels", "feature_schema",
        )
    }, isolation_forest_candidate=forest, lstm_candidate=lstm, output_dir=output, max_false_positives_per_hour=1.0)


@pytest.fixture(scope="module")
def report_dir(dataset_dir, candidates, tmp_path_factory):
    forest, lstm = candidates
    return compare(comparison_arguments(dataset_dir, forest, lstm, tmp_path_factory.mktemp("cmp") / "report"))


def test_comparison_covers_the_five_detectors_without_accuracy(report_dir):
    report = json.loads((report_dir / "comparison.json").read_text())
    assert [row["detector"] for row in report["rows"]] == EXPECTED_DETECTORS
    assert all(REQUIRED_METRICS <= set(row) for row in report["rows"])
    assert report["threshold_policy"]["selected_on"] == "validation"
    assert "ccuracy" not in (report_dir / "comparison.md").read_text() + json.dumps(report)


def test_comparison_is_deterministic(dataset_dir, candidates, report_dir, tmp_path):
    again = compare(comparison_arguments(dataset_dir, *candidates, tmp_path / "again"))
    first = json.loads((report_dir / "comparison.json").read_text())["rows"]
    second = json.loads((again / "comparison.json").read_text())["rows"]
    strip = lambda rows: [{k: v for k, v in row.items() if k not in {"cpu_ms_per_vector", "peak_rss_mb", "p95_inference_ms", "event_rate_eps"}} for row in rows]  # noqa: E731
    assert strip(first) == strip(second)


def test_candidate_from_another_dataset_or_swapped_family_is_refused(dataset_dir, candidates, tmp_path):
    forest, lstm = candidates
    with pytest.raises(ModelProvenanceError, match="must be a"):
        compare(comparison_arguments(dataset_dir, lstm, forest, tmp_path / "swapped"))
    other = tmp_path / "other-forest"
    other.mkdir()
    for item in forest.iterdir():
        other.joinpath(item.name).write_bytes(item.read_bytes())
    metadata = json.loads((other / "metadata.json").read_text())
    metadata["dataset"]["manifest_sha256"] = "0" * 64
    (other / "metadata.json").write_text(json.dumps(metadata))
    with pytest.raises(ModelProvenanceError, match="different dataset"):
        compare(comparison_arguments(dataset_dir, other, lstm, tmp_path / "other"))


def test_promotion_carries_only_a_comparison_bound_to_the_promoted_model(candidates, report_dir, tmp_path, relaxed_policy):
    forest, lstm = candidates
    result = promotion.promote(forest, tmp_path / "active", approver="reviewer", policy_path=relaxed_policy,
                               comparison=report_dir)
    carried = json.loads((tmp_path / "active" / "comparison.json").read_text())
    assert [row["detector"] for row in carried["rows"]] == EXPECTED_DETECTORS and result["metadata_sha256"]

    forged = tmp_path / "forged"
    forged.mkdir()
    report = json.loads((report_dir / "comparison.json").read_text())
    report["models"]["isolation-forest"]["model_sha256"] = "1" * 64
    report["models"]["lstm-autoencoder"]["model_sha256"] = "2" * 64
    (forged / "comparison.json").write_text(json.dumps(report))
    (forged / "comparison.md").write_text("x")
    with pytest.raises(ModelProvenanceError, match="does not include the promoted model"):
        promotion.promote(forest, tmp_path / "bad", approver="reviewer", policy_path=relaxed_policy, comparison=forged)

    partial = tmp_path / "partial"
    partial.mkdir()
    report = json.loads((report_dir / "comparison.json").read_text())
    report["rows"] = report["rows"][:3]
    (partial / "comparison.json").write_text(json.dumps(report))
    (partial / "comparison.md").write_text("x")
    with pytest.raises(ModelProvenanceError, match="five protocol detectors"):
        promotion.promote(forest, tmp_path / "bad2", approver="reviewer", policy_path=relaxed_policy, comparison=partial)
