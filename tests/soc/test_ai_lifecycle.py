"""Dataset -> candidate -> promotion -> approved serving, end to end, on synthetic data.

The synthetic telemetry only exercises the machinery.  Nothing here is a research
result; it proves that datasets are leakage-safe, evaluation is bound to the
artifact, promotion cannot be shortcut, and the approved model serves requests.
"""

import argparse
from copy import deepcopy
import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from ai.api.main import create_app
from ai.evaluation.benchmark import markdown_table
from ai.features.contracts import NETWORK_FEATURES
from ai.models.isolation_forest import ModelProvenanceError, load_approved_model
from ai.training import promote as promotion
from ai.training.build_dataset import DatasetBuildError, build, load_scenarios, write_dataset
from ai.training.train_isolation_forest import train as train_forest

import synthetic_soc as synthetic
from synthetic_soc import training_arguments
from test_feature_pipeline import GIT

ROOT = Path(__file__).resolve().parents[2]
DIGEST = "sha256:" + "a" * 64


@pytest.fixture(scope="module")
def candidate(dataset_dir, tmp_path_factory):
    return train_forest(training_arguments(dataset_dir, tmp_path_factory.mktemp("cand") / "candidate",
                                                 model_id="synthetic-if-1"))


def test_dataset_partitions_are_ordered_labelled_and_benign_only_for_training(dataset_dir):
    manifest = yaml.safe_load((dataset_dir / "dataset-manifest.yaml").read_text())
    assert manifest["split"]["train"]["label_profile"] == "benign_biased"
    labels = [json.loads(line) for line in (dataset_dir / "labels.jsonl").read_text().splitlines()]
    from ai.training.partitions import canonical_hash

    train_hashes = {
        canonical_hash(json.loads(line)) for line in (dataset_dir / "train.jsonl").read_text().splitlines()
    }
    assert train_hashes and not any(item["label"] for item in labels if item["vector_sha256"] in train_hashes)
    assert sum(item["label"] for item in labels) >= 4
    assert {item["scenario_id"] for item in labels if item["label"]} == set(synthetic.SCENARIOS)
    ledger = json.loads((dataset_dir / "session-assignments.json").read_text())
    sessions = {name: {sid for m in part["memberships"] for sid in m["session_ids"]}
                for name, part in ledger["partitions"].items()}
    assert not sessions["train"] & sessions["validation"] and not sessions["validation"] & sessions["test"]


def test_a_scenario_straddling_a_partition_boundary_is_refused(tmp_path):
    payload = synthetic.scenario_file_payload()
    payload["scenarios"][0]["start"] = "2026-08-01T13:00:00Z"   # spills from train day into validation day
    payload["scenarios"][0]["end"] = "2026-08-02T11:30:00Z"
    path = tmp_path / "scenarios.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(DatasetBuildError):
        build(events=synthetic.generate_events(), scenarios=load_scenarios(path), schema="network-window-v1",
              boundaries=synthetic.boundaries(), git_sha=GIT)


def test_candidate_is_artifact_bound_and_never_loadable_until_promoted(candidate):
    metadata = json.loads((candidate / "metadata.json").read_text())
    binding = json.loads((candidate / "evaluation.json").read_text())
    assert metadata["status"] == "candidate"
    assert binding["model_sha256"] == metadata["artifact"]["sha256"]
    assert binding["threshold"] == metadata["threshold"]
    assert binding["threshold_policy"]["selected_on"] == "validation"
    assert set(metadata["evaluation"]) == {
        "precision", "recall", "f1", "pr_auc", "false_positives_per_hour", "mttd_seconds", "p95_inference_ms",
    }
    assert "accuracy" not in json.dumps(metadata) + (candidate / "benchmark.md").read_text().lower()
    table = (candidate / "benchmark.md").read_text()
    for detector in ("static-rules", "isolation-forest", "static+isolation-forest"):
        assert detector in table
    from hashlib import sha256

    with pytest.raises(ModelProvenanceError):
        load_approved_model(candidate, repository_root=ROOT,
                            trusted_metadata_sha256=sha256((candidate / "metadata.json").read_bytes()).hexdigest())


def test_promotion_rejects_tampered_or_unbound_evaluation(candidate, tmp_path, relaxed_policy):
    broken = tmp_path / "broken"
    broken.mkdir()
    for item in candidate.iterdir():
        (broken / item.name).write_bytes(item.read_bytes())
    binding = json.loads((broken / "evaluation.json").read_text())
    binding["model_sha256"] = "0" * 64
    (broken / "evaluation.json").write_text(json.dumps(binding))
    with pytest.raises(ModelProvenanceError, match="not bound"):
        promotion.promote(broken, tmp_path / "out", approver="reviewer", policy_path=relaxed_policy)

    metric = tmp_path / "metric"
    metric.mkdir()
    for item in candidate.iterdir():
        (metric / item.name).write_bytes(item.read_bytes())
    binding = json.loads((metric / "evaluation.json").read_text())
    binding["test_metrics"]["recall"] = 1.0 if binding["test_metrics"]["recall"] != 1.0 else 0.99
    (metric / "evaluation.json").write_text(json.dumps(binding))
    with pytest.raises(ModelProvenanceError, match="differs from the bound evaluation"):
        promotion.promote(metric, tmp_path / "out2", approver="reviewer", policy_path=relaxed_policy)

    tampered = tmp_path / "tampered"
    tampered.mkdir()
    for item in candidate.iterdir():
        (tampered / item.name).write_bytes(item.read_bytes())
    with (tampered / "model.joblib").open("ab") as handle:
        handle.write(b"x")
    with pytest.raises(ModelProvenanceError, match="artifact digest"):
        promotion.promote(tampered, tmp_path / "out3", approver="reviewer", policy_path=relaxed_policy)


def test_promotion_policy_is_enforced(candidate, tmp_path):
    policy = yaml.safe_load((ROOT / "ai/training/promotion-policy.yaml").read_text())
    policy["minimum"]["precision"] = 1.01
    path = tmp_path / "strict.yaml"
    path.write_text(yaml.safe_dump(policy))
    with pytest.raises(ModelProvenanceError, match="policy not satisfied"):
        promotion.promote(candidate, tmp_path / "out", approver="reviewer", policy_path=path)


def test_promoted_model_serves_only_with_its_independent_digest(candidate, tmp_path, relaxed_policy):
    result = promotion.promote(candidate, tmp_path / "active", approver="reviewer", policy_path=relaxed_policy,
                               note="synthetic unit test")
    active = tmp_path / "active"
    approval = json.loads((active / "approval.json").read_text())
    assert approval["metadata_sha256"] == result["metadata_sha256"]
    model = load_approved_model(active, repository_root=ROOT, trusted_metadata_sha256=result["metadata_sha256"])
    assert model.model_id == "synthetic-if-1"
    with pytest.raises(ModelProvenanceError, match="digest"):
        load_approved_model(active, repository_root=ROOT, trusted_metadata_sha256="f" * 64)

    client = TestClient(create_app(model_dir=active, trusted_metadata_sha256=result["metadata_sha256"]))
    assert client.get("/ready").status_code == 200
    quiet = dict.fromkeys(NETWORK_FEATURES, 0)
    quiet.update(connection_count=3, unique_dst_ip=2, unique_dst_port=2, bytes_out=1500, bytes_in=5000)
    loud = dict.fromkeys(NETWORK_FEATURES, 0)
    loud.update(connection_count=40, unique_dst_ip=1, unique_dst_port=40, blocked_ratio=1.0,
                suricata_alert_count=3, bytes_out=2400)
    scores = {}
    for name, features in (("quiet", quiet), ("loud", loud)):
        reply = client.post("/v1/infer", json={"feature_schema": "network-window-v1",
                                                "entity": "192.168.40.10", "features": features})
        assert reply.status_code == 200
        scores[name] = reply.json()["score"]
    assert scores["loud"] > scores["quiet"]
    # a point model has no history; supplying one is a contract error, not silently ignored
    bad = client.post("/v1/infer", json={"feature_schema": "network-window-v1", "entity": "192.168.40.10",
                                         "features": quiet, "history": [quiet]})
    assert bad.status_code == 422 and bad.json()["detail"]["code"] == "HISTORY_LENGTH_MISMATCH"


def test_retired_model_is_refused_by_the_loader(candidate, tmp_path, relaxed_policy):
    result = promotion.promote(candidate, tmp_path / "active", approver="reviewer", policy_path=relaxed_policy)
    digest = promotion.retire(tmp_path / "active", tmp_path / "retired", status="revoked", reason="drift")
    with pytest.raises(ModelProvenanceError, match="approved"):
        load_approved_model(tmp_path / "retired", repository_root=ROOT, trusted_metadata_sha256=digest)
    assert digest != result["metadata_sha256"]


def test_benchmark_markdown_has_no_accuracy_column():
    table = markdown_table([{"detector": "x", "precision": 1.0, "mttd_seconds": None}])
    assert "n/a" in table and "ccuracy" not in table
