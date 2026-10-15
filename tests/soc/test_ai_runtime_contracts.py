"""Offline component tests: no lab, network devices or containment operations."""

import pytest
from fastapi.testclient import TestClient

from ai.api.main import create_app
from ai.evaluation.metrics import EvaluationError, evaluate_detector
from ai.features.contracts import NETWORK_FEATURES
from soc.workers.outbox import Outbox


def test_missing_model_is_unready_but_process_is_healthy(tmp_path):
    client = TestClient(create_app(model_dir=tmp_path))
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 503
    assert client.get("/metrics").status_code == 200
    assert client.post("/v1/infer", json={
        "feature_schema": "network-window-v1", "entity": "192.168.40.2",
        "features": dict.fromkeys(NETWORK_FEATURES, 0),
    }).status_code == 503


@pytest.mark.parametrize("mutation", [
    {"feature_schema": "unknown"}, {"entity": "not-an-ip"},
    {"features": {"connection_count": 1}}, {"firewall_key": "forbidden"},
])
def test_invalid_inference_rejected_before_model_loading(tmp_path, mutation):
    payload = {"feature_schema": "network-window-v1", "entity": "192.168.40.2",
               "features": dict.fromkeys(NETWORK_FEATURES, 0)}
    payload.update(mutation)
    assert TestClient(create_app(model_dir=tmp_path)).post("/v1/infer", json=payload).status_code == 422


def test_outbox_result_survives_restart_and_deadletter_requeue(tmp_path):
    path = tmp_path / "private" / "jobs.db"
    box = Outbox(path)
    assert box.enqueue({"fixture": 1}, "a" * 64)
    assert not box.enqueue({"fixture": 1}, "a" * 64)
    identifier = box.due(1)[0]["id"]
    box.save_event(identifier, {"event": "original"})
    box.failed(identifier, code="PERMANENT", retryable=False)
    box.close()
    recovered = Outbox(path)
    assert recovered.status()["deadletter"] == 1
    recovered.requeue(identifier)
    row = recovered.due(1)[0]
    assert row["state"] == "scored"
    assert row["event"] == '{"event":"original"}'
    recovered.sent(identifier)
    assert recovered.status()["sent"] == 1
    recovered.close()


def metric_args():
    return dict(labels=[0, 1], scores=[0.1, 0.9], threshold=0.5,
                observation_seconds=3600, detection_delays_seconds=[2],
                inference_latencies_ms=[1, 2])


@pytest.mark.parametrize("changes", [
    {"labels": ["benign", "attack"]}, {"scores": [0.1, float("nan")]},
    {"observation_seconds": float("inf")}, {"detection_delays_seconds": [-1]},
    {"inference_latencies_ms": [1]}, {"inference_latencies_ms": [1, -1]},
])
def test_metrics_reject_invalid_evidence(changes):
    args = metric_args()
    args.update(changes)
    with pytest.raises(EvaluationError):
        evaluate_detector(**args)


def test_metrics_perfect_detector():
    result = evaluate_detector(**metric_args())
    assert result["precision"] == result["recall"] == result["f1"] == 1
    assert result["false_positives_per_hour"] == 0
    assert result["mttd_seconds"] == 2
