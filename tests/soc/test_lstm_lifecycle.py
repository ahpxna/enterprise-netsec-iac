"""LSTM autoencoder: candidate -> promotion -> approved serving with window history."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

pytest.importorskip("torch")
pytest.importorskip("safetensors")

from ai.api.main import create_app  # noqa: E402
from ai.features.contracts import NETWORK_FEATURES  # noqa: E402
from ai.features.sequences import history_window_ends  # noqa: E402
from ai.models.isolation_forest import ModelProvenanceError, load_approved_model  # noqa: E402
from ai.models.lstm_autoencoder import SocLstmAutoencoder, read_safetensors_metadata  # noqa: E402
from ai.training import promote as promotion  # noqa: E402
from ai.training.train_lstm_autoencoder import train as train_lstm  # noqa: E402

from synthetic_soc import training_arguments  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def lstm_arguments(dataset_dir, output):
    args = training_arguments(dataset_dir, output, model_id="synthetic-lstm-1")
    args.sequence_length, args.epochs, args.hidden_size = 6, 25, 12
    args.latent_size, args.learning_rate, args.batch_size = 4, 0.02, 64
    return args


@pytest.fixture(scope="module")
def candidate(dataset_dir, tmp_path_factory):
    return train_lstm(lstm_arguments(dataset_dir, tmp_path_factory.mktemp("lstm") / "candidate"))


def test_training_is_deterministic_for_a_fixed_seed(dataset_dir, tmp_path, candidate):
    again = train_lstm(lstm_arguments(dataset_dir, tmp_path / "again"))
    first = json.loads((candidate / "metadata.json").read_text())["artifact"]["sha256"]
    second = json.loads((again / "metadata.json").read_text())["artifact"]["sha256"]
    assert first == second


def test_artifact_is_safetensors_with_declared_geometry(candidate):
    blob = (candidate / "model.safetensors").read_bytes()
    meta = read_safetensors_metadata(blob)
    assert meta["sequence_length"] == "6" and meta["format"] == "cxyz-lstm-autoencoder-v1"
    model = SocLstmAutoencoder.from_safetensors(blob)
    assert model.sequence_length == 6 and model.calibration_high > model.calibration_low


def test_candidate_benchmark_covers_static_baseline_its_family_and_the_hybrid(candidate):  # five-way: test_benchmark_comparison
    rows = json.loads((candidate / "benchmark.json").read_text())
    assert [row["detector"] for row in rows] == ["static-rules", "lstm-autoencoder", "static+lstm-autoencoder"]


def test_promoted_lstm_requires_exact_history_and_scores_a_scan_higher(candidate, tmp_path, relaxed_policy):
    result = promotion.promote(candidate, tmp_path / "active", approver="reviewer", policy_path=relaxed_policy)
    model = load_approved_model(tmp_path / "active", repository_root=ROOT,
                                trusted_metadata_sha256=result["metadata_sha256"])
    assert model.algorithm == "LSTMAutoencoder" and model.sequence_length == 6
    client = TestClient(create_app(model_dir=tmp_path / "active",
                                   trusted_metadata_sha256=result["metadata_sha256"]))
    status = client.get("/model").json()
    assert status["sequence_length"] == 6

    quiet = dict.fromkeys(NETWORK_FEATURES, 0)
    quiet.update(connection_count=3, unique_dst_ip=2, unique_dst_port=2, bytes_out=1500, bytes_in=5000)
    loud = dict.fromkeys(NETWORK_FEATURES, 0)
    loud.update(connection_count=40, unique_dst_port=40, blocked_ratio=1.0, suricata_alert_count=3,
                bytes_out=2400, unique_dst_ip=1)

    def post(features, history):
        return client.post("/v1/infer", json={"feature_schema": "network-window-v1", "entity": "192.168.40.10",
                                              "features": features, "history": history})

    assert post(quiet, []).status_code == 422                       # history is mandatory
    assert post(quiet, [quiet] * 4).status_code == 422              # and exactly T-1 long
    calm = post(quiet, [quiet] * 5).json()["score"]
    attack = post(loud, [quiet] * 5).json()["score"]
    assert attack > calm
    # a window with no telemetry is the explicit all-zero row, not an error
    assert post(quiet, [quiet, None, quiet, quiet, quiet]).status_code == 200
    assert len(history_window_ends("2026-08-02T11:05:00Z", 6)) == 5


def test_tampered_artifact_is_refused_before_deserialization(candidate, tmp_path, relaxed_policy):
    result = promotion.promote(candidate, tmp_path / "active", approver="reviewer", policy_path=relaxed_policy)
    with (tmp_path / "active" / "model.safetensors").open("ab") as handle:
        handle.write(b"\0")
    with pytest.raises(ModelProvenanceError, match="digest"):
        load_approved_model(tmp_path / "active", repository_root=ROOT,
                            trusted_metadata_sha256=result["metadata_sha256"])
