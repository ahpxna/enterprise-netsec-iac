"""The demo registry tool must produce a registry the real loader accepts - and say it is a demo."""

import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import demo_registry  # noqa: E402
from ai.models.isolation_forest import ModelProvenanceError, load_approved_model  # noqa: E402


def test_demo_registry_is_loadable_only_with_its_digest_and_is_labelled_a_demo(tmp_path, capsys):
    output, env = tmp_path / "active", tmp_path / ".env"
    env.write_text("KEEP=1\nSOC_GIT_SHA=0000000\n# SOC_AI_METADATA_SHA256=commented\n")
    env.chmod(0o600)
    assert demo_registry.main(["--output", str(output), "--write-env", "--env-file", str(env)]) == 0
    out = capsys.readouterr().out
    digest = next(line.split("=", 1)[1] for line in out.splitlines() if line.startswith("SOC_AI_METADATA_SHA256="))
    model = load_approved_model(output, repository_root=ROOT, trusted_metadata_sha256=digest)
    assert model.model_id == "demo-synthetic-if-1" and model.metadata["status"] == "approved"
    approval = json.loads((output / "approval.json").read_text())
    assert "DEMO" in approval["note"] and approval["approver"].startswith("demo-registry")
    with pytest.raises(ModelProvenanceError):
        load_approved_model(output, repository_root=ROOT, trusted_metadata_sha256="f" * 64)
    lines = env.read_text().splitlines()
    assert "KEEP=1" in lines and f"SOC_AI_METADATA_SHA256={digest}" in lines and "# SOC_AI_METADATA_SHA256=commented" in lines
    assert not any(line == "SOC_GIT_SHA=0000000" for line in lines) and env.stat().st_mode & 0o777 == 0o600


def test_demo_registry_refuses_to_overwrite_an_existing_registry(tmp_path, capsys):
    (tmp_path / "active").mkdir()
    (tmp_path / "active" / "metadata.json").write_text("{}")
    assert demo_registry.main(["--output", str(tmp_path / "active")]) == 1
    assert "refusing to overwrite" in capsys.readouterr().err
    assert (tmp_path / "active" / "metadata.json").read_text() == "{}"


def test_update_env_creates_missing_keys_and_never_touches_other_lines(tmp_path):
    env = tmp_path / ".env"
    demo_registry.update_env(env, {"A": "1"})
    assert env.read_text() == "A=1\n"
    env.write_text("X=9\nA=old\n")
    demo_registry.update_env(env, {"A": "2", "B": "3"})
    assert env.read_text().splitlines() == ["X=9", "A=2", "B=3"]
