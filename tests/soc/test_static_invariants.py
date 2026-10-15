"""The static trust-boundary checks must actually fail when a boundary is broken.

Each case copies the files the checker reads (never certificate or key directories)
into a scratch tree, breaks exactly one rule, and expects the checker to name it.
"""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from soc.workers.common import elastic_authorization

ROOT = Path(__file__).resolve().parents[2]
COPIED = (
    "docker-compose.yml", "requirements-soc-service.in", "requirements-soc-service.lock",
    "k8s", "response", "ai", "soc/elasticsearch", "soc/workers", "docker/soc-python", "docker/enforcer",
    "docker/wazuh/active-response", "supply-chain", "clab/configs", "terraform/vyos-fabric/configs",
    "scripts/check_soc_ai_static.py", "scripts/render_k8s_runtime_secrets.py",
    "scripts/provision_wazuh_response_user.py", ".gitignore",
)
IGNORED = shutil.ignore_patterns("__pycache__", ".DS_Store", "certs", "*.key", "*.pem", "*.pyc")


@pytest.fixture()
def tree(tmp_path):
    for relative in COPIED:
        source, target = ROOT / relative, tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target, ignore=IGNORED)
        else:
            shutil.copy2(source, target)
    return tmp_path


def run(tree: Path):
    return subprocess.run(
        [sys.executable, str(tree / "scripts/check_soc_ai_static.py")], capture_output=True, text=True, check=False,
    )


def mutate(tree: Path, relative: str, old: str, new: str, *, count: int = 1) -> None:
    path = tree / relative
    body = path.read_text()
    assert old in body, f"mutation anchor missing from {relative}"
    path.write_text(body.replace(old, new, count))


def test_the_unmodified_tree_passes(tree):
    result = run(tree)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "relative, old, new, message",
    [
        ("k8s/52-soc-ai.yaml", "readOnlyRootFilesystem: true", "readOnlyRootFilesystem: false", "read-only"),
        ("k8s/52-soc-ai.yaml", "secretName: cxyz-soc-decision", "secretName: cxyz-soc-response", "only its own credential Secret"),
        ("k8s/52-soc-ai.yaml", "automountServiceAccountToken: false", "automountServiceAccountToken: true", "ServiceAccount token"),
        ("k8s/52-soc-ai.yaml", "claimName: soc-model-registry, readOnly: true", "claimName: soc-model-registry", "read-only"),
        ("k8s/52-soc-ai.yaml", "image: cxyz/soc-python:local", "image: cxyz/soc-python:latest", "locked SOC image"),
        ("scripts/render_k8s_runtime_secrets.py", '"decision-key-1.pub": soc_file("decision/decision-key-1.pub"),',
         '"decision-key-1.pub": soc_file("decision/decision-key-1.pub"), "signing.key": "x",', "verification keys only"),
        ("response/deployments/path-c/response.yaml", "mode: observe", "mode: enforce", "observe"),
        ("response/deployments/path-a/decision.yaml", "mode: observe", "mode: enforce", "observe"),
        ("k8s/kustomization.yaml", "resources:", "# loaders/soc-model-loader.yaml\nresources:", "model loader"),
        ("k8s/loaders/soc-model-loader.yaml", "readOnlyRootFilesystem: true", "readOnlyRootFilesystem: false", "model loader Pod must be read-only"),
        ("k8s/loaders/soc-model-loader.yaml", "claimName: soc-model-registry", "claimName: soc-state-response", "only the model registry volume"),
    ],
)
def test_breaking_one_boundary_fails_the_check(tree, relative, old, new, message):
    mutate(tree, relative, old, new)
    result = run(tree)
    assert result.returncode == 1 and message in result.stderr, result.stderr


def test_the_decision_policy_may_not_reach_outside_the_cluster(tree):
    import yaml

    path = tree / "k8s/40-network-policies.yaml"
    documents = list(yaml.safe_load_all(path.read_text()))
    policy = next(d for d in documents if d and d["metadata"]["name"] == "soc-decision")
    policy["spec"]["egress"].append({"to": [{"ipBlock": {"cidr": "10.1.1.0/24"}}]})
    path.write_text(yaml.safe_dump_all(documents))
    result = run(tree)
    assert result.returncode == 1 and "must not have egress outside the cluster" in result.stderr


def test_service_credentials_select_basic_or_api_key_authorization():
    assert elastic_authorization("cxyz_feature:s3cret").startswith("Basic ")
    assert elastic_authorization("c2VjcmV0S2V5") == "ApiKey c2VjcmV0S2V5"
    from base64 import b64decode

    assert b64decode(elastic_authorization("cxyz_feature:s3cret").split()[1]) == b"cxyz_feature:s3cret"
