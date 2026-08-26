"""Shared provenance helpers for evidence producers.

Evidence is bound to the actual reviewed source tree, not just Git HEAD.  This
prevents a stale PASS from surviving a local firewall/Compose/Ansible change
that was never committed.
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FALLBACK_EXCLUDES = {
    ".git", ".pytest_cache", "__pycache__", ".terraform", "evidence",
    "clab/runtime-configs", "terraform/vyos-fabric/runtime-configs",
    "docker/ids/logs", "wireguard/config",
}


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tracked_files() -> list[pathlib.Path]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=False
        )
    except FileNotFoundError:
        result = None
    if result is not None and result.returncode == 0 and result.stdout:
        names = result.stdout.decode(errors="surrogateescape").split("\0")
        return sorted(ROOT / name for name in names if name and (ROOT / name).is_file())

    files: list[pathlib.Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if any(rel == item or rel.startswith(item + "/") for item in FALLBACK_EXCLUDES):
            continue
        if path.name in {".env", "terraform.tfvars", "routing.auto.tfvars.json", "bootstrap.auto.tfvars.json", "known_hosts"}:
            continue
        files.append(path)
    return sorted(files)


def source_tree_hash() -> str:
    digest = hashlib.sha256()
    for path in _tracked_files():
        rel = path.relative_to(ROOT).as_posix().encode()
        digest.update(len(rel).to_bytes(4, "big"))
        digest.update(rel)
        data = path.read_bytes()
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def test_suite_hash() -> str:
    digest = hashlib.sha256()
    for path in sorted((ROOT / "tests").rglob("*.py")):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    for name in ("attack_chain.sh", "path_b_audit.py"):
        path = ROOT / "scripts" / name
        if path.exists():
            digest.update(path.relative_to(ROOT).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def git_sha() -> str:
    configured = os.environ.get("GIT_SHA")
    if configured:
        return configured
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False
        )
    except FileNotFoundError:
        return "unknown"
    return result.stdout.strip() or "unknown"


def git_dirty() -> bool:
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=normal"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        return True
    if result.returncode != 0:
        return True
    return bool(result.stdout.strip())


DEPLOYMENT_CONFIG_KEYS = (
    "ORG_DOMAIN", "DEPLOY_ENV", "PUBLIC_HOSTNAME",
    "WAZUH_MANAGER_IP",
    "WG_SERVER_PORT", "WG_ENDPOINT", "WG_PEER_COUNT",
    "NTP_UPSTREAM_1", "NTP_UPSTREAM_2",
    "PATH_B_SSH_PUBLIC_KEY_FILE",
)


def deployment_config_hash() -> str:
    """Hash only non-secret deployment knobs that can change control behavior.

    Evidence intentionally never embeds dotenv values.  The digest binds a run
    to domain/listener/upstream choices while passwords and routing secrets stay
    outside provenance.  When .env is absent (for static/unit contexts), the
    reviewed .env.example defaults are used.
    """
    scripts = ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    from env_exec import parse_dotenv  # local import avoids shell evaluation

    source = ROOT / ".env"
    if not source.is_file():
        source = ROOT / ".env.example"
    values = parse_dotenv(source) if source.is_file() else {}
    digest = hashlib.sha256()
    for key in DEPLOYMENT_CONFIG_KEYS:
        value = str(values.get(key, ""))
        record = f"{key}={value}\n".encode()
        digest.update(record)
        if key == "PATH_B_SSH_PUBLIC_KEY_FILE" and value:
            key_path = pathlib.Path(value).expanduser()
            if not key_path.is_absolute():
                key_path = ROOT / key_path
            if key_path.is_file():
                digest.update(b"PATH_B_SSH_PUBLIC_KEY_SHA256=")
                digest.update(hashlib.sha256(key_path.read_bytes()).hexdigest().encode())
                digest.update(b"\n")
            else:
                digest.update(b"PATH_B_SSH_PUBLIC_KEY_SHA256=<missing>\n")
    return digest.hexdigest()

def current_provenance() -> dict[str, object]:
    return {
        "git_sha": git_sha(),
        "git_dirty": git_dirty(),
        "source_tree_sha256": source_tree_hash(),
        "control_catalog_sha256": sha256_file(ROOT / "compliance" / "controls.yaml"),
        "topology_sha256": sha256_file(ROOT / "intent" / "fabric.yaml"),
        "test_suite_sha256": test_suite_hash(),
        "deployment_config_sha256": deployment_config_hash(),
    }
