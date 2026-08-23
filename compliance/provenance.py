"""Shared provenance helpers for pytest and shell evidence producers."""

from __future__ import annotations

import hashlib
import os
import pathlib
import subprocess


ROOT = pathlib.Path(__file__).resolve().parent.parent


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_suite_hash() -> str:
    digest = hashlib.sha256()
    for path in sorted((ROOT / "tests").rglob("*.py")):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(path.read_bytes())
    attack_chain = ROOT / "scripts" / "attack_chain.sh"
    digest.update(attack_chain.relative_to(ROOT).as_posix().encode())
    digest.update(attack_chain.read_bytes())
    return digest.hexdigest()


def git_sha() -> str:
    configured = os.environ.get("GIT_SHA")
    if configured:
        return configured
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return "unknown"
    return result.stdout.strip() or "unknown"


def current_provenance() -> dict[str, str]:
    return {
        "git_sha": git_sha(),
        "control_catalog_sha256": sha256_file(ROOT / "compliance" / "controls.yaml"),
        "topology_sha256": sha256_file(ROOT / "intent" / "fabric.yaml"),
        "test_suite_sha256": test_suite_hash(),
    }
