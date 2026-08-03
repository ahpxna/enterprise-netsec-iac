"""
Shared pytest fixtures for LIVE control validation against the running
containerlab topology. Every test that asserts a security property also
writes a raw-evidence file, so a PASS is never just a green dot — it is a
green dot *plus* a captured command output an auditor can read.
"""
import json
import os
import pathlib
import subprocess
import time

import pytest

LAB = "companyxyz"
EVIDENCE_DIR = pathlib.Path(os.environ.get("EVIDENCE_DIR", "evidence/runs/adhoc"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def node(name: str) -> str:
    """containerlab prefixes nodes as clab-<lab>-<node>."""
    return f"clab-{LAB}-{name}"


def in_node(name: str, *cmd: str, timeout: int = 30):
    """Run a command inside a lab node, return CompletedProcess."""
    full = ["docker", "exec", node(name), *cmd]
    return subprocess.run(full, capture_output=True, text=True, timeout=timeout)


def save_evidence(test_id: str, payload: dict):
    out = EVIDENCE_DIR / f"{test_id}.json"
    payload["captured_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out.write_text(json.dumps(payload, indent=2))
    return out


@pytest.fixture
def evidence(request):
    """Yield a recorder bound to the current test's id."""
    tid = request.node.name

    def _record(**kw):
        return save_evidence(tid, kw)

    return _record
