"""Shared live-validation helpers and outcome-bound evidence recording."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from datetime import datetime, timezone

import pytest

from compliance.evidence import automatic_payload, classify_result, mapped_control_for_nodeid
from compliance.provenance import current_provenance


ROOT = pathlib.Path(__file__).resolve().parents[2]
LAB = "companyxyz"
EVIDENCE_DIR = pathlib.Path(os.environ.get("EVIDENCE_DIR", "evidence/runs/adhoc"))
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


RUN_METADATA = {
    "run_id": os.environ.get("EVIDENCE_RUN_ID", EVIDENCE_DIR.name),
    **current_provenance(),
    "environment": os.environ.get("LAB_ENVIRONMENT", "local-containerlab"),
}


def node(name: str) -> str:
    return f"clab-{LAB}-{name}"


def in_node(name: str, *cmd: str, timeout: int = 30):
    full = ["docker", "exec", node(name), *cmd]
    return subprocess.run(full, capture_output=True, text=True, timeout=timeout)


def _safe_filename(nodeid: str) -> str:
    return nodeid.replace("/", "__").replace("::", "__")


def save_evidence(nodeid: str, payload: dict) -> pathlib.Path:
    out = EVIDENCE_DIR / f"{_safe_filename(nodeid)}.json"
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return out


@pytest.fixture
def evidence(request):
    """Collect observations now; persist only after pytest knows the outcome."""
    request.node._evidence_started_at = utc_now()
    request.node._evidence_started_monotonic = time.monotonic()
    request.node._evidence_payload = {}
    request.node._evidence_recorded = False

    def _record(
        *,
        control: str,
        assertion: str,
        observed: dict,
        enforcement_node: str | None = None,
        counter_before: int | None = None,
        counter_after: int | None = None,
    ) -> None:
        request.node._evidence_recorded = True
        request.node._evidence_payload = {
            "control_id": control,
            "assertion": assertion,
            "observed": observed,
            "enforcement_node": enforcement_node,
            "counter_before": counter_before,
            "counter_after": counter_after,
        }

    return _record


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when != "call":
        return

    recorded = getattr(item, "_evidence_payload", {})
    evidence_recorded = bool(getattr(item, "_evidence_recorded", False))
    mapped_control = mapped_control_for_nodeid(item.nodeid)
    if not recorded:
        if mapped_control is None:
            return
        recorded = automatic_payload(mapped_control)

    assertion_failure = call.excinfo is not None and call.excinfo.errisinstance(AssertionError)
    result = classify_result(
        passed=report.passed,
        assertion_failure=assertion_failure,
        evidence_recorded=evidence_recorded,
    )
    if result == "PASS":
        failure = None
    elif report.passed and not evidence_recorded:
        failure = "mapped control test passed without calling evidence(); refusing to emit PASS"
    else:
        failure = report.longreprtext

    started_monotonic = getattr(item, "_evidence_started_monotonic", time.monotonic())
    payload = {
        "schema_version": 1,
        "test_id": item.nodeid,
        "result": result,
        **recorded,
        "failure": failure,
        "started_at": getattr(item, "_evidence_started_at", utc_now()),
        "ended_at": utc_now(),
        "duration_seconds": round(time.monotonic() - started_monotonic, 6),
        **RUN_METADATA,
    }
    save_evidence(item.nodeid, payload)
