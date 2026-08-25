"""Pure helpers shared by evidence producers and unit tests.

Keeping control lookup and result classification here makes the fail-closed
artifact semantics testable without requiring Docker/containerlab.
"""
from __future__ import annotations

import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent


def verified_test_suffix(verified_by: str) -> str:
    filename, test_name = verified_by.split("::", 1)
    return f"/{filename}::{test_name}"


def mapped_control_for_nodeid(nodeid: str, controls_path: pathlib.Path | None = None) -> str | None:
    """Return the Path A control mapped to a pytest node id, if any."""
    path = controls_path or ROOT / "compliance" / "controls.yaml"
    controls = yaml.safe_load(path.read_text())["controls"]
    for control in controls:
        verified_by = control.get("verified_by", "")
        if verified_by and nodeid.endswith(verified_test_suffix(verified_by)):
            return str(control["id"])
    return None


def automatic_payload(control_id: str) -> dict:
    """Fallback observations when a mapped test exits before evidence()."""
    return {
        "control_id": control_id,
        "assertion": "mapped control test exited before recording explicit observations",
        "observed": {"evidence_recorded": False},
        "enforcement_node": None,
        "counter_before": None,
        "counter_after": None,
    }


def classify_result(*, passed: bool, assertion_failure: bool, evidence_recorded: bool) -> str:
    """Translate pytest call outcome to the evidence schema fail-closed."""
    if passed:
        return "PASS" if evidence_recorded else "ERROR"
    if assertion_failure:
        return "FAIL"
    return "ERROR"
