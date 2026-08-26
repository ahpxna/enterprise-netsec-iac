import json
import pathlib

import compliance.generate_report as report_module
from compliance.evidence import (
    automatic_payload,
    classify_phase_result,
    classify_result,
    mapped_control_for_nodeid,
)
from compliance.generate_report import load_evidence, status_for, validate_provenance


def artifact(result: str) -> dict:
    return {
        "schema_version": 2,
        "control_id": "SEG-01",
        "test_id": "tests/validation/test_segmentation.py::test_user_vlan_blocked_from_radius",
        "result": result,
        "assertion": "blocked and counter increased",
        "observed": {},
        "started_at": "2026-01-01T00:00:00Z",
        "ended_at": "2026-01-01T00:00:01Z",
        "run_id": "unit",
        "git_sha": "abc",
        "git_dirty": False,
        "source_tree_sha256": "tree",
        "control_catalog_sha256": "a",
        "topology_sha256": "b",
        "test_suite_sha256": "c",
        "deployment_config_sha256": "cfg",
        "environment": "local-containerlab",
    }


CONTROL = {
    "id": "SEG-01",
    "verified_by": "test_segmentation.py::test_user_vlan_blocked_from_radius",
    "verified_by_path_b": "path_b_audit.py::test_seg01",
}


def expected_from(item: dict) -> dict:
    return {
        key: item[key]
        for key in (
            "git_sha",
            "git_dirty",
            "source_tree_sha256",
            "control_catalog_sha256",
            "topology_sha256",
            "test_suite_sha256",
            "deployment_config_sha256",
        )
    }


def test_explicit_fail_can_never_become_pass():
    status, _ = status_for(CONTROL, [artifact("FAIL")])
    assert status == "FAIL"


def test_explicit_pass_is_required():
    status, _ = status_for(CONTROL, [artifact("PASS")])
    assert status == "PASS"


def test_invalid_artifact_is_rejected(tmp_path: pathlib.Path):
    (tmp_path / "bad.json").write_text(json.dumps({"result": "PASS"}))
    evidence, errors = load_evidence(tmp_path)
    assert evidence == []
    assert errors and "missing fields" in errors[0]


def test_missing_artifact_is_unverified():
    status, _ = status_for(CONTROL, [])
    assert status == "UNVERIFIED"


def test_mixed_provenance_is_rejected(tmp_path: pathlib.Path, monkeypatch):
    first = artifact("PASS")
    second = artifact("PASS")
    second["git_sha"] = "different"
    monkeypatch.setattr(report_module, "current_provenance", lambda: expected_from(first))
    errors = validate_provenance([first, second], tmp_path / "unit")
    assert any("mixed provenance field git_sha" in error for error in errors)


def test_path_b_profile_never_accepts_path_a_test_id():
    status, _ = status_for(CONTROL, [artifact("PASS")], profile="path-b")
    assert status == "UNVERIFIED"


def test_path_b_profile_accepts_only_path_b_test_id():
    item = artifact("PASS")
    item["test_id"] = "path_b_audit.py::test_seg01"
    item["environment"] = "path-b"
    status, _ = status_for(CONTROL, [item], profile="path-b")
    assert status == "PASS"


def test_strict_report_rejects_dirty_source(tmp_path: pathlib.Path, monkeypatch):
    item = artifact("PASS")
    item["git_dirty"] = True
    monkeypatch.setattr(report_module, "current_provenance", lambda: expected_from(item))
    errors = validate_provenance([item], tmp_path / "unit", strict=True)
    assert any("dirty worktree" in error for error in errors)


def test_source_tree_hash_mismatch_is_rejected(tmp_path: pathlib.Path, monkeypatch):
    item = artifact("PASS")
    expected = expected_from(item)
    expected["source_tree_sha256"] = "reviewed-tree"
    monkeypatch.setattr(report_module, "current_provenance", lambda: expected)
    errors = validate_provenance([item], tmp_path / "unit")
    assert any("stale source_tree_sha256" in error for error in errors)


def test_topology_hash_mismatch_is_rejected(tmp_path: pathlib.Path, monkeypatch):
    item = artifact("PASS")
    expected = expected_from(item)
    expected["topology_sha256"] = "reviewed-topology"
    monkeypatch.setattr(report_module, "current_provenance", lambda: expected)
    errors = validate_provenance([item], tmp_path / "unit")
    assert any("stale topology_sha256" in error for error in errors)


def test_test_suite_hash_mismatch_is_rejected(tmp_path: pathlib.Path, monkeypatch):
    item = artifact("PASS")
    expected = expected_from(item)
    expected["test_suite_sha256"] = "reviewed-tests"
    monkeypatch.setattr(report_module, "current_provenance", lambda: expected)
    errors = validate_provenance([item], tmp_path / "unit")
    assert any("stale test_suite_sha256" in error for error in errors)


def test_deployment_config_mismatch_is_rejected(tmp_path: pathlib.Path, monkeypatch):
    item = artifact("PASS")
    expected = expected_from(item)
    expected["deployment_config_sha256"] = "different-runtime-config"
    monkeypatch.setattr(report_module, "current_provenance", lambda: expected)
    errors = validate_provenance([item], tmp_path / "unit")
    assert any("stale deployment_config_sha256" in error for error in errors)


def test_duplicate_control_artifacts_are_rejected(tmp_path: pathlib.Path):
    first = artifact("PASS")
    second = artifact("FAIL")
    (tmp_path / "first.json").write_text(json.dumps(first))
    (tmp_path / "second.json").write_text(json.dumps(second))
    evidence, errors = load_evidence(tmp_path)
    assert len(evidence) == 2
    assert any("duplicate evidence for SEG-01" in error for error in errors)


def test_malformed_timestamp_is_rejected(tmp_path: pathlib.Path):
    item = artifact("PASS")
    item["started_at"] = "not-a-timestamp"
    (tmp_path / "bad-time.json").write_text(json.dumps(item))
    evidence, errors = load_evidence(tmp_path)
    assert evidence == []
    assert any("timezone-aware ISO-8601" in error for error in errors)


def test_timestamp_order_is_rejected(tmp_path: pathlib.Path):
    item = artifact("PASS")
    item["ended_at"] = "2025-12-31T23:59:59Z"
    (tmp_path / "bad-order.json").write_text(json.dumps(item))
    evidence, errors = load_evidence(tmp_path)
    assert evidence == []
    assert any("ended_at precedes started_at" in error for error in errors)


def test_wrong_path_a_environment_is_rejected(tmp_path: pathlib.Path, monkeypatch):
    item = artifact("PASS")
    item["environment"] = "developer-laptop"
    monkeypatch.setattr(report_module, "current_provenance", lambda: expected_from(item))
    errors = validate_provenance([item], tmp_path / "unit", profile="path-a")
    assert any("environment is not Path A" in error for error in errors)


def test_wrong_path_b_environment_is_rejected(tmp_path: pathlib.Path, monkeypatch):
    item = artifact("PASS")
    monkeypatch.setattr(report_module, "current_provenance", lambda: expected_from(item))
    errors = validate_provenance([item], tmp_path / "unit", profile="path-b")
    assert any("environment is not Path B" in error for error in errors)


def test_early_assertion_generates_fail_classification():
    assert classify_result(passed=False, assertion_failure=True, evidence_recorded=False) == "FAIL"


def test_early_exception_generates_error_classification():
    assert classify_result(passed=False, assertion_failure=False, evidence_recorded=False) == "ERROR"


def test_passing_without_explicit_evidence_is_error():
    assert classify_result(passed=True, assertion_failure=False, evidence_recorded=False) == "ERROR"


def test_automatic_payload_is_bound_to_mapped_control():
    nodeid = "tests/validation/test_hardening.py::test_ntp_authenticated"
    control = mapped_control_for_nodeid(nodeid)
    assert control == "TIME-01"
    fallback = automatic_payload(control)
    assert fallback["control_id"] == "TIME-01"
    assert fallback["observed"] == {"evidence_recorded": False}


def test_setup_failure_is_explicit_error_artifact_semantics():
    assert classify_phase_result(
        phase="setup", passed=False, assertion_failure=True, evidence_recorded=False
    ) == "ERROR"


def test_successful_setup_emits_no_control_result():
    assert classify_phase_result(
        phase="setup", passed=True, assertion_failure=False, evidence_recorded=False
    ) is None


def test_teardown_failure_overrides_call_result_as_error():
    assert classify_phase_result(
        phase="teardown", passed=False, assertion_failure=False, evidence_recorded=True
    ) == "ERROR"


def test_call_phase_still_requires_explicit_evidence_for_pass():
    assert classify_phase_result(
        phase="call", passed=True, assertion_failure=False, evidence_recorded=False
    ) == "ERROR"
