import json
import pathlib

from compliance.generate_report import load_evidence, status_for


def artifact(result: str) -> dict:
    return {
        "schema_version": 1,
        "control_id": "SEG-01",
        "test_id": "tests/validation/test_segmentation.py::test_user_vlan_blocked_from_radius",
        "result": result,
        "assertion": "blocked and counter increased",
        "observed": {},
        "started_at": "2026-01-01T00:00:00Z",
        "ended_at": "2026-01-01T00:00:01Z",
        "run_id": "unit",
        "git_sha": "abc",
        "control_catalog_sha256": "a",
        "topology_sha256": "b",
        "test_suite_sha256": "c",
        "environment": "unit",
    }


CONTROL = {
    "id": "SEG-01",
    "verified_by": "test_segmentation.py::test_user_vlan_blocked_from_radius",
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
