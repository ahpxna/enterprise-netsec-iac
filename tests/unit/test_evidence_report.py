import json
import pathlib

from compliance.generate_report import load_evidence, status_for, validate_provenance


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
        "git_dirty": False,
        "source_tree_sha256": "tree",
        "control_catalog_sha256": "a",
        "topology_sha256": "b",
        "test_suite_sha256": "c",
        "environment": "unit",
    }


CONTROL = {
    "id": "SEG-01",
    "verified_by": "test_segmentation.py::test_user_vlan_blocked_from_radius",
    "verified_by_path_b": "path_b_audit.py::test_seg01",
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


def test_mixed_provenance_is_rejected(tmp_path: pathlib.Path):
    first = artifact("PASS")
    second = artifact("PASS")
    second["git_sha"] = "different"
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
