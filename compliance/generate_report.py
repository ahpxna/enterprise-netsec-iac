#!/usr/bin/env python3
"""Generate a fail-closed compliance report from explicit evidence results."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from compliance.provenance import current_provenance
VALID_RESULTS = {"PASS", "FAIL", "ERROR"}
REQUIRED_FIELDS = {
    "schema_version", "control_id", "test_id", "result", "assertion",
    "observed", "started_at", "ended_at", "run_id", "git_sha", "git_dirty",
    "source_tree_sha256", "control_catalog_sha256", "topology_sha256",
    "test_suite_sha256", "environment",
}


def latest_run(runs_root: pathlib.Path) -> pathlib.Path | None:
    runs = sorted(path for path in runs_root.glob("*") if path.is_dir())
    return runs[-1] if runs else None


def load_evidence(run: pathlib.Path | None) -> tuple[list[dict], list[str]]:
    evidence: list[dict] = []
    errors: list[str] = []
    if run is None:
        return evidence, errors
    for path in sorted(run.glob("*.json")):
        try:
            payload = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{path.name}: invalid JSON: {exc}")
            continue
        missing = sorted(REQUIRED_FIELDS - payload.keys())
        if missing:
            errors.append(f"{path.name}: missing fields: {', '.join(missing)}")
            continue
        if payload["schema_version"] != 1:
            errors.append(f"{path.name}: unsupported schema_version")
            continue
        if payload["result"] not in VALID_RESULTS:
            errors.append(f"{path.name}: invalid result {payload['result']!r}")
            continue
        evidence.append(payload)
    return evidence, errors


def validate_provenance(evidence: list[dict], run: pathlib.Path | None, *, strict: bool = False, profile: str = "path-a") -> list[str]:
    """Reject mixed, stale, dirty, unknown, or mislabelled evidence runs."""
    if not evidence:
        return []
    expected = current_provenance()
    run_id = run.name if run else None
    errors: list[str] = []
    baseline = evidence[0]
    fields = (
        "git_sha", "git_dirty", "source_tree_sha256", "control_catalog_sha256",
        "topology_sha256", "test_suite_sha256", "environment",
    )
    for item in evidence:
        label = item["test_id"]
        if run_id and item["run_id"] != run_id:
            errors.append(f"{label}: run_id does not match evidence directory")
        for field in fields:
            if item[field] != baseline[field]:
                errors.append(f"{label}: mixed provenance field {field}")
        for field, value in expected.items():
            if item[field] != value:
                errors.append(f"{label}: stale {field}")
    if profile == "path-b" and baseline.get("environment") != "path-b":
        errors.append("evidence environment is not Path B")
    if profile == "path-a" and baseline.get("environment") == "path-b":
        errors.append("Path B evidence cannot satisfy a Path A report")
    if strict:
        if baseline.get("git_sha") == "unknown":
            errors.append("strict report requires a resolvable Git SHA")
        if baseline.get("git_dirty"):
            errors.append("strict report refuses evidence produced from a dirty worktree; commit/review the source first")
    return errors


def verified_test_suffix(verified_by: str) -> str:
    filename, test_name = verified_by.split("::", 1)
    return f"/{filename}::{test_name}"


def verifier_for(control: dict, profile: str) -> str:
    return control["verified_by_path_b"] if profile == "path-b" else control["verified_by"]


def status_for(control: dict, evidence: list[dict], profile: str = "path-a") -> tuple[str, dict | None]:
    verified_by = verifier_for(control, profile)
    suffix = verified_test_suffix(verified_by)
    matches = [
        item for item in evidence
        if item["control_id"] == control["id"]
        and (item["test_id"].endswith(suffix) or item["test_id"] == verified_by)
    ]
    if not matches:
        return "UNVERIFIED", None
    latest = matches[-1]
    return latest["result"], latest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="evidence/COMPLIANCE-REPORT.md")
    parser.add_argument("--run", type=pathlib.Path)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--profile", choices=("path-a", "path-b"), default="path-a")
    args = parser.parse_args()

    controls = yaml.safe_load((ROOT / "compliance" / "controls.yaml").read_text())["controls"]
    default_root = ROOT / "evidence" / "runs"
    run = args.run or latest_run(default_root)
    if run is not None and not run.is_absolute():
        run = ROOT / run
    evidence, artifact_errors = load_evidence(run)
    artifact_errors.extend(validate_provenance(evidence, run, strict=args.strict, profile=args.profile))

    counts = {"PASS": 0, "FAIL": 0, "ERROR": 0, "UNVERIFIED": 0}
    badges = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️", "UNVERIFIED": "⚪"}
    rows = []
    for control in controls:
        status, artifact = status_for(control, evidence, args.profile)
        counts[status] += 1
        frameworks = control["framework"]
        framework_text = ", ".join(frameworks) if isinstance(frameworks, list) else frameworks
        verifier = verifier_for(control, args.profile)
        evidence_ref = artifact["test_id"] if artifact else "none"
        rows.append(
            f"| {control['id']} | {framework_text} | {control['severity']} | "
            f"`{verifier}` | {badges[status]} {status} | `{evidence_ref}` |"
        )
    if artifact_errors:
        counts["ERROR"] += len(artifact_errors)

    run_name = run.name if run else "none"
    provenance = evidence[0] if evidence else {}
    md = [
        "# CompanyXYZ-NG — Compliance & Control Validation Report", "",
        f"_Profile: `{args.profile}` · Evidence run: `{run_name}` · Git SHA: `{provenance.get('git_sha', 'unknown')}`._", "",
        "> PASS requires a schema-valid artifact with an explicit `result: PASS` from the selected deployment profile. "
        "Path A evidence can never substitute for Path B evidence.", "",
        f"**Summary:** {counts['PASS']} passed · {counts['FAIL']} failed · "
        f"{counts['ERROR']} error · {counts['UNVERIFIED']} unverified "
        f"(of {len(controls)} controls)", "",
        "| Control | Framework | Severity | Verified by | Status | Evidence |",
        "|---------|-----------|----------|-------------|--------|----------|",
        *rows,
    ]
    if artifact_errors:
        md.extend(["", "## Invalid artifacts", ""])
        md.extend(f"- {error}" for error in artifact_errors)

    output = ROOT / args.out
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(md) + "\n")
    print(
        f"wrote {output} ({counts['PASS']} pass / {counts['FAIL']} fail / "
        f"{counts['ERROR']} error / {counts['UNVERIFIED']} unverified)"
    )
    nonpass = counts["PASS"] != len(controls) or any(counts[key] for key in ("FAIL", "ERROR", "UNVERIFIED"))
    return 1 if args.strict and nonpass else 0


if __name__ == "__main__":
    raise SystemExit(main())
