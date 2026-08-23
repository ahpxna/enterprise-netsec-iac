#!/usr/bin/env python3
"""Generate a fail-closed compliance report from explicit evidence results."""

from __future__ import annotations

import argparse
import json
import pathlib

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
VALID_RESULTS = {"PASS", "FAIL", "ERROR"}
REQUIRED_FIELDS = {
    "schema_version", "control_id", "test_id", "result", "assertion",
    "observed", "started_at", "ended_at", "run_id", "git_sha",
    "control_catalog_sha256", "topology_sha256", "test_suite_sha256",
    "environment",
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


def verified_test_suffix(verified_by: str) -> str:
    filename, test_name = verified_by.split("::", 1)
    return f"/{filename}::{test_name}"


def status_for(control: dict, evidence: list[dict]) -> tuple[str, dict | None]:
    suffix = verified_test_suffix(control["verified_by"])
    matches = [
        item for item in evidence
        if item["control_id"] == control["id"]
        and (item["test_id"].endswith(suffix)
             or item["test_id"] == control["verified_by"])
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
    args = parser.parse_args()

    controls = yaml.safe_load((ROOT / "compliance" / "controls.yaml").read_text())["controls"]
    run = args.run or latest_run(ROOT / "evidence" / "runs")
    if run is not None and not run.is_absolute():
        run = ROOT / run
    evidence, artifact_errors = load_evidence(run)

    counts = {"PASS": 0, "FAIL": 0, "ERROR": 0, "UNVERIFIED": 0}
    badges = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️", "UNVERIFIED": "⚪"}
    rows = []
    for control in controls:
        status, artifact = status_for(control, evidence)
        counts[status] += 1
        frameworks = control["framework"]
        framework_text = ", ".join(frameworks) if isinstance(frameworks, list) else frameworks
        evidence_ref = artifact["test_id"] if artifact else "none"
        rows.append(
            f"| {control['id']} | {framework_text} | {control['severity']} | "
            f"`{control['verified_by']}` | {badges[status]} {status} | `{evidence_ref}` |"
        )
    if artifact_errors:
        counts["ERROR"] += len(artifact_errors)

    run_name = run.name if run else "none"
    provenance = evidence[0] if evidence else {}
    md = [
        "# CompanyXYZ-NG — Compliance & Control Validation Report", "",
        f"_Evidence run: `{run_name}` · Git SHA: `{provenance.get('git_sha', 'unknown')}`._", "",
        "> PASS requires a schema-valid artifact with an explicit `result: PASS`. "
        "File presence alone never grants PASS.", "",
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
    nonpass = counts["PASS"] != len(controls) or any(
        counts[key] for key in ("FAIL", "ERROR", "UNVERIFIED")
    )
    return 1 if args.strict and nonpass else 0


if __name__ == "__main__":
    raise SystemExit(main())
