#!/usr/bin/env python3
"""Emit a schema-v1 evidence artifact for non-pytest test runners."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
from datetime import datetime, timezone


ROOT = pathlib.Path(__file__).resolve().parent.parent


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def suite_digest() -> str:
    value = hashlib.sha256()
    for path in sorted((ROOT / "tests").rglob("*.py")):
        value.update(path.relative_to(ROOT).as_posix().encode())
        value.update(path.read_bytes())
    value.update((ROOT / "scripts" / "attack_chain.sh").read_bytes())
    return value.hexdigest()


def coerce(value: str):
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-id", required=True)
    parser.add_argument("--control", required=True)
    parser.add_argument("--result", required=True, choices=("PASS", "FAIL", "ERROR"))
    parser.add_argument("--assertion", required=True)
    parser.add_argument("--enforcement-node")
    parser.add_argument("--counter-before", type=int)
    parser.add_argument("--counter-after", type=int)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--observed", action="append", default=[])
    args = parser.parse_args()

    observed = {}
    for item in args.observed:
        key, separator, value = item.partition("=")
        if not separator:
            parser.error(f"--observed must be key=value, got {item!r}")
        observed[key] = coerce(value)

    git = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False
    ).stdout.strip() or "unknown"
    payload = {
        "schema_version": 1,
        "control_id": args.control,
        "test_id": args.test_id,
        "result": args.result,
        "assertion": args.assertion,
        "observed": observed,
        "enforcement_node": args.enforcement_node,
        "counter_before": args.counter_before,
        "counter_after": args.counter_after,
        "failure": None if args.result == "PASS" else observed.get("failure"),
        "started_at": args.started_at,
        "ended_at": now(),
        "run_id": os.environ.get("EVIDENCE_RUN_ID", pathlib.Path(os.environ.get("EVIDENCE_DIR", "adhoc")).name),
        "git_sha": os.environ.get("GIT_SHA", git),
        "control_catalog_sha256": digest(ROOT / "compliance" / "controls.yaml"),
        "topology_sha256": digest(ROOT / "intent" / "fabric.yaml"),
        "test_suite_sha256": suite_digest(),
        "environment": os.environ.get("LAB_ENVIRONMENT", "local-containerlab"),
    }
    directory = ROOT / os.environ.get("EVIDENCE_DIR", "evidence/runs/adhoc")
    directory.mkdir(parents=True, exist_ok=True)
    filename = args.test_id.replace("/", "__").replace("::", "__") + ".json"
    (directory / filename).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
