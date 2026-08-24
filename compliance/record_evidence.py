#!/usr/bin/env python3
"""Emit a schema-v1 evidence artifact for non-pytest test runners."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from datetime import datetime, timezone


ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from compliance.provenance import current_provenance


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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

    provenance = current_provenance()
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
        **provenance,
        "environment": os.environ.get("LAB_ENVIRONMENT", "local-containerlab"),
    }
    directory = ROOT / os.environ.get("EVIDENCE_DIR", "evidence/runs/adhoc")
    directory.mkdir(parents=True, exist_ok=True)
    filename = args.test_id.replace("/", "__").replace("::", "__") + ".json"
    (directory / filename).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
