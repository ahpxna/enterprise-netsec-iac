#!/usr/bin/env python3
"""Scan every immutable runtime image in the audited image lock with Trivy."""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOCK_PATH = ROOT / "supply-chain/images.lock.yml"


def locked_refs() -> list[str]:
    data = yaml.safe_load(LOCK_PATH.read_text()) or {}
    images = data.get("images") or {}
    refs: list[str] = []
    for name, entry in images.items():
        if entry.get("status") == "deferred":
            raise SystemExit(f"image lock entry {name} is deferred")
        ref = entry.get("pinned_ref")
        if not ref:
            raise SystemExit(f"image lock entry {name} has no pinned_ref")
        refs.append(str(ref))
    return refs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--severity",
        default="HIGH,CRITICAL",
        help="Trivy severity list (default: HIGH,CRITICAL)",
    )
    args = parser.parse_args()
    refs = locked_refs()
    failed = False
    for ref in refs:
        print(f"==> Trivy image scan: {ref}", flush=True)
        result = subprocess.run(
            [
                "trivy",
                "image",
                "--scanners",
                "vuln",
                "--severity",
                args.severity,
                "--exit-code",
                "1",
                ref,
            ],
            cwd=ROOT,
            check=False,
        )
        if result.returncode != 0:
            failed = True
    if failed:
        print("supply-chain image scan FAILED", file=sys.stderr)
        return 1
    print(f"OK: scanned {len(refs)} immutable image references")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
