#!/usr/bin/env python3
"""Fail CI if any control's `verified_by` names a test file that doesn't exist.
Cheap guard that keeps controls.yaml honest as tests move around."""
import pathlib, sys, yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
controls = yaml.safe_load((ROOT / "compliance/controls.yaml").read_text())["controls"]

problems = []
for c in controls:
    vb = c["verified_by"]
    fname = vb.split("::")[0]
    # search under tests/ and scripts/
    hits = list(ROOT.glob(f"tests/**/{fname}")) + list(ROOT.glob(f"scripts/{fname}"))
    if not hits:
        problems.append(f"{c['id']}: verified_by '{vb}' -> file '{fname}' not found")

if problems:
    print("Control wiring problems:")
    print("\n".join("  - " + p for p in problems))
    sys.exit(1)
print(f"OK: all {len(controls)} controls point at an existing test/script.")
