#!/usr/bin/env python3
"""Fail closed before a 2026 Authentik deployment can reuse a legacy volume."""
from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent


def legacy_volume_names(project: str) -> set[str]:
    result = subprocess.run(
        ["docker", "volume", "ls", "--format", "{{.Name}}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "cannot list Docker volumes")
    names = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    return {name for name in names if name == "authentik_db" or name == f"{project}_authentik_db"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", default=os.environ.get("COMPOSE_PROJECT_NAME") or ROOT.name)
    args = parser.parse_args()
    try:
        legacy = legacy_volume_names(args.project)
    except RuntimeError as exc:
        print(f"Authentik migration preflight ERROR: {exc}", file=sys.stderr)
        return 2
    if legacy:
        listed = ", ".join(sorted(legacy))
        print("Authentik migration preflight BLOCKED.", file=sys.stderr)
        print(f"Legacy Authentik volume detected: {listed}", file=sys.stderr)
        print("Do not start Authentik 2026.8 against a 2024.8 database.", file=sys.stderr)
        print("Follow docs/AUTHENTIK-UPGRADE.md and migrate on a copy through supported release steps.", file=sys.stderr)
        return 1
    print("OK: no legacy Authentik 2024.8 volume detected; fresh authentik_db_2026 is safe to create")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
