#!/usr/bin/env python3
"""Parse repository YAML syntax while allowing application-specific YAML tags.

`yaml.safe_load` intentionally rejects Authentik Blueprint tags such as !Env
and !Find.  `yaml.compose_all` still validates YAML structure/indentation while
preserving unknown tags as nodes, which is the correct static syntax check.
"""
from __future__ import annotations

import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP_PARTS = {".git", ".terraform", "evidence", "__pycache__"}


def main() -> int:
    errors: list[str] = []
    files = 0
    docs = 0
    for path in sorted(ROOT.rglob("*")):
        if path.suffix.lower() not in {".yaml", ".yml"} or not path.is_file():
            continue
        if any(part in SKIP_PARTS for part in path.relative_to(ROOT).parts):
            continue
        files += 1
        try:
            parsed = list(yaml.compose_all(path.read_text()))
            docs += len(parsed)
        except yaml.YAMLError as exc:
            errors.append(f"{path.relative_to(ROOT)}: {exc}")
    if errors:
        print("YAML syntax errors:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1
    print(f"OK: YAML syntax parsed for {files} files / {docs} documents (custom tags preserved)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
