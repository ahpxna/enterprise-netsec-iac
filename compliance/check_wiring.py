#!/usr/bin/env python3
"""Fail CI when a control points at a missing or duplicate executable proof."""
from __future__ import annotations

import ast
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
controls = yaml.safe_load((ROOT / "compliance/controls.yaml").read_text())["controls"]


def python_functions(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def shell_functions(path: pathlib.Path) -> set[str]:
    return set(re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{", path.read_text()))


def resolve(test_id: str) -> tuple[pathlib.Path | None, str, str | None]:
    try:
        filename, function = test_id.split("::", 1)
    except ValueError:
        return None, "", f"'{test_id}' must use file::function syntax"
    candidates = list(ROOT.glob(f"tests/**/{filename}")) + list(ROOT.glob(f"scripts/{filename}"))
    if len(candidates) != 1:
        return None, function, f"'{filename}' resolved to {len(candidates)} files"
    return candidates[0], function, None


problems: list[str] = []
seen: dict[tuple[str, str], str] = {}
for control in controls:
    for profile, field in (("path-a", "verified_by"), ("path-b", "verified_by_path_b")):
        test_id = control.get(field)
        if not test_id:
            problems.append(f"{control['id']}[{profile}]: missing {field}")
            continue
        key = (profile, test_id)
        if key in seen:
            problems.append(f"{control['id']}[{profile}]: '{test_id}' already assigned to {seen[key]}")
        seen[key] = control["id"]
        path, function, error = resolve(test_id)
        if error:
            problems.append(f"{control['id']}[{profile}]: {error}")
            continue
        assert path is not None
        functions = python_functions(path) if path.suffix == ".py" else shell_functions(path)
        if function not in functions:
            problems.append(f"{control['id']}[{profile}]: function '{function}' absent from {path.relative_to(ROOT)}")

if problems:
    print("Control wiring problems:")
    print("\n".join(f"  - {problem}" for problem in problems))
    sys.exit(1)

print(f"OK: all {len(controls)} controls map one-to-one to executable Path A and Path B proofs.")
