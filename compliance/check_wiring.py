#!/usr/bin/env python3
"""Fail CI when a control points at a missing or duplicate executable test."""

from __future__ import annotations

import ast
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
controls = yaml.safe_load((ROOT / "compliance/controls.yaml").read_text())["controls"]


def python_tests(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def shell_functions(path: pathlib.Path) -> set[str]:
    return set(
        re.findall(
            r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{",
            path.read_text(),
        )
    )


problems: list[str] = []
seen: dict[str, str] = {}
for control in controls:
    test_id = control["verified_by"]
    if test_id in seen:
        problems.append(
            f"{control['id']}: '{test_id}' is already assigned to {seen[test_id]}"
        )
    seen[test_id] = control["id"]

    try:
        filename, function = test_id.split("::", 1)
    except ValueError:
        problems.append(f"{control['id']}: '{test_id}' must use file::function syntax")
        continue

    candidates = list(ROOT.glob(f"tests/**/{filename}")) + list(
        ROOT.glob(f"scripts/{filename}")
    )
    if len(candidates) != 1:
        problems.append(
            f"{control['id']}: '{filename}' resolved to {len(candidates)} files"
        )
        continue

    path = candidates[0]
    functions = python_tests(path) if path.suffix == ".py" else shell_functions(path)
    if function not in functions:
        problems.append(
            f"{control['id']}: function '{function}' is absent from {path.relative_to(ROOT)}"
        )

if problems:
    print("Control wiring problems:")
    print("\n".join(f"  - {problem}" for problem in problems))
    sys.exit(1)

print(f"OK: all {len(controls)} controls map one-to-one to executable tests.")
