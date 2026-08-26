#!/usr/bin/env python3
"""Parse repository YAML while preserving custom tags and rejecting duplicate keys.

Authentik Blueprints use tags such as !Env/!Find, so safe_load is intentionally
not used. compose_all validates syntax without constructing those tags; a small
node walk additionally rejects duplicate mapping keys, which Kustomize also
rejects and which plain PyYAML composition otherwise permits.
"""
from __future__ import annotations

import pathlib
import sys

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP_PARTS = {".git", ".terraform", "evidence", "__pycache__"}


def duplicate_key_errors(node: Node | None, path: str = "$.") -> list[str]:
    if node is None:
        return []
    errors: list[str] = []
    if isinstance(node, MappingNode):
        seen: dict[str, int] = {}
        for key_node, value_node in node.value:
            key = key_node.value if isinstance(key_node, ScalarNode) else repr(key_node.value)
            line = key_node.start_mark.line + 1
            if key in seen:
                errors.append(f"{path}: duplicate mapping key {key!r} at line {line} (first at line {seen[key]})")
            else:
                seen[key] = line
            errors.extend(duplicate_key_errors(value_node, f"{path}{key}."))
    elif isinstance(node, SequenceNode):
        for index, child in enumerate(node.value):
            errors.extend(duplicate_key_errors(child, f"{path}[{index}]."))
    return errors


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
            for index, document in enumerate(parsed, start=1):
                for error in duplicate_key_errors(document, f"doc[{index}]."):
                    errors.append(f"{path.relative_to(ROOT)}: {error}")
        except yaml.YAMLError as exc:
            errors.append(f"{path.relative_to(ROOT)}: {exc}")
    if errors:
        print("YAML syntax/structure errors:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1
    print(f"OK: YAML syntax parsed for {files} files / {docs} documents; duplicate keys rejected (custom tags preserved)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
