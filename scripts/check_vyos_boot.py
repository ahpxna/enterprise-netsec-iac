#!/usr/bin/env python3
"""Fail fast on repository-level VyOS bootstrap invariants.

This is intentionally not a substitute for loading the configuration on the
pinned VyOS image. It catches mistakes Terraform cannot see before a VM apply.
"""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIGS = ROOT / "terraform" / "vyos-fabric" / "configs"


def main() -> int:
    errors: list[str] = []
    for path in sorted(CONFIGS.glob("*.boot")):
        text = path.read_text()
        # Comments can include braces, so strip them before a structural check.
        syntax = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        if syntax.count("{") != syntax.count("}"):
            errors.append(f"{path.name}: unbalanced curly-brace configuration")
        if not re.search(r"\bservice\s*\{\s*ssh\s*\{", syntax):
            errors.append(f"{path.name}: missing explicit SSH service bootstrap")
        if "plaintext-password" in syntax:
            errors.append(f"{path.name}: plaintext VyOS password is forbidden")
        if "address dhcp" not in syntax or "no-default-route" not in syntax:
            errors.append(f"{path.name}: management DHCP/no-default-route bootstrap is incomplete")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("OK: VyOS bootstrap configs satisfy repository invariants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
