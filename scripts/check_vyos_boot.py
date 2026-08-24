#!/usr/bin/env python3
"""Fail fast on repository-level VyOS 1.4 bootstrap invariants.

This is not a substitute for loading every configuration on the exact pinned
VyOS image. It deliberately catches security and version-drift mistakes that
Terraform itself cannot parse.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIGS = ROOT / "terraform" / "vyos-fabric" / "configs"
FIREWALLS = {"fw-core.boot", "fw-dmz.boot"}


def main() -> int:
    errors: list[str] = []
    paths = sorted(CONFIGS.glob("*.boot"))
    if len(paths) != 8:
        errors.append(f"expected 8 VyOS boot configs, found {len(paths)}")
    for path in paths:
        text = path.read_text()
        syntax = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        if syntax.count("{") != syntax.count("}"):
            errors.append(f"{path.name}: unbalanced curly-brace configuration")
        if not re.search(r"\bservice\s*\{\s*ssh\s*\{", syntax):
            errors.append(f"{path.name}: missing explicit SSH service bootstrap")
        if "plaintext-password" in syntax:
            errors.append(f"{path.name}: plaintext VyOS password is forbidden")
        if "disable-password-authentication" not in syntax:
            errors.append(f"{path.name}: SSH password authentication is not disabled")
        if 'listen-address "MANAGEMENT_IP"' not in syntax:
            errors.append(f"{path.name}: SSH is not bound to the canonical management address placeholder")
        if 'client-keepalive-interval 300' not in syntax or not re.search(r"login\s*\{.*?timeout 300", syntax, re.DOTALL):
            errors.append(f"{path.name}: VyOS management session timeout is not fixed at 300 seconds")
        if 'SSH_KEY_TYPE' not in syntax or 'SSH_KEY_DATA' not in syntax:
            errors.append(f"{path.name}: persistent SSH bootstrap public-key placeholders are missing")
        if "address dhcp" not in syntax or "no-default-route" not in syntax:
            errors.append(f"{path.name}: management DHCP/no-default-route bootstrap is incomplete")
        if path.name in FIREWALLS:
            if not re.search(r"firewall\s*\{.*?ipv4\s*\{.*?forward\s*\{.*?filter\s*\{", syntax, re.DOTALL):
                errors.append(f"{path.name}: missing VyOS 1.4 ipv4 forward filter")
            if re.search(r"firewall\s*\{.*?\bname\s+[A-Z]", syntax, re.DOTALL):
                errors.append(f"{path.name}: legacy pre-1.4 firewall name syntax is forbidden")
            if "input" not in syntax or "Management-plane SSH only" not in syntax:
                errors.append(f"{path.name}: local management-plane firewall is incomplete")
            if path.name == "fw-core.boot" and "Campus and DC egress SNAT" not in syntax:
                errors.append(f"{path.name}: Path A/Path B campus egress NAT parity is missing")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("OK: VyOS 1.4 bootstrap configs satisfy repository invariants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
