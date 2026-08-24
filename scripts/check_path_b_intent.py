#!/usr/bin/env python3
"""Detect Path B drift between canonical intent and reviewed VyOS configs.

Terraform derives NIC ordering directly from intent/fabric.yaml.  This check
makes the corresponding config.boot interface addresses and static routes part
of the same fail-closed contract so a topology edit cannot silently leave the
VyOS guest configuration behind.
"""
from __future__ import annotations

import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
INTENT = yaml.safe_load((ROOT / "intent" / "fabric.yaml").read_text())
CONFIG_DIR = ROOT / "terraform" / "vyos-fabric" / "configs"
VYOS_NODES = ("isp1", "isp2", "edge", "fw-core", "core", "dist1", "dist2", "fw-dmz")


def strip_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def named_block(text: str, pattern: str) -> str | None:
    match = re.search(pattern + r"\s*\{", text)
    if not match:
        return None
    start = match.end()
    depth = 1
    i = start
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i]
        i += 1
    return None


def normalize(value: str) -> str:
    return value.strip().strip('"\'')


def main() -> int:
    errors: list[str] = []
    for node_name in VYOS_NODES:
        node = INTENT["nodes"][node_name]
        path = CONFIG_DIR / f"{node_name}.boot"
        body = strip_comments(path.read_text())
        attachments = node.get("attachments", [])

        for index, attachment in enumerate(attachments):
            block = named_block(body, rf"\bethernet\s+eth{index}\b")
            if block is None:
                errors.append(f"{path.name}: missing eth{index} for intent attachment {attachment['link']}")
                continue
            addresses = [normalize(v) for v in re.findall(r"\baddress\s+([^\s;{}]+)", block)]
            expected = str(attachment["address"])
            if expected not in addresses:
                errors.append(f"{path.name}: eth{index} address drift: intent={expected}, config={addresses or ['<missing>']}")

        mgmt_index = len(attachments)
        mgmt = named_block(body, rf"\bethernet\s+eth{mgmt_index}\b")
        if mgmt is None:
            errors.append(f"{path.name}: missing management eth{mgmt_index}")
        else:
            if not re.search(r"\baddress\s+dhcp\b", mgmt):
                errors.append(f"{path.name}: management eth{mgmt_index} is not DHCP")
            if "no-default-route" not in mgmt:
                errors.append(f"{path.name}: management eth{mgmt_index} can import a default route")

        for route in node.get("routes", []):
            destination = re.escape(str(route["to"]))
            via = re.escape(str(route["via"]))
            route_pattern = rf"\broute\s+{destination}\s*\{{[^{{}}]*?next-hop\s+{via}(?:\s|\}})"
            if not re.search(route_pattern, body, flags=re.S):
                errors.append(f"{path.name}: missing intent static route {route['to']} via {route['via']}")

    if errors:
        print("Path B intent/config drift detected:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1
    print("OK: Path B VyOS interface and static-route configs match canonical intent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
