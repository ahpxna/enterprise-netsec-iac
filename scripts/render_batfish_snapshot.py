#!/usr/bin/env python3
"""Render the minimal complete Batfish model used by offline policy gates."""

from __future__ import annotations

import argparse
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
INTENT = yaml.safe_load((ROOT / "intent/fabric.yaml").read_text())
CONFIG_DIR = ROOT / "tests/batfish/snapshots/configs"


def address(node: str, link: str) -> str:
    return next(
        item["address"]
        for item in INTENT["nodes"][node]["attachments"]
        if item["link"] == link
    )


def ios_interface(name: str, ip: str, *, acl: str | None = None) -> str:
    lines = [f"interface {name}", f" ip address {ip.replace('/', ' ')}", " no shutdown"]
    if acl:
        lines.append(f" ip access-group {acl} in")
    return "\n".join(lines)


def prefix_to_mask(value: str) -> str:
    address_value, prefix = value.split("/")
    prefix_value = int(prefix)
    mask = (0xFFFFFFFF << (32 - prefix_value)) & 0xFFFFFFFF
    dotted = ".".join(str((mask >> shift) & 0xFF) for shift in (24, 16, 8, 0))
    return f"{address_value} {dotted}"


def render() -> dict[str, str]:
    dist1 = "\n".join(
        [
            "hostname dist1",
            ios_interface("Ethernet0", prefix_to_mask(address("dist1", "core_dist1"))),
            ios_interface("Ethernet1", prefix_to_mask(address("dist1", "vlan10"))),
            "ip route 0.0.0.0 0.0.0.0 10.255.1.0",
            "",
        ]
    )
    core = "\n".join(
        [
            "hostname core",
            ios_interface("Ethernet0", prefix_to_mask(address("core", "fwcore_core"))),
            ios_interface("Ethernet1", prefix_to_mask(address("core", "core_dist1"))),
            "ip route 192.168.10.0 255.255.255.0 10.255.1.1",
            "ip route 172.16.50.0 255.255.255.0 10.255.0.5",
            "",
        ]
    )
    fw_core = "\n".join(
        [
            "hostname fw-core",
            ios_interface("Ethernet0", prefix_to_mask(address("fw-core", "edge_fwcore"))),
            ios_interface(
                "Ethernet1",
                prefix_to_mask(address("fw-core", "fwcore_core")),
                acl="CAMPUS_IN",
            ),
            ios_interface("Ethernet2", prefix_to_mask(address("fw-core", "dc"))),
            "ip route 192.168.10.0 255.255.255.0 10.255.0.6",
            "ip access-list extended CAMPUS_IN",
            " permit udp 192.168.10.0 0.0.0.255 172.16.50.0 0.0.0.255 eq 53",
            " permit udp 192.168.10.0 0.0.0.255 172.16.50.0 0.0.0.255 eq 123",
            " deny udp 192.168.10.0 0.0.0.255 host 172.16.50.1 eq 1812 log",
            " deny ip 192.168.10.0 0.0.0.255 172.16.50.0 0.0.0.255 log",
            " permit ip 192.168.0.0 0.0.255.255 any",
            "",
        ]
    )
    return {"dist1.cfg": dist1, "core.cfg": core, "fw-core.cfg": fw_core}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = render()
    drift = [name for name, body in rendered.items() if not (CONFIG_DIR / name).exists() or (CONFIG_DIR / name).read_text() != body]
    stale = [path.name for path in CONFIG_DIR.glob("*.cfg") if path.name not in rendered]
    if args.check:
        if drift or stale:
            print(f"Batfish snapshot drift: missing/stale={drift + stale}", file=sys.stderr)
            return 1
        print("OK: Batfish snapshot matches canonical fabric intent")
        return 0
    for path in CONFIG_DIR.glob("*.cfg"):
        if path.name not in rendered:
            path.unlink()
    for name, body in rendered.items():
        (CONFIG_DIR / name).write_text(body)
    print(f"rendered {len(rendered)} Batfish configs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
