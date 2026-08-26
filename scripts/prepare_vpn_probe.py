#!/usr/bin/env python3
"""Build a VPN-01 client config that traverses the host-published UDP entrypoint."""
from __future__ import annotations

import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "wireguard/config/peer1/peer1.conf"
DEST = ROOT / "wireguard/probe/wg_confs/wg0.conf"
TARGET = "172.16.50.1/32"


def env_value(name: str, default: str) -> str:
    configured = os.environ.get(name)
    if configured:
        return configured
    env_file = ROOT / ".env"
    if env_file.exists():
        for raw in env_file.read_text().splitlines():
            key, sep, value = raw.partition("=")
            if sep and key.strip() == name:
                value = value.strip().strip('"').strip("'")
                return value or default
    return default


def main() -> int:
    if not SOURCE.exists():
        print(
            f"missing {SOURCE.relative_to(ROOT)}; start the WireGuard server first (make security)",
            file=sys.stderr,
        )
        return 1
    try:
        port = int(env_value("WG_SERVER_PORT", "51820"))
    except ValueError:
        print("WG_SERVER_PORT must be an integer", file=sys.stderr)
        return 1
    if not 1 <= port <= 65535:
        print("WG_SERVER_PORT must be between 1 and 65535", file=sys.stderr)
        return 1

    text = SOURCE.read_text()
    if "[Interface]" not in text or "[Peer]" not in text:
        print("peer1.conf does not look like a WireGuard client profile", file=sys.stderr)
        return 1
    text, endpoint_count = re.subn(
        r"(?m)^Endpoint\s*=.*$", f"Endpoint = host.docker.internal:{port}", text, count=1
    )
    text, allowed_count = re.subn(
        r"(?m)^AllowedIPs\s*=.*$", f"AllowedIPs = {TARGET}", text, count=1
    )
    if endpoint_count != 1 or allowed_count != 1:
        print("peer1.conf is missing Endpoint or AllowedIPs", file=sys.stderr)
        return 1
    DEST.parent.mkdir(parents=True, exist_ok=True)
    DEST.write_text(text)
    DEST.chmod(0o600)
    print(f"rendered ignored VPN probe config: {DEST.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
