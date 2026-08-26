#!/usr/bin/env python3
"""Physically detach untrusted Path A endpoints from Docker OOB management.

Containerlab needs the management network during bootstrap, but PC1 and the DMZ
web host are production-untrusted endpoints.  `docker exec`/the Ansible Docker
connection do not require a container network attachment, so after deployment
we remove their persistent L2 path instead of merely setting eth0 DOWN.
"""
from __future__ import annotations

import subprocess
import sys

NETWORK = "cxyz_mgmt"
ENDPOINTS = ("clab-companyxyz-pc1", "clab-companyxyz-dmz-web")


def run(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def attached(container: str) -> bool:
    result = run("docker", "network", "inspect", NETWORK, "--format", "{{json .Containers}}")
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"cannot inspect Docker network {NETWORK}")
    return container in result.stdout


def main() -> int:
    for container in ENDPOINTS:
        if not attached(container):
            continue
        result = run("docker", "network", "disconnect", "-f", NETWORK, container)
        if result.returncode != 0:
            print(f"failed to detach {container} from {NETWORK}: {result.stderr.strip()}", file=sys.stderr)
            return 1
    remaining = [container for container in ENDPOINTS if attached(container)]
    if remaining:
        print(f"untrusted endpoints still attached to {NETWORK}: {', '.join(remaining)}", file=sys.stderr)
        return 1
    print(f"OK: untrusted Path A endpoints are physically detached from {NETWORK}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
