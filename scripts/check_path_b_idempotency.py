#!/usr/bin/env python3
"""Run Path B Day-2 a second time and require a zero-change Ansible recap."""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ANSIBLE = ROOT / "ansible"
EXPECTED = {"isp1", "isp2", "edge", "core", "dist1", "dist2", "fw-core", "fw-dmz", "pc1", "pc4", "server1", "dmz-web"}
RECAP = re.compile(
    r"^(?P<host>\S+)\s*:\s*ok=(?P<ok>\d+)\s+changed=(?P<changed>\d+)\s+"
    r"unreachable=(?P<unreachable>\d+)\s+failed=(?P<failed>\d+)",
    re.MULTILINE,
)


def main() -> int:
    result = subprocess.run(
        ["ansible-playbook", "-i", "inventory/vm-fabric.yml", "playbooks/31-path-b.yml"],
        cwd=ANSIBLE,
        capture_output=True,
        text=True,
        check=False,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode != 0:
        print("Path B idempotency run failed", file=sys.stderr)
        return 1
    recap = {match.group("host"): {k: int(match.group(k)) for k in ("changed", "unreachable", "failed")} for match in RECAP.finditer(result.stdout)}
    missing = EXPECTED - recap.keys()
    dirty = {host: values for host, values in recap.items() if any(values.values())}
    if missing or dirty:
        if missing:
            print("missing Path B recap host(s): " + ", ".join(sorted(missing)), file=sys.stderr)
        if dirty:
            print("non-idempotent/unhealthy Path B recap: " + repr(dirty), file=sys.stderr)
        return 1
    print("OK: Path B Day-2 second run changed=0, unreachable=0, failed=0 on all 12 nodes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
