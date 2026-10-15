#!/usr/bin/env python3
"""Wazuh Active Response: reversible endpoint isolation (stdlib only, Linux/nftables).

Installed on managed endpoints twice, under two fixed names that select the mode:

    cxyz-isolate-endpoint   apply isolation
    cxyz-restore-endpoint   remove isolation

The Response Orchestrator triggers them through the Wazuh API with one argument,
the operation id (the response idempotency key).  There is no other input: no
target host, command, rule or script path is ever taken from the request.

Isolation installs a dedicated nftables table (``inet cxyz_isolation``) that drops
all traffic except loopback, established flows and the Wazuh manager / management
addresses listed in ``/var/ossec/etc/cxyz-isolation.json``.  After the ruleset is
active a marker file is written under ``/var/ossec/var/cxyz-isolation/``; Wazuh
FIM watches that directory, so "marker present in FIM" is the read-only proof the
orchestrator uses to verify enforcement, and "marker absent" proves restoration.
The marker name is ``sha256(op)[:40]`` and is removed only after the ruleset is.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from hashlib import sha256
from pathlib import Path
from typing import Callable, Sequence

CONFIG = Path("/var/ossec/etc/cxyz-isolation.json")
MARKER_DIR = Path("/var/ossec/var/cxyz-isolation")
LOG = Path("/var/ossec/logs/active-responses.log")
TABLE = ("inet", "cxyz_isolation")
OP_ID = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
Runner = Callable[[Sequence[str], str | None], "subprocess.CompletedProcess[str]"]


def marker_name(op: str) -> str:
    return sha256(op.encode()).hexdigest()[:40]


def _run(argv: Sequence[str], stdin: str | None = None) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(list(argv), input=stdin, capture_output=True, text=True, timeout=10, check=False)


def log(message: str, path: Path = LOG) -> None:
    try:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{time.strftime('%Y/%m/%d %H:%M:%S')} cxyz-isolation: {message}\n")
    except OSError:
        pass


def load_allowed(config: Path) -> list[str]:
    data = json.loads(config.read_text(encoding="utf-8"))
    allowed = [str(ipaddress.ip_address(item)) for item in data.get("allowed_addresses", [])]
    if not allowed:
        raise ValueError("isolation refused: no manager/management address is configured")
    return allowed


def ruleset(allowed: Sequence[str]) -> str:
    v4 = [a for a in allowed if ":" not in a]
    v6 = [a for a in allowed if ":" in a]
    lines = [
        f"add table {TABLE[0]} {TABLE[1]}",
        f"delete table {TABLE[0]} {TABLE[1]}",
        f"add table {TABLE[0]} {TABLE[1]}",
    ]
    for hook in ("input", "output", "forward"):
        lines.append(
            f"add chain {TABLE[0]} {TABLE[1]} {hook} {{ type filter hook {hook} priority -150; policy drop; }}"
        )
    rules = []
    for hook, direction in (("input", "saddr"), ("output", "daddr")):
        rules.append(f"add rule {TABLE[0]} {TABLE[1]} {hook} iifname lo accept" if hook == "input"
                     else f"add rule {TABLE[0]} {TABLE[1]} {hook} oifname lo accept")
        rules.append(f"add rule {TABLE[0]} {TABLE[1]} {hook} ct state established,related accept")
        if v4:
            rules.append(f"add rule {TABLE[0]} {TABLE[1]} {hook} ip {direction} {{ {', '.join(v4)} }} accept")
        if v6:
            rules.append(f"add rule {TABLE[0]} {TABLE[1]} {hook} ip6 {direction} {{ {', '.join(v6)} }} accept")
    return "\n".join(lines + rules) + "\n"


def isolate(op: str, *, config: Path = CONFIG, marker_dir: Path = MARKER_DIR, run: Runner = _run) -> None:
    if not OP_ID.fullmatch(op):
        raise ValueError("invalid operation id")
    allowed = load_allowed(config)
    result = run(["nft", "-f", "-"], ruleset(allowed))
    if result.returncode != 0:
        raise RuntimeError("nft refused the isolation ruleset")
    marker_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = marker_dir / marker_name(op)
    marker.write_text(json.dumps({"op": marker_name(op), "at": int(time.time())}), encoding="utf-8")
    marker.chmod(0o600)
    log(f"isolated op={marker_name(op)}")


def restore(op: str, *, marker_dir: Path = MARKER_DIR, run: Runner = _run) -> None:
    if not OP_ID.fullmatch(op):
        raise ValueError("invalid operation id")
    result = run(["nft", "delete", "table", TABLE[0], TABLE[1]], None)
    if result.returncode != 0 and "No such file" not in result.stderr:
        raise RuntimeError("nft could not remove the isolation table")
    (marker_dir / marker_name(op)).unlink(missing_ok=True)
    log(f"restored op={marker_name(op)}")


def main(argv: Sequence[str] | None = None, stdin=None) -> int:
    argv = list(sys.argv if argv is None else argv)
    mode = os.path.basename(argv[0])
    if mode not in {"cxyz-isolate-endpoint", "cxyz-restore-endpoint"}:
        print("must be invoked as cxyz-isolate-endpoint or cxyz-restore-endpoint", file=sys.stderr)
        return 2
    try:
        message = json.loads((stdin or sys.stdin).readline())
        command = message.get("command")
        args = message.get("parameters", {}).get("extra_args", [])
        if command not in {"add", "delete"} or len(args) != 1:
            raise ValueError("unsupported Active Response request")
        # "delete" is Wazuh's own timeout-driven reversal; it always restores.
        if mode == "cxyz-isolate-endpoint" and command == "add":
            isolate(str(args[0]))
        else:
            restore(str(args[0]))
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as exc:
        log(f"failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
