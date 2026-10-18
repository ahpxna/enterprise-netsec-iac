#!/usr/bin/env python3
"""HA-01: did routed user traffic keep flowing through the backup gateway while the master was down?

Input: the `ping -D` capture from pc1 (each reply line starts with `[unix time]`) and the times at which
dist1's user-facing interface was shut down and restored. Prints one JSON object; exits 0 only if the
longest interruption inside that window (from the shutdown, between replies, until the restore) stays
under the bound and enough replies arrived while the master was down.

The previous check took the largest gap between successful replies anywhere in the capture. When no
reply came back after the failover at all, the gaps before it were small and HA-01 passed. That is what
the first Linux run recorded: 13 replies, "Destination Net Unreachable", then nothing, and a PASS.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Iterable

REPLY = re.compile(r"^\[(\d+(?:\.\d+)?)\].*\bbytes from\b")


def analyse(lines: Iterable[str], failover_at: float, restored_at: float, *,
            bound: float = 5.0, min_replies: int = 5) -> dict:
    replies = [float(match.group(1)) for line in lines if (match := REPLY.match(line))]
    during = [moment for moment in replies if failover_at < moment < restored_at]
    edges = [failover_at, *during, restored_at]
    interruption = max(later - earlier for earlier, later in zip(edges, edges[1:]))
    recovery = during[0] - failover_at if during else None
    return {
        "replies_total": len(replies),
        "replies_while_master_down": len(during),
        "outage_window_seconds": round(restored_at - failover_at, 3),
        "recovery_seconds": None if recovery is None else round(recovery, 3),
        "max_interruption_seconds": round(interruption, 3),
        "pass": bool(during) and len(during) >= min_replies and interruption < bound,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("usage: vrrp_failover_check.py PING_CAPTURE FAILOVER_AT RESTORED_AT", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8", errors="replace") as capture:
        result = analyse(capture, float(argv[2]), float(argv[3]))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
