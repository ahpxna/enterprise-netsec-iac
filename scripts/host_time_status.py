#!/usr/bin/env python3
"""Verify that the Path A host clock is disciplined by authenticated NTS.

Docker containers use the host kernel clock. TIME-01 therefore belongs at the
Linux host trust boundary rather than inside server1. This verifier is kept
read-only: it never changes time or chrony configuration.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

MAX_OFFSET_SECONDS = 1.0
MIN_NTS_SOURCES = 2


def run_chronyc(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["chronyc", *args], capture_output=True, text=True, check=False, timeout=15
    )


def parse_tracking(text: str) -> tuple[str | None, int | None, float | None]:
    leap = re.search(r"Leap status\s*:\s*(.+)", text)
    stratum = re.search(r"Stratum\s*:\s*(\d+)", text)
    offset = re.search(r"System time\s*:\s*([0-9.eE+-]+) seconds", text)
    return (
        leap.group(1).strip() if leap else None,
        int(stratum.group(1)) if stratum else None,
        abs(float(offset.group(1))) if offset else None,
    )


def selected_source(text: str) -> str | None:
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("^*"):
            fields = line.split()
            return fields[1] if len(fields) > 1 else None
    return None


def nts_sources(text: str) -> list[str]:
    result: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("Name/IP", "=")):
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[1].upper() == "NTS":
            result.append(fields[0])
    return result


def collect() -> tuple[dict, list[str]]:
    tracking = run_chronyc("tracking")
    sources = run_chronyc("-n", "sources")
    authdata = run_chronyc("-n", "authdata")

    leap, stratum, offset = parse_tracking(tracking.stdout)
    selected = selected_source(sources.stdout)
    authenticated = nts_sources(authdata.stdout)
    errors: list[str] = []

    if tracking.returncode != 0:
        errors.append("chronyc tracking failed")
    if sources.returncode != 0:
        errors.append("chronyc sources failed")
    if authdata.returncode != 0:
        errors.append("chronyc authdata failed; host chrony must support NTS")
    if leap is None or leap.lower() != "normal":
        errors.append(f"Leap status is not Normal: {leap!r}")
    if stratum is None or stratum <= 0 or stratum >= 16:
        errors.append(f"invalid synchronized stratum: {stratum!r}")
    if offset is None or offset >= MAX_OFFSET_SECONDS:
        errors.append(f"system clock offset is not < {MAX_OFFSET_SECONDS}s: {offset!r}")
    if selected is None:
        errors.append("no selected chrony source (^*)")
    if len(authenticated) < MIN_NTS_SOURCES:
        errors.append(f"fewer than {MIN_NTS_SOURCES} NTS-authenticated sources are active")
    if selected and authenticated and selected not in authenticated:
        errors.append(f"selected source {selected!r} is not listed as NTS-authenticated")

    observed = {
        "tracking_rc": tracking.returncode,
        "sources_rc": sources.returncode,
        "authdata_rc": authdata.returncode,
        "leap_status": leap,
        "stratum": stratum,
        "system_time_offset_seconds": offset,
        "selected_source": selected,
        "nts_authenticated_sources": authenticated,
        "nts_authenticated_source_count": len(authenticated),
        "clock_owner": "linux-host-kernel",
    }
    return observed, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit machine-readable observations")
    args = parser.parse_args()

    if not shutil_which("chronyc"):
        errors = ["chronyc is not installed on the Path A Linux host"]
        observed = {"clock_owner": "linux-host-kernel", "chronyc_present": False}
    else:
        observed, errors = collect()

    if args.json:
        print(json.dumps({"ok": not errors, "observed": observed, "errors": errors}, sort_keys=True))
    else:
        if errors:
            print("TIME-01 host clock verification FAILED:", file=sys.stderr)
            for error in errors:
                print(f" - {error}", file=sys.stderr)
        else:
            print("OK: Path A host kernel clock is synchronized to authenticated NTS")
    return 1 if errors else 0


def shutil_which(command: str) -> str | None:
    # Local helper keeps this script dependency-free and easy to unit-test.
    import shutil

    return shutil.which(command)


if __name__ == "__main__":
    raise SystemExit(main())
