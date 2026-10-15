"""Export closed five-minute vectors from a normalized JSONL capture."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sys

from .contracts import validate_vector
from .engine import build_endpoint_vectors, build_network_vectors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--schema", choices=("network-window-v1", "endpoint-window-v1"), required=True)
    parser.add_argument("--git-sha", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-fA-F0-9]{7,64}", args.git_sha):
        raise SystemExit("valid generator Git SHA required")
    windows = {}
    with args.input.open() as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            event = json.loads(line)
            timestamp = datetime.fromisoformat(event["@timestamp"].replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                raise ValueError(f"timestamp at line {number} needs a timezone")
            timestamp = timestamp.astimezone(timezone.utc)
            start = timestamp.replace(minute=timestamp.minute // 5 * 5, second=0, microsecond=0)
            windows.setdefault(start, []).append(event)
    builder = build_network_vectors if args.schema == "network-window-v1" else build_endpoint_vectors
    for start, events in sorted(windows.items()):
        for vector in builder(events, window_start=start, window_end=start + timedelta(minutes=5),
                              generator_git_sha=args.git_sha):
            validate_vector(vector)
            sys.stdout.write(json.dumps(vector, sort_keys=True, allow_nan=False) + "\n")


if __name__ == "__main__":
    main()
