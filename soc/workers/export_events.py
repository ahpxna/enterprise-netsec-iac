"""Export normalized events for a time range as JSONL (dataset capture).

The capture feeds ``python -m ai.training.build_dataset``.  It uses the same
read-only feature-engine identity as the feature worker and the same field
selection, so the exported events are exactly the ones a live vector would see.
Raw payloads (``event.original``) are never exported.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Sequence

from .common import elastic_from_environment, parse_rfc3339, rfc3339
from .features import ENDPOINT_INDICES, EVENT_FIELDS, NETWORK_DATASETS, NETWORK_INDICES, _expand


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", choices=("network-window-v1", "endpoint-window-v1"), required=True)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-events", type=int, default=20_000_000)
    args = parser.parse_args(argv)
    start, end = parse_rfc3339(args.start), parse_rfc3339(args.end)
    if end <= start:
        raise SystemExit("--end must be after --start")
    if args.output.exists():
        raise SystemExit("refusing to overwrite an existing capture")
    window = {"range": {"@timestamp": {"gte": rfc3339(start), "lt": rfc3339(end)}}}
    if args.schema == "network-window-v1":
        query = {"bool": {"filter": [window, {"terms": {"event.dataset": list(NETWORK_DATASETS)}},
                                     {"exists": {"field": "source.ip"}}]}}
        index = NETWORK_INDICES
    else:
        query = {"bool": {"filter": [window, {"exists": {"field": "host.name"}}]}}
        index = ENDPOINT_INDICES
    os.umask(0o077)
    count = 0
    with args.output.open("x", encoding="utf-8") as handle:
        for hit in elastic_from_environment().scan(
            index, query, [{"@timestamp": "asc"}, {"cxyz.ingestion_id": "asc"}],
            source=EVENT_FIELDS, page_size=5000, limit=args.max_events,
        ):
            handle.write(json.dumps(_expand(hit["_source"]), sort_keys=True) + "\n")
            count += 1
    print(json.dumps({"events": count, "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
