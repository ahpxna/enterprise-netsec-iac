#!/usr/bin/env python3
"""Report ingestion health without exposing Elastic credentials."""

from __future__ import annotations

import json
import shlex
import subprocess


def request(path: str, body: dict | None = None) -> dict:
    command = (
        "curl --silent --show-error --fail --cacert config/certs/ca.crt "
        '--user "elastic:${ELASTIC_PASSWORD}" '
        + ("-X POST -H 'Content-Type: application/json' " if body is not None else "")
        + (f"--data-binary {shlex.quote(json.dumps(body))} " if body is not None else "")
        + f'"https://localhost:9200/{path}"'
    )
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "elasticsearch", "bash", "-ec", command],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def main() -> int:
    cluster = request("_cluster/health")
    aggregations = request(
        "soc-network-*,soc-endpoint-*,soc-auth-*,soc-alerts-*/_search?allow_no_indices=true&ignore_unavailable=true"
        "&filter_path=hits.total,aggregations.datasets.buckets",
        {"size": 0, "aggs": {"datasets": {"terms": {"field": "event.dataset", "size": 50}}}},
    )
    stream_counts = {
        stream: request(f"soc-{stream}-*/_count?allow_no_indices=true&ignore_unavailable=true").get("count", 0)
        for stream in ("raw", "network", "endpoint", "auth", "alerts", "features", "ai", "response", "deadletter")
    }
    report = {
        "cluster": cluster.get("status"),
        "events": aggregations.get("hits", {}).get("total", {}).get("value", 0),
        "datasets": {
            item["key"]: item["doc_count"]
            for item in aggregations.get("aggregations", {}).get("datasets", {}).get("buckets", [])
        },
        "streams": stream_counts,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
