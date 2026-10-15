#!/usr/bin/env python3
"""Inject four source fixtures and prove normalized events plus dashboard."""

from __future__ import annotations

import json
import subprocess
import time
import uuid
from urllib.parse import quote


DATASETS = {
    "firewall.log": ("firewall.syslog", "src=203.0.113.44 dst=172.16.60.20 spt=43120 dpt=443 proto=tcp action=blocked"),
    "radius.log": ("freeradius.auth", "user=soc-smoke outcome=failure src=192.168.40.20"),
    "suricata.json": (
        "suricata.eve",
        json.dumps({
            "timestamp": "2026-08-31T12:00:00.000000+00:00",
            "event_type": "alert",
            "src_ip": "192.168.40.20",
            "src_port": 53312,
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "proto": "UDP",
            "app_proto": "dns",
            "alert": {"signature_id": 990001, "signature": "SOC smoke Suricata", "severity": 2},
        }),
    ),
    "wazuh.json": (
        "wazuh.alerts",
        json.dumps({
            "timestamp": "2026-08-31T12:00:01.000+0000",
            "rule": {"level": 8, "id": "990002", "description": "SOC smoke Wazuh"},
            "agent": {"name": "dmz-web"},
            "data": {"srcip": "192.168.40.20", "dstip": "172.16.60.20"},
        }),
    ),
}


def append_fixture(filename: str, payload: str) -> None:
    subprocess.run(
        ["docker", "compose", "exec", "-T", "logstash", "bash", "-ec", f"cat >> /fixtures/{filename}"],
        input=payload + "\n",
        check=True,
        text=True,
    )


def elastic(path: str) -> dict:
    result = subprocess.run(
        [
            "docker", "compose", "exec", "-T", "elasticsearch", "bash", "-ec",
            "curl --silent --show-error --fail --cacert config/certs/ca.crt "
            '--user "elastic:${ELASTIC_PASSWORD}" "https://localhost:9200/' + path + '"',
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def kibana_dashboard_exists() -> bool:
    result = subprocess.run(
        [
            "docker", "compose", "exec", "-T", "elasticsearch", "bash", "-ec",
            "curl --silent --show-error --fail --cacert config/certs/ca.crt "
            '--user "elastic:${ELASTIC_PASSWORD}" '
            '"https://kibana:5601/api/saved_objects/dashboard/cxyz-soc-overview"',
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout).get("id") == "cxyz-soc-overview"


def main() -> int:
    marker = f"cxyz-soc-smoke-{uuid.uuid4()}"
    for filename, (_, payload) in DATASETS.items():
        if filename.endswith(".log"):
            append_fixture(filename, f"{payload} marker={marker}")
        else:
            append_fixture(filename, payload[:-1] + f', "cxyz_smoke_id": "{marker}"}}')
    append_fixture("suricata.json", f"not-json-{marker}")

    expected = {dataset for dataset, _ in DATASETS.values()}
    deadline = time.monotonic() + 90
    observed: set[str] = set()
    raw = 0
    malformed = 0
    while time.monotonic() < deadline:
        query = elastic(
            f'soc-network-*,soc-endpoint-*,soc-auth-*,soc-alerts-*/_search?allow_no_indices=true&ignore_unavailable=true&q={quote(marker)}&size=20'
        )
        observed = {
            hit["_source"].get("event", {}).get("dataset")
            for hit in query.get("hits", {}).get("hits", [])
        }
        bad = elastic(
            f'soc-deadletter-*/_count?allow_no_indices=true&ignore_unavailable=true&q={quote(marker)}'
        )
        raw_result = elastic(
            f'soc-raw-*/_count?allow_no_indices=true&ignore_unavailable=true&q={quote(marker)}'
        )
        raw = int(raw_result.get("count", 0))
        malformed = int(bad.get("count", 0))
        if expected.issubset(observed) and raw >= len(expected) + 1 and malformed > 0:
            break
        time.sleep(3)

    missing = sorted(expected - observed)
    if missing or raw < len(expected) + 1 or malformed < 1:
        raise SystemExit(
            f"SOC smoke failed: missing={missing}, raw_count={raw}, malformed_count={malformed}"
        )
    if not kibana_dashboard_exists():
        raise SystemExit("SOC smoke failed: Kibana SOC dashboard is absent")
    print(
        f"SOC smoke PASS: datasets={sorted(observed)}, raw={raw}, "
        f"malformed={malformed}, dashboard=cxyz-soc-overview"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
