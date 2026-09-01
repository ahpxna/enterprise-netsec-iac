"""Fail fast when the SOC/AI architecture contracts drift."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_schema(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text())


def test_all_soc_schemas_are_valid_json_objects() -> None:
    paths = sorted((ROOT / "schemas").glob("**/*.schema.json"))
    assert paths
    for path in paths:
        payload = json.loads(path.read_text())
        assert payload["$schema"].endswith("2020-12/schema")
        assert payload["type"] == "object"


def test_feature_contract_freezes_mvp_entities_windows_and_fields() -> None:
    schema = load_schema("schemas/features/feature-vector.schema.json")
    assert schema["properties"]["entity"]["properties"]["type"]["enum"] == [
        "host",
        "user",
        "src_ip",
    ]
    assert schema["properties"]["window"]["properties"]["duration"]["enum"] == [
        "1m",
        "5m",
        "15m",
    ]
    expected = {
        "conn_count", "unique_dst_ip", "unique_dst_port", "bytes_in", "bytes_out",
        "blocked_ratio", "dns_count", "unique_domain", "rare_port_ratio",
        "suricata_alert_count", "login_success", "login_failed", "distinct_src_ip",
        "fail_to_success", "after_hours_login", "process_count", "rare_process_count",
        "powershell_count", "fim_change_count", "account_change_count",
        "privilege_event_count",
    }
    features = schema["properties"]["features"]
    assert set(features["required"]) == expected
    assert set(features["properties"]) == expected
    assert features["additionalProperties"] is False


def test_response_contract_requires_correlation_and_reversibility() -> None:
    schema = load_schema("schemas/response/action-request.schema.json")
    properties = schema["properties"]
    assert properties["ai_score"]["minimum"] == 0.9
    assert properties["signals"]["minItems"] == 2
    assert properties["allowlist_checked"]["const"] is True
    assert properties["rollback_required"]["const"] is True
    assert properties["ttl_seconds"]["minimum"] > 0


def test_architecture_separates_ai_from_privileged_response() -> None:
    architecture = (ROOT / "docs/SOC-AI-ARCHITECTURE.md").read_text()
    for token in (
        "An anomaly alone never authorizes containment",
        "Elasticsearch and Kibana form the SOC analytics plane",
        "Wazuh Manager remains",
        "SOC_BLOCKLIST",
        "Detect -> Analyze -> Decide -> Respond -> Verify -> Learn",
    ):
        assert token in architecture
