"""Fail fast when the SOC/AI architecture contracts drift."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_schema(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text())


def load_kibana_objects() -> list[dict]:
    return [
        json.loads(line)
        for line in (ROOT / "soc/kibana/saved-objects/soc-overview.ndjson").read_text().splitlines()
        if line.strip()
    ]


def test_all_soc_schemas_are_valid_json_objects() -> None:
    paths = sorted((ROOT / "schemas").glob("**/*.schema.json"))
    paths += sorted((ROOT / "response/schemas").glob("**/*.schema.json"))
    assert paths
    for path in paths:
        payload = json.loads(path.read_text())
        assert payload["$schema"].endswith("2020-12/schema")
        assert payload["type"] == "object"


def test_required_soc_schemas_are_present_and_versioned() -> None:
    required = {
        "schemas/ecs/soc-event.schema.json",
        "schemas/ecs/soc-raw-event.schema.json",
        "schemas/events/anomaly-event-v1.schema.json",
        "schemas/events/correlation-decision-event-v1.schema.json",
        "schemas/events/dataset-manifest-v1.schema.json",
        "schemas/events/model-provenance-v1.schema.json",
        "schemas/features/network-window-v1.schema.json",
        "schemas/features/endpoint-window-v1.schema.json",
        "schemas/response/action-request.schema.json",
        "response/schemas/response-command-v1.schema.json",
        "response/schemas/response-audit-event-v1.schema.json",
    }
    for relative in required:
        path = ROOT / relative
        assert path.is_file(), relative
        payload = json.loads(path.read_text())
        assert payload["$schema"].endswith("2020-12/schema")
        assert payload["type"] == "object"
        assert "$id" in payload, relative


def test_stream_schemas_preserve_raw_and_create_new_ai_response_events() -> None:
    raw = load_schema("schemas/ecs/soc-raw-event.schema.json")
    raw_event = raw["properties"]["event"]
    assert raw["properties"]["cxyz"]["properties"]["schema_version"]["const"] == "soc-raw-v1"
    assert raw_event["properties"]["kind"]["const"] == "event"
    assert raw_event["properties"]["dataset"]["pattern"].endswith(r"\.raw$")
    assert "original" in raw_event["required"]

    anomaly = load_schema("schemas/events/anomaly-event-v1.schema.json")
    assert anomaly["properties"]["event"]["properties"]["dataset"]["const"] == "soc.ai.anomaly"
    assert anomaly["properties"]["schema_version"]["const"] == "anomaly-event-v1"
    assert anomaly["additionalProperties"] is False
    assert "feature_vector" in anomaly["required"]

    decision = load_schema("schemas/events/correlation-decision-event-v1.schema.json")
    assert decision["properties"]["event"]["properties"]["dataset"]["const"] == "soc.correlation.decision"
    assert decision["properties"]["signals"]["minItems"] == 2

    audit = load_schema("response/schemas/response-audit-event-v1.schema.json")
    assert audit["properties"]["event"]["properties"]["dataset"]["const"] == "soc.response.audit"
    assert audit["properties"]["state"]["enum"] == [
        "REQUESTED", "APPLIED", "VERIFIED", "EXPIRED", "ROLLED_BACK", "FAILED",
    ]
    assert "immutable audit document" in audit["description"]


def test_feature_contract_freezes_mvp_entities_windows_and_fields() -> None:
    schema = load_schema("schemas/features/feature-vector.schema.json")
    assert schema["oneOf"] == [
        {"$ref": "network-window-v1.schema.json"},
        {"$ref": "endpoint-window-v1.schema.json"},
    ]
    for name, entity in (("network-window-v1", "src_ip"), ("endpoint-window-v1", "host")):
        contract = load_schema(f"schemas/features/{name}.schema.json")
        assert contract["properties"]["entity_type"]["const"] == entity
        assert contract["properties"]["window_duration"]["const"] == "5m"
        features = contract["properties"]["features"]
        assert set(features["required"]) == set(features["properties"])
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


def test_ingestion_mvp_declares_all_required_datasets() -> None:
    pipeline = "\n".join(
        path.read_text() for path in sorted((ROOT / "soc/logstash/pipelines").glob("*.conf"))
    )
    for dataset in ("suricata.eve", "wazuh.alerts", "firewall.syslog", "freeradius.auth"):
        assert dataset in pipeline


def test_storage_roles_keep_soc_streams_separate_and_raw_create_only() -> None:
    roles = {
        "logstash": load_schema("soc/elasticsearch/logstash-writer-role.json"),
        "feature": load_schema("soc/elasticsearch/feature-engine-role.json"),
        "decision": load_schema("soc/elasticsearch/decision-engine-role.json"),
        "orchestrator": load_schema("soc/elasticsearch/response-orchestrator-role.json"),
    }
    logstash = roles["logstash"]
    raw_grant = next(grant for grant in logstash["indices"] if "soc-raw-*" in grant["names"])
    assert "create_doc" in raw_grant["privileges"]
    assert not {"create", "index", "write", "update", "delete", "all"} & set(raw_grant["privileges"])

    logstash_streams = {
        stream
        for grant in logstash["indices"]
        for stream in grant["names"]
    }
    assert "soc-ai-*" not in logstash_streams
    assert "soc-response-*" not in logstash_streams

    feature_streams = {
        stream
        for grant in roles["feature"]["indices"]
        for stream in grant["names"]
    }
    assert "soc-raw-*" not in feature_streams
    assert "soc-ai-*" not in feature_streams
    assert "soc-response-*" not in feature_streams

    decision_writes = next(
        grant for grant in roles["decision"]["indices"] if "soc-response-*" in grant["names"]
    )
    assert "create_doc" in decision_writes["privileges"]
    assert not {"create", "index", "write", "update", "delete", "all"} & set(decision_writes["privileges"])

    orchestrator_streams = {
        stream
        for grant in roles["orchestrator"]["indices"]
        for stream in grant["names"]
    }
    assert orchestrator_streams == {"soc-response-*"}


def test_kibana_dashboards_preserve_data_view_boundaries() -> None:
    objects = load_kibana_objects()
    assert {item["type"] for item in objects} == {"index-pattern", "search", "dashboard"}
    views = {item["id"]: item["attributes"]["title"] for item in objects if item["type"] == "index-pattern"}
    assert views == {
        "soc-events": "soc-network-*,soc-endpoint-*,soc-auth-*,soc-alerts-*",
        "soc-ai": "soc-ai-*",
        "soc-response": "soc-response-*",
        "soc-raw": "soc-raw-*",
        "soc-deadletter": "soc-deadletter-*",
    }

    searches = {item["id"]: item for item in objects if item["type"] == "search"}
    for search in searches.values():
        assert "event.original" not in search["attributes"]["columns"]
        assert not any(
            token in column.lower()
            for column in search["attributes"]["columns"]
            for token in ("password", "secret", "credential")
        )

    dashboards = {item["id"]: item for item in objects if item["type"] == "dashboard"}
    expected_views = {
        "cxyz-soc-overview": "soc-events",
        "cxyz-network-nids": "soc-events",
        "cxyz-ai": "soc-ai",
        "cxyz-response": "soc-response",
    }
    assert set(expected_views) <= set(dashboards)
    for dashboard_id, view_id in expected_views.items():
        panel_searches = {
            ref["id"]
            for ref in dashboards[dashboard_id]["references"]
            if ref["type"] == "search"
        }
        assert panel_searches
        for search_id in panel_searches:
            search = searches[search_id]
            source_view = next(
                ref["id"]
                for ref in search["references"]
                if ref["type"] == "index-pattern"
            )
            assert source_view == view_id


def test_one_shot_kibana_bootstrap_is_revoked_after_import() -> None:
    makefile = (ROOT / "Makefile").read_text()
    setup = "docker compose --profile soc run --rm --no-deps soc-kibana-setup"
    revoke = "docker compose --profile soc run --rm --no-deps soc-kibana-bootstrap-revoke"
    assert setup in makefile
    assert revoke in makefile
    assert makefile.index(setup) < makefile.index(revoke)

    bootstrap = (ROOT / "soc/kibana/bootstrap-kibana.sh").read_text()
    revoke_script = (ROOT / "soc/elasticsearch/revoke-kibana-bootstrap.sh").read_text()
    assert "cxyz_kibana_bootstrap:" in bootstrap
    assert "KIBANA_BOOTSTRAP_PASSWORD" in bootstrap
    assert "-X DELETE" in revoke_script
    assert "_security/user/cxyz_kibana_bootstrap" in revoke_script
    assert "KIBANA_BOOTSTRAP_PASSWORD" not in revoke_script


def test_ai_cannot_bypass_decision_orchestrator_boundary() -> None:
    architecture = (ROOT / "docs/SOC-AI-ARCHITECTURE.md").read_text()
    assert "AI services cannot call either" in architecture
    assert "An anomaly alone never authorizes containment" in architecture

    command = load_schema("response/schemas/response-command-v1.schema.json")
    assert command["properties"]["authorization"]["properties"]["issuer"]["const"] == "decision_engine"

    request = load_schema("schemas/response/action-request.schema.json")
    assert request["properties"]["issued_by"]["const"] == "decision_engine"

    for path in (ROOT / "ai").glob("**/*"):
        # OS metadata is not part of the AI plane; every other file is still scanned. Binary
        # artifacts (a promoted model under ai/registry) are decoded leniently, not skipped.
        if (not path.is_file() or path.suffix in {".md", ".pyc"} or "__pycache__" in path.parts
                or path.name == ".DS_Store"):
            continue
        text = path.read_text(errors="replace").lower()
        for forbidden in (
            "opnsense_api",
            "opnsense_",
            "soc_blocklist",
            "wazuh_active_response",
            "wazuh_api",
            "response/adapters",
            "response.adapters",
        ):
            assert forbidden not in text, path
