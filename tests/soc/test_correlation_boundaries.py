"""Source regression cases; no external services or privileged operations."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker

from response.decision import DecisionEngine, HmacCommandAuthenticator
from response.errors import CommandRejected, CorrelationRejected, PolicyError
from response.orchestrator.audit import InMemoryAuditLedger
from response.orchestrator.engine import ResponseOrchestrator
from response.policy import PolicyCatalog


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 9, 7, tzinfo=timezone.utc)


def policy_document():
    return yaml.safe_load((ROOT / "response/policies/default.yaml").read_text())


def setup_decision(document=None):
    catalog = PolicyCatalog.from_mapping(policy_document() if document is None else document)
    auth = HmacCommandAuthenticator(keys={"test": b"x" * 32}, signing_key_id="test")
    return DecisionEngine(catalog, auth), catalog, auth


def evidence():
    target = {"type": "ip", "value": "172.16.60.10"}
    return {
        "policy_id": "COR-001", "now": NOW, "target": target,
        "anomaly": {
            "event_id": "ai-event", "model_id": "approved-model", "score": 0.95,
            "threshold": 0.9, "is_anomaly": True, "observed_at": NOW.isoformat(),
            "target": deepcopy(target),
        },
        "independent_signals": [{
            "type": "authentication", "reference": "auth-event", "count": 20,
            "observed_at": NOW.isoformat(), "target": deepcopy(target),
        }],
    }


def test_bound_fresh_corroboration_creates_signed_command():
    engine, _, auth = setup_decision()
    result = engine.evaluate(**evidence())
    assert result.eligible and result.command
    auth.verify(result.command, now=NOW)
    for path, payload in (
        ("schemas/events/correlation-decision-event-v1.schema.json", result.decision_event),
        ("schemas/response/action-request.schema.json", result.action_request),
        ("response/schemas/response-command-v1.schema.json", result.command),
    ):
        schema = json.loads((ROOT / path).read_text())
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(payload)


@pytest.mark.parametrize("which", ["anomaly", "signal"])
@pytest.mark.parametrize("missing", [False, True])
def test_unbound_or_unrelated_evidence_is_rejected(which, missing):
    engine, _, _ = setup_decision()
    data = evidence()
    item = data["anomaly"] if which == "anomaly" else data["independent_signals"][0]
    if missing:
        item.pop("target")
    else:
        item["target"]["value"] = "172.16.60.11"
    with pytest.raises(CorrelationRejected):
        engine.evaluate(**data)


@pytest.mark.parametrize("which", ["anomaly", "signal"])
@pytest.mark.parametrize("seconds", [-901, 61])
def test_stale_or_future_evidence_cannot_authorize_containment(which, seconds):
    engine, _, _ = setup_decision()
    data = evidence()
    item = data["anomaly"] if which == "anomaly" else data["independent_signals"][0]
    item["observed_at"] = (NOW + timedelta(seconds=seconds)).isoformat()
    result = engine.evaluate(**data)
    assert not result.eligible
    assert result.command is None and result.action_request is None
    assert not result.decision_event["decision"]["automatic_response_eligible"]


@pytest.mark.parametrize("seconds", [-900, 60])
def test_freshness_boundaries_are_inclusive(seconds):
    engine, _, _ = setup_decision()
    data = evidence()
    data["anomaly"]["observed_at"] = (NOW + timedelta(seconds=seconds)).isoformat()
    assert engine.evaluate(**data).eligible


def test_ai_reference_cannot_be_relabelled_as_independent():
    engine, _, _ = setup_decision()
    data = evidence()
    data["independent_signals"][0]["reference"] = data["anomaly"]["event_id"]
    with pytest.raises(CorrelationRejected):
        engine.evaluate(**data)


def test_same_reference_cannot_count_as_two_signal_types():
    engine, _, _ = setup_decision()
    data = evidence()
    second = deepcopy(data["independent_signals"][0])
    second["type"] = "threat_intel"
    data["independent_signals"].append(second)
    with pytest.raises(CorrelationRejected):
        engine.evaluate(**data)


def test_reordering_evidence_and_changing_trace_does_not_repeat_action():
    engine, _, _ = setup_decision()
    data = evidence()
    second = deepcopy(data["independent_signals"][0])
    second.update(type="threat_intel", reference="intel-event")
    data["independent_signals"].append(second)
    first = engine.evaluate(**data, correlation_id="trace-one")
    data["independent_signals"].reverse()
    data["independent_signals"][1]["count"] = 20.0
    for item in data["independent_signals"]:
        item["observed_at"] = "2026-09-07T08:00:00+08:00"
    repeated = engine.evaluate(**data, correlation_id="trace-two")
    assert first.command["idempotency_key"] == repeated.command["idempotency_key"]
    assert first.command["request_id"] == repeated.command["request_id"]
    assert first.command["decision_event_id"] == repeated.command["decision_event_id"]


def test_ipv6_spellings_do_not_create_different_response_identities():
    engine, _, _ = setup_decision()
    data = evidence()
    for item in (data, data["anomaly"], *data["independent_signals"]):
        item["target"]["value"] = "2606:4700:4700::1111"
    first = engine.evaluate(**data)
    data["independent_signals"][0]["target"]["value"] = "2606:4700:4700:0:0:0:0:1111"
    repeated = engine.evaluate(**data)
    assert first.eligible and repeated.eligible
    assert first.command["idempotency_key"] == repeated.command["idempotency_key"]


def test_model_flag_must_agree_with_threshold():
    engine, _, _ = setup_decision()
    data = evidence()
    data["anomaly"]["threshold"] = 0.99
    with pytest.raises(CorrelationRejected):
        engine.evaluate(**data)


@pytest.mark.parametrize("number", [10 ** 400, float("inf"), float("nan"), True])
def test_invalid_numeric_evidence_is_a_domain_error(number):
    engine, _, _ = setup_decision()
    data = evidence()
    data["anomaly"]["score"] = number
    with pytest.raises(CorrelationRejected):
        engine.evaluate(**data)
    data = evidence()
    data["independent_signals"][0]["count"] = number
    with pytest.raises(CorrelationRejected):
        engine.evaluate(**data)


def test_fractional_count_cannot_satisfy_a_count_policy():
    engine, _, _ = setup_decision()
    data = evidence()
    data["independent_signals"][0]["count"] = 20.5
    with pytest.raises(CorrelationRejected):
        engine.evaluate(**data)


@pytest.mark.parametrize("trace", ["", "   ", False, "x" * 257])
def test_invalid_explicit_trace_id_is_not_silently_replaced(trace):
    engine, _, _ = setup_decision()
    with pytest.raises(CorrelationRejected):
        engine.evaluate(**evidence(), correlation_id=trace)


@pytest.mark.parametrize("field", ["evidence_max_age_seconds", "dedup_seconds", "command_valid_for_seconds", "rate_limit", "protections"])
def test_changed_safeguards_invalidate_old_signed_command(field):
    decision, catalog, auth = setup_decision()
    result = decision.evaluate(**evidence())
    document = policy_document()
    if field == "rate_limit":
        document["defaults"][field]["max_actions"] += 1
    elif field == "protections":
        document["defaults"][field]["protected_hosts"].append("new-management-host")
    else:
        document["defaults"][field] += 1
    changed = PolicyCatalog.from_mapping(document)
    assert changed.policy("COR-001").sha256 != catalog.policy("COR-001").sha256
    adapters = []
    for name, action in (("opnsense", "block_ip"), ("wazuh", "isolate_host")):
        adapter = Mock()
        adapter.name, adapter.action = name, action
        adapters.append(adapter)
    orchestrator = ResponseOrchestrator(catalog=changed, authenticator=auth,
                                        ledger=InMemoryAuditLedger(), adapters=adapters)
    with pytest.raises(CommandRejected):
        orchestrator.submit(result.command, now=NOW)
    for adapter in adapters:
        adapter.apply.assert_not_called()


def test_semantically_equivalent_safeguards_have_same_hash():
    document = policy_document()
    first = PolicyCatalog.from_mapping(document)
    document["defaults"]["protections"]["protected_hosts"].reverse()
    second = PolicyCatalog.from_mapping(document)
    assert first.policy("COR-001").sha256 == second.policy("COR-001").sha256


@pytest.mark.parametrize("age", [None, True, 0, 29, 86401])
def test_freshness_limit_is_explicit_and_bounded(age):
    document = policy_document()
    document["defaults"]["evidence_max_age_seconds"] = age
    with pytest.raises(PolicyError):
        PolicyCatalog.from_mapping(document)


def test_non_ascii_signature_is_rejected_without_compare_digest_type_error():
    engine, _, auth = setup_decision()
    command = deepcopy(engine.evaluate(**evidence()).command)
    command["authorization"]["signature"] = "é" * 43
    with pytest.raises(CorrelationRejected):
        auth.verify(command, now=NOW)


@pytest.mark.parametrize("which", ["target", "signal"])
def test_non_string_discriminators_raise_domain_errors(which):
    engine, _, _ = setup_decision()
    data = evidence()
    if which == "target":
        data["target"]["type"] = []
    else:
        data["independent_signals"][0]["type"] = []
    with pytest.raises(CorrelationRejected):
        engine.evaluate(**data)
