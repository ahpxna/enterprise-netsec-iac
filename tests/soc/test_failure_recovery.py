"""Regression cases for transport failures and response audit/recovery boundaries.

All transports are fakes; these tests never contact AI, ES or containment peers.
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from http.client import IncompleteRead
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from ai.features.contracts import FeatureSchemaError, NETWORK_FEATURES, require_exact_features
from response.adapters.base import AdapterOutcome
from response.decision import HmacCommandAuthenticator
from response.errors import CommandRejected
from response.orchestrator.audit import InMemoryAuditLedger
from response.orchestrator.engine import ResponseOrchestrator
from response.policy import PolicyCatalog
from soc.workers.enrichment import anomaly_event, drain
from soc.workers.https import DeliveryError, JsonHTTPS


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 9, 7, tzinfo=timezone.utc)


def transport(reply=None, error=None):
    client = object.__new__(JsonHTTPS)
    client.origin = "https://soc.invalid"
    client._authorization = None
    client._opener = Mock()
    if error:
        client._opener.open.side_effect = error
    else:
        client._opener.open.return_value.__enter__ = Mock(return_value=reply)
        client._opener.open.return_value.__exit__ = Mock(return_value=False)
    return client


def test_incomplete_chunked_http_is_retryable():
    reply = Mock()
    reply.read.side_effect = IncompleteRead(b'{"score":')
    with pytest.raises(DeliveryError) as caught:
        transport(reply).request("POST", "/v1/infer", {})
    assert caught.value.retryable
    assert caught.value.code == "INCOMPLETE_HTTP_RESPONSE"


def test_short_content_length_is_retryable_even_if_json_is_complete():
    reply = Mock(status=200, length=8)
    reply.read.return_value = b'{}'
    with pytest.raises(DeliveryError) as caught:
        transport(reply).request("POST", "/v1/infer", {})
    assert caught.value.retryable


def test_complete_invalid_json_remains_permanent():
    reply = Mock(status=200, length=0)
    reply.read.return_value = b'{broken'
    with pytest.raises(DeliveryError) as caught:
        transport(reply).request("POST", "/v1/infer", {})
    assert caught.value.code == "INVALID_JSON_RESPONSE"
    assert not caught.value.retryable


def test_oversized_integer_feature_is_a_contract_error():
    features = dict.fromkeys(NETWORK_FEATURES, 0)
    features["connection_count"] = 10 ** 400
    with pytest.raises(FeatureSchemaError):
        require_exact_features("network-window-v1", features)


def test_oversized_inference_number_is_deadletterable():
    vector = {"feature_schema": "network-window-v1", "feature_schema_sha256": "a" * 64}
    result = {
        "model_id": "approved", "algorithm": "IsolationForest",
        **vector, "model_sha256": "b" * 64, "model_metadata_sha256": "c" * 64,
        "score": 10 ** 400, "threshold": 0.9, "is_anomaly": True, "inference_ms": 1,
    }
    with pytest.raises(DeliveryError) as caught:
        anomaly_event(vector, result, identifier="job", metadata_hash="c" * 64, observer="soc")
    assert caught.value.code == "INVALID_INFERENCE_NUMBER"
    assert not caught.value.retryable


@pytest.mark.parametrize("limit", [-1, 0, True, 10001])
def test_direct_drain_cannot_request_an_unbounded_batch(limit):
    outbox = Mock()
    with pytest.raises(ValueError):
        drain(outbox, Mock(), Mock(), limit=limit)
    outbox.due.assert_not_called()


class FailingLedger(InMemoryAuditLedger):
    fail_state = None

    def append(self, event):
        if event["state"] == self.fail_state:
            raise OSError("audit unavailable")
        super().append(event)


def response_fixture():
    catalog = PolicyCatalog.from_path(ROOT / "response/policies/default.yaml")
    auth = HmacCommandAuthenticator(keys={"test": b"x" * 32}, signing_key_id="test")
    ledger = FailingLedger()
    adapter = Mock()
    adapter.name, adapter.action = "opnsense", "block_ip"
    adapter.recovery_reference.return_value = "ref"
    adapter.apply.return_value = AdapterOutcome.success(adapter_reference="ref", evidence_refs=("apply",))
    adapter.revert.return_value = AdapterOutcome.success(adapter_reference="ref", evidence_refs=("removed",))
    endpoint = Mock()
    endpoint.name, endpoint.action = "wazuh", "isolate_host"
    engine = ResponseOrchestrator(catalog=catalog, authenticator=auth, ledger=ledger,
                                  adapters=[adapter, endpoint])
    policy = catalog.policy("COR-001")
    command = {
        "schema_version": "response-command-v1", "request_id": "request", "decision_event_id": "decision",
        "correlation_id": "correlation", "policy": {"id": policy.id, "version": policy.version, "sha256": policy.sha256},
        "target": {"type": "ip", "value": "172.16.60.10"}, "action": policy.action,
        "ttl_seconds": policy.ttl_seconds, "allowlist_checked": True, "rollback_required": True,
        "idempotency_key": "idemp-" + "a" * 64,
    }
    return engine, ledger, adapter, auth, command, catalog


def signed(auth, command, now=NOW):
    command = deepcopy(command)
    command["authorization"] = {
        "issuer": "decision_engine", "key_id": "test", "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=300)).isoformat(),
    }
    command["authorization"]["signature"] = auth.sign(command)
    return command


def test_failed_initial_audit_does_not_leave_an_applicable_request():
    engine, ledger, adapter, auth, command, _ = response_fixture()
    ledger.fail_state = "REQUESTED"
    with pytest.raises(OSError):
        engine.submit(signed(auth, command), now=NOW)
    response_id = "resp-" + sha256(command["idempotency_key"].encode()).hexdigest()[:24]
    with pytest.raises(CommandRejected):
        engine.apply(response_id, now=NOW)
    adapter.apply.assert_not_called()
    ledger.fail_state = None
    assert engine.submit(signed(auth, command), now=NOW).accepted


def test_failed_rate_limit_audit_cannot_bypass_rate_limit():
    engine, ledger, adapter, auth, command, catalog = response_fixture()
    for number in range(catalog.rate_limit.max_actions):
        command["idempotency_key"] = f"idemp-{number:064d}"
        assert engine.submit(signed(auth, command), now=NOW).accepted
    ledger.fail_state = "FAILED"
    command["idempotency_key"] = "idemp-" + "z" * 64
    with pytest.raises(OSError):
        engine.submit(signed(auth, command), now=NOW)
    duplicate = engine.submit(signed(auth, command), now=NOW)
    assert duplicate.deduplicated and not duplicate.accepted
    with pytest.raises(CommandRejected):
        engine.apply(duplicate.response_id, now=NOW)
    adapter.apply.assert_not_called()


def test_failed_applied_audit_cannot_repeat_the_side_effect():
    engine, ledger, adapter, auth, command, _ = response_fixture()
    request = engine.submit(signed(auth, command), now=NOW)
    ledger.fail_state = "APPLIED"
    with pytest.raises(OSError):
        engine.apply(request.response_id, now=NOW)
    ledger.fail_state = None
    with pytest.raises(CommandRejected):
        engine.apply(request.response_id, now=NOW)
    adapter.apply.assert_called_once()


def test_timeout_after_privileged_write_is_not_retryable():
    engine, ledger, adapter, auth, command, _ = response_fixture()
    adapter.apply.side_effect = TimeoutError("secret-bearing upstream details")
    request = engine.submit(signed(auth, command), now=NOW)
    result = engine.apply(request.response_id, now=NOW)
    assert result.state == "FAILED" and not result.accepted
    assert result.audit_event["failure"]["code"] == "APPLICATION_OUTCOME_UNKNOWN"
    assert "secret-bearing" not in json.dumps(result.audit_event)
    with pytest.raises(CommandRejected):
        engine.apply(request.response_id, now=NOW)
    adapter.apply.assert_called_once()


def test_intent_failure_prevents_privileged_io():
    engine, ledger, adapter, auth, command, _ = response_fixture()
    request = engine.submit(signed(auth, command), now=NOW)
    ledger.claim_apply = Mock(side_effect=OSError("disk full"))
    with pytest.raises(OSError):
        engine.apply(request.response_id, now=NOW)
    adapter.apply.assert_not_called()


def test_reissued_evidence_after_dedup_expiry_keeps_original_lifecycle():
    engine, ledger, adapter, auth, command, catalog = response_fixture()
    request = engine.submit(signed(auth, command), now=NOW)
    engine.apply(request.response_id, now=NOW)
    later = NOW + timedelta(seconds=catalog.dedup_seconds + 1)
    duplicate = engine.submit(signed(auth, command, later), now=later)
    assert duplicate.response_id == request.response_id
    assert duplicate.deduplicated and duplicate.state == "APPLIED"
    assert len(ledger.events(request.response_id)) == 2
    adapter.apply.assert_called_once()


@pytest.mark.parametrize("recover_via", ["manual", "ttl"])
def test_failed_rollback_can_fail_again_then_recover(recover_via):
    engine, ledger, adapter, auth, command, _ = response_fixture()
    request = engine.submit(signed(auth, command), now=NOW)
    engine.apply(request.response_id, now=NOW)
    adapter.revert.side_effect = [
        AdapterOutcome.failure(code="UNAVAILABLE", message="peer down"),
        AdapterOutcome.failure(code="UNAVAILABLE", message="peer down"),
        AdapterOutcome.success(adapter_reference="ref", evidence_refs=("removed",)),
    ]
    assert engine.rollback(request.response_id, now=NOW).state == "FAILED"
    later = NOW + timedelta(seconds=command["ttl_seconds"] + 1)
    if recover_via == "manual":
        assert engine.rollback(request.response_id, cause="recovery", now=later).state == "FAILED"
        result = engine.rollback(request.response_id, cause="recovery", now=later)
    else:
        assert engine.expire_due(now=later)[0].state == "FAILED"
        result = engine.expire_due(now=later)[0]
    assert result.state == "ROLLED_BACK" and result.accepted
    assert engine.expire_due(now=later) == ()
    history = ledger.events(request.response_id)
    assert [event["state"] for event in history] == ["REQUESTED", "APPLIED", "FAILED", "FAILED", "ROLLED_BACK"]
    schema = json.loads((ROOT / "response/schemas/response-audit-event-v1.schema.json").read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for event in history:
        validator.validate(event)


def test_failure_before_apply_cannot_enter_recovery():
    engine, _, adapter, auth, command, _ = response_fixture()
    request = engine.submit(signed(auth, command), now=NOW)
    assert engine.apply(request.response_id, now=NOW + timedelta(seconds=301)).state == "FAILED"
    with pytest.raises(CommandRejected):
        engine.rollback(request.response_id, cause="recovery", now=NOW)
    assert engine.expire_due(now=NOW + timedelta(days=1)) == ()
    adapter.revert.assert_not_called()
    adapter.apply.assert_not_called()
