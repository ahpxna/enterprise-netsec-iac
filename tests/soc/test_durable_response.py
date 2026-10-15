"""Restart/commit-failure regressions, using SQLite and fake peers only."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from unittest.mock import Mock

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from response.adapters.base import AdapterOutcome
from response.adapters.opnsense import OPNsenseBlocklistAdapter, OPNsensePeer
from response.adapters.wazuh import WazuhIsolationAdapter
from response.decision import HmacCommandAuthenticator
from response.errors import CommandRejected
from response.orchestrator import ResponseOrchestrator, SQLiteResponseStore
from response.policy import PolicyCatalog


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 9, 7, tzinfo=timezone.utc)


class FakeAdapter:
    def __init__(self, name="opnsense", action="block_ip"):
        self.name, self.action = name, action
        self.apply_calls, self.revert_calls = 0, 0
        self.active = set()
        self.after_apply = self.after_revert = None

    def recovery_reference(self, command):
        return "ref:" + command["idempotency_key"]

    def apply(self, command):
        self.apply_calls += 1
        self.active.add(command["idempotency_key"])
        if self.after_apply:
            raise self.after_apply
        return AdapterOutcome.success(adapter_reference=self.recovery_reference(command), evidence_refs=("applied",))

    def verify(self, command, *, adapter_reference):
        if command["idempotency_key"] not in self.active:
            return AdapterOutcome.failure(code="ABSENT", message="not enforced")
        return AdapterOutcome.success(adapter_reference=adapter_reference, evidence_refs=("enforced",))

    def revert(self, command, *, adapter_reference):
        self.revert_calls += 1
        self.active.discard(command["idempotency_key"])
        if self.after_revert:
            raise self.after_revert
        return AdapterOutcome.success(adapter_reference=adapter_reference, evidence_refs=("removed",))


def setup_engine(path, adapter=None, store_type=SQLiteResponseStore):
    catalog = PolicyCatalog.from_path(ROOT / "response/policies/default.yaml")
    auth = HmacCommandAuthenticator(keys={"test": b"x" * 32}, signing_key_id="test")
    adapter = FakeAdapter() if adapter is None else adapter
    store = store_type(path)
    engine = ResponseOrchestrator(catalog=catalog, authenticator=auth, store=store,
                                  adapters=[adapter, FakeAdapter("wazuh", "isolate_host")])
    return engine, store, adapter, catalog, auth


def command(catalog, auth, number=1, *, target="172.16.60.10", now=NOW):
    policy = catalog.policy("COR-001")
    value = {
        "schema_version": "response-command-v1", "request_id": f"request-{number}",
        "decision_event_id": f"decision-{number}", "correlation_id": f"trace-{number}",
        "policy": {"id": policy.id, "version": policy.version, "sha256": policy.sha256},
        "target": {"type": "ip", "value": target}, "action": policy.action,
        "ttl_seconds": policy.ttl_seconds, "allowlist_checked": True, "rollback_required": True,
        "idempotency_key": f"idemp-{number:064d}",
        "authorization": {"issuer": "decision_engine", "key_id": "test", "issued_at": now.isoformat(),
                          "expires_at": (now + timedelta(seconds=300)).isoformat()},
    }
    value["authorization"]["signature"] = auth.sign(value)
    return value


def validate_history(engine, response_id):
    schema = json.loads((ROOT / "response/schemas/response-audit-event-v1.schema.json").read_text())
    for event in engine.audit_history(response_id):
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(event)


def test_restart_preserves_authorization_dedup_and_ttl(tmp_path):
    path = tmp_path / "private" / "response.sqlite"
    engine, store, adapter, catalog, auth = setup_engine(path)
    cmd = command(catalog, auth)
    request = engine.submit(cmd, now=NOW)
    store.close()
    engine, store, _, _, _ = setup_engine(path, adapter)
    try:
        assert engine.submit(cmd, now=NOW).deduplicated
        assert engine.apply(request.response_id, now=NOW).state == "APPLIED"
        assert engine.verify(request.response_id, now=NOW).state == "VERIFIED"
    finally:
        store.close()
    engine, store, _, _, _ = setup_engine(path, adapter)
    try:
        later = NOW + timedelta(seconds=cmd["ttl_seconds"] + 1)
        assert engine.expire_due(now=later)[0].state == "EXPIRED"
        assert adapter.apply_calls == 1 and not adapter.active
        assert engine.expire_due(now=later) == ()
        validate_history(engine, request.response_id)
    finally:
        store.close()


def test_restart_does_not_reset_rate_limit(tmp_path):
    path = tmp_path / "private" / "response.sqlite"
    engine, store, _, catalog, auth = setup_engine(path)
    for number in range(catalog.rate_limit.max_actions):
        assert engine.submit(command(catalog, auth, number), now=NOW).accepted
    store.close()
    engine, store, _, catalog, auth = setup_engine(path)
    try:
        result = engine.submit(command(catalog, auth, 100), now=NOW)
        assert result.state == "FAILED" and not result.accepted
        assert result.audit_event["failure"]["code"] == "RATE_LIMITED"
    finally:
        store.close()


@pytest.mark.parametrize("crash", [TimeoutError("receipt lost"), SystemExit("process stopped")])
def test_uncertain_apply_recovers_after_restart_without_reapplying(tmp_path, crash):
    path = tmp_path / "private" / "response.sqlite"
    engine, store, adapter, catalog, auth = setup_engine(path)
    request = engine.submit(command(catalog, auth), now=NOW)
    adapter.after_apply = crash
    if isinstance(crash, SystemExit):
        with pytest.raises(SystemExit):
            engine.apply(request.response_id, now=NOW)
    else:
        assert engine.apply(request.response_id, now=NOW).state == "FAILED"
    store.close()
    engine, store, _, _, _ = setup_engine(path, adapter)
    try:
        with pytest.raises(CommandRejected):
            engine.apply(request.response_id, now=NOW)
        recovered = engine.recover_pending(now=NOW + timedelta(days=1))
        assert recovered[0].state == "ROLLED_BACK"
        assert "application" not in recovered[0].audit_event
        assert adapter.apply_calls == 1 and not adapter.active
        assert engine.recover_pending(now=NOW) == ()
        validate_history(engine, request.response_id)
    finally:
        store.close()


class FailedCommitStore(SQLiteResponseStore):
    fail_state = None
    fail_after_commit = False
    fail_intent = False

    def checkpoint(self, record, *, event=None):
        should_fail = event is not None and event["state"] == self.fail_state
        if self.fail_intent and event is None and record["pending_operation"] == "apply":
            raise OSError("intent journal unavailable")
        if should_fail and not self.fail_after_commit:
            raise OSError("audit not committed")
        super().checkpoint(record, event=event)
        if should_fail:
            raise OSError("commit acknowledgement lost")


def test_intent_must_be_durable_before_any_adapter_call(tmp_path):
    engine, store, adapter, catalog, auth = setup_engine(tmp_path / "private" / "response.sqlite", store_type=FailedCommitStore)
    try:
        request = engine.submit(command(catalog, auth), now=NOW)
        store.fail_intent = True
        with pytest.raises(OSError):
            engine.apply(request.response_id, now=NOW)
        assert adapter.apply_calls == 0
        with pytest.raises(RuntimeError):
            engine.apply(request.response_id, now=NOW)
    finally:
        store.close()


@pytest.mark.parametrize("after_commit", [False, True])
def test_applied_commit_failure_reopens_consistently(tmp_path, after_commit):
    path = tmp_path / "private" / "response.sqlite"
    engine, store, adapter, catalog, auth = setup_engine(path, store_type=FailedCommitStore)
    request = engine.submit(command(catalog, auth), now=NOW)
    store.fail_state, store.fail_after_commit = "APPLIED", after_commit
    with pytest.raises(OSError):
        engine.apply(request.response_id, now=NOW)
    with pytest.raises(RuntimeError):
        engine.rollback(request.response_id, now=NOW)
    store.close()
    engine, store, _, _, _ = setup_engine(path, adapter)
    try:
        with pytest.raises(CommandRejected):
            engine.apply(request.response_id, now=NOW)
        if after_commit:
            assert engine.audit_history(request.response_id)[-1]["state"] == "APPLIED"
            assert engine.rollback(request.response_id, now=NOW).state == "ROLLED_BACK"
        else:
            assert engine.recover_pending(now=NOW)[0].state == "ROLLED_BACK"
        assert adapter.apply_calls == 1 and not adapter.active
        validate_history(engine, request.response_id)
    finally:
        store.close()


def test_revert_crash_is_recovered_idempotently(tmp_path):
    path = tmp_path / "private" / "response.sqlite"
    engine, store, adapter, catalog, auth = setup_engine(path)
    request = engine.submit(command(catalog, auth), now=NOW)
    engine.apply(request.response_id, now=NOW)
    adapter.after_revert = SystemExit("crash after removal")
    with pytest.raises(SystemExit):
        engine.rollback(request.response_id, now=NOW)
    store.close()
    adapter.after_revert = None
    engine, store, _, _, _ = setup_engine(path, adapter)
    try:
        assert engine.recover_pending(now=NOW)[0].state == "ROLLED_BACK"
        assert adapter.revert_calls == 2 and adapter.apply_calls == 1
        validate_history(engine, request.response_id)
    finally:
        store.close()


def test_unresolved_target_is_not_applied_twice(tmp_path):
    engine, store, adapter, catalog, auth = setup_engine(tmp_path / "private" / "response.sqlite")
    try:
        first = engine.submit(command(catalog, auth, 1), now=NOW)
        second = engine.submit(command(catalog, auth, 2), now=NOW)
        engine.apply(first.response_id, now=NOW)
        with pytest.raises(CommandRejected):
            engine.apply(second.response_id, now=NOW)
        assert adapter.apply_calls == 1
        engine.rollback(first.response_id, now=NOW)
        assert engine.apply(second.response_id, now=NOW).state == "APPLIED"
    finally:
        store.close()


def test_only_one_owner_and_closed_store_cannot_apply(tmp_path):
    path = tmp_path / "private" / "response.sqlite"
    engine, store, adapter, catalog, auth = setup_engine(path)
    request = engine.submit(command(catalog, auth), now=NOW)
    try:
        with pytest.raises(RuntimeError):
            SQLiteResponseStore(path)
    finally:
        store.close()
    with pytest.raises(RuntimeError):
        engine.apply(request.response_id, now=NOW)
    assert adapter.apply_calls == 0


def test_audit_and_input_are_immutable(tmp_path):
    engine, store, _, catalog, auth = setup_engine(tmp_path / "private" / "response.sqlite")
    request = engine.submit(command(catalog, auth), now=NOW)
    try:
        for statement in ("DELETE FROM audit", "UPDATE audit SET payload='{}'", "DELETE FROM records", "UPDATE records SET command='{}'"):
            with pytest.raises(sqlite3.IntegrityError), store.db:
                store.db.execute(statement)
        returned = store.latest(request.response_id)
        returned["state"] = "VERIFIED"
        assert store.latest(request.response_id)["state"] == "REQUESTED"
    finally:
        store.close()


def test_opnsense_compensates_the_peer_whose_add_timed_out():
    first, second = Mock(), Mock()
    first.add_soc_blocklist_address.return_value = "added"
    first.soc_blocklist_contains.return_value = True
    second.add_soc_blocklist_address.side_effect = TimeoutError()
    adapter = OPNsenseBlocklistAdapter(primary=OPNsensePeer("a", first), secondary=OPNsensePeer("b", second))
    result = adapter.apply({"action": "block_ip", "target": {"type": "ip", "value": "172.16.60.10"}, "idempotency_key": "operation"})
    assert not result.ok
    for peer in (first, second):
        peer.remove_soc_blocklist_address.assert_called_once_with(address="172.16.60.10", idempotency_key="operation")


def test_snapshot_failure_rolls_back_the_audit_insert(tmp_path):
    path = tmp_path / "private" / "response.sqlite"
    engine, store, adapter, catalog, auth = setup_engine(path)
    request = engine.submit(command(catalog, auth), now=NOW)
    store.db.execute('''CREATE TRIGGER reject_applied_snapshot BEFORE UPDATE ON records
        WHEN NEW.snapshot LIKE '%"state":"APPLIED"%'
        BEGIN SELECT RAISE(ABORT, 'injected snapshot failure'); END''')
    with pytest.raises(sqlite3.IntegrityError):
        engine.apply(request.response_id, now=NOW)
    assert store.latest(request.response_id)["state"] == "REQUESTED"
    assert store.load()[0]["pending_operation"] == "apply"
    store.close()
    engine, store, _, _, _ = setup_engine(path, adapter)
    try:
        assert engine.recover_pending(now=NOW)[0].state == "ROLLED_BACK"
        assert adapter.apply_calls == 1
    finally:
        store.close()


def test_wazuh_uses_operation_identity_for_apply_and_recovery():
    client = Mock()
    client.start_isolation.return_value = "receipt"
    client.restore_isolation.return_value = "removed"
    client.isolation_is_removed.return_value = True
    adapter = WazuhIsolationAdapter(client=client)
    cmd = {"action": "isolate_host", "target": {"type": "host", "value": "endpoint"},
           "idempotency_key": "stable-operation", "correlation_id": "trace-one"}
    result = adapter.apply(cmd)
    cmd["correlation_id"] = "trace-two"
    assert adapter.recovery_reference(cmd) == result.adapter_reference
    adapter.revert(cmd, adapter_reference=result.adapter_reference)
    client.start_isolation.assert_called_once_with(host="endpoint", correlation_id="stable-operation")
    client.restore_isolation.assert_called_once_with(host="endpoint", correlation_id="stable-operation")


@pytest.mark.parametrize("reported", ["false", "true", None, 1])
def test_non_boolean_peer_readback_cannot_prove_containment(reported):
    client = Mock()
    client.isolation_is_enforced.return_value = reported
    client.isolation_is_removed.return_value = reported
    adapter = WazuhIsolationAdapter(client=client)
    cmd = {"action": "isolate_host", "target": {"type": "host", "value": "endpoint"},
           "idempotency_key": "operation"}
    assert not adapter.verify(cmd, adapter_reference="ref").ok
    assert not adapter.revert(cmd, adapter_reference="ref").ok


def test_existing_audit_only_database_is_not_silently_reused(tmp_path):
    from response.orchestrator.sqlite_audit import SQLiteAuditLedger

    path = tmp_path / "private" / "audit.sqlite"
    audit = SQLiteAuditLedger(path)
    audit.close()
    with pytest.raises(ValueError, match="incompatible"):
        SQLiteResponseStore(path)
