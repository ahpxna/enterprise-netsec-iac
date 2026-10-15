import sqlite3
from datetime import datetime, timezone

import pytest

from response.errors import CommandRejected
from response.orchestrator.sqlite_audit import SQLiteAuditLedger


def event(state="REQUESTED", previous=None, number=1):
    return {"response_id": "resp-test", "state": state,
            "previous_state": previous, "transition_number": number}


def test_submission_count_does_not_reset_on_restart(tmp_path):
    path = tmp_path / "audit" / "events.db"
    ledger = SQLiteAuditLedger(path)
    ledger.append({**event(), "policy_id": "COR-001", "@timestamp": "2026-09-07T00:00:01Z"})
    ledger.close()
    restarted = SQLiteAuditLedger(path)
    assert restarted.requested_since("COR-001", datetime(2026, 9, 7, tzinfo=timezone.utc)) == 1
    assert restarted.requested_since("COR-002", datetime(2026, 9, 7, tzinfo=timezone.utc)) == 0
    restarted.close()


def test_history_survives_restart_and_caller_mutation(tmp_path):
    path = tmp_path / "audit" / "events.db"
    ledger = SQLiteAuditLedger(path)
    original = event()
    ledger.append(original)
    original["state"] = "FAILED"
    ledger.close()
    recovered = SQLiteAuditLedger(path)
    assert recovered.latest("resp-test")["state"] == "REQUESTED"
    recovered.append(event("APPLIED", "REQUESTED", 2))
    assert len(recovered.events("resp-test")) == 2
    recovered.close()


def test_application_intent_survives_crash_before_result(tmp_path):
    path = tmp_path / "audit" / "events.db"
    ledger = SQLiteAuditLedger(path)
    ledger.append(event())
    ledger.claim_apply("resp-test")
    ledger.close()
    restarted = SQLiteAuditLedger(path)
    with pytest.raises(CommandRejected, match="reconciliation"):
        restarted.claim_apply("resp-test")
    assert restarted.latest("resp-test")["state"] == "REQUESTED"
    pending = restarted.recovery_queue()
    assert len(pending) == 1
    assert pending[0]["requires_peer_reconciliation"]
    assert pending[0]["automatic_replay_allowed"] is False
    restarted.close()


def test_recovery_queue_retains_active_and_removes_proven_rollback(tmp_path):
    ledger = SQLiteAuditLedger(tmp_path / "audit" / "events.db")
    ledger.append(event())
    ledger.claim_apply("resp-test")
    ledger.append(event("APPLIED", "REQUESTED", 2))
    assert ledger.recovery_queue()[0]["state"] == "APPLIED"
    ledger.append(event("ROLLED_BACK", "APPLIED", 3))
    assert ledger.recovery_queue() == ()
    ledger.close()


def test_stale_writer_and_invalid_transition_leave_no_partial_event(tmp_path):
    path = tmp_path / "audit" / "events.db"
    first, second = SQLiteAuditLedger(path), SQLiteAuditLedger(path)
    first.append(event())
    with pytest.raises(CommandRejected):
        second.append(event())
    with pytest.raises(CommandRejected):
        second.append(event("EXPIRED", "REQUESTED", 2))
    assert len(first.events("resp-test")) == 1
    first.close()
    second.close()


@pytest.mark.parametrize("statement", ["DELETE FROM audit", "UPDATE audit SET body='{}'"])
def test_prior_events_cannot_be_mutated(tmp_path, statement):
    ledger = SQLiteAuditLedger(tmp_path / "audit" / "events.db")
    ledger.append(event())
    with pytest.raises(sqlite3.IntegrityError):
        ledger.db.execute(statement)
    assert ledger.latest("resp-test") == event()
    ledger.close()
