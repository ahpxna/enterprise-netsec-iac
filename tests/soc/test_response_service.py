"""Decision runner -> signed command -> orchestrator service -> audit export, offline."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator, FormatChecker

from response.decision import DecisionEngine
from response.orchestrator import ResponseOrchestrator, SQLiteResponseStore
from response.policy import PolicyCatalog
from response.service.decision_runner import DecisionRunner, DecisionState
from response.service.runner import AuditExporter, ResponseService
from response.signing import Ed25519CommandAuthenticator, generate_key_pair
from soc.workers.common import ElasticClient
from soc.workers.https import DeliveryError

from fake_elastic import FakeElastic
from test_durable_response import FakeAdapter

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)
WINDOW_END = NOW - timedelta(minutes=2)
ATTACKER = "192.168.40.20"


def ts(moment):
    return moment.isoformat().replace("+00:00", "Z")


def validator(path):
    return Draft202012Validator(json.loads((ROOT / path).read_text()), format_checker=FormatChecker())


def anomaly(event_id="an-1", entity=ATTACKER, entity_type="src_ip", score=0.97, minutes_before=2):
    end = NOW - timedelta(minutes=minutes_before)
    return {
        "@timestamp": ts(end + timedelta(seconds=30)), "schema_version": "anomaly-event-v1",
        "event": {"id": event_id, "kind": "event", "category": ["anomaly_detection"], "dataset": "soc.ai.anomaly"},
        "feature_vector": {"id": f"v-{event_id}", "entity_type": entity_type, "entity": entity,
                           "window_start": ts(end - timedelta(minutes=5)), "window_end": ts(end)},
        "ai": {"model_id": "approved-model", "score": score, "threshold": 0.9, "is_anomaly": score >= 0.9},
    }


def suricata_alert(event_id="sur-1", severity=1, source=ATTACKER, minutes_before=3):
    return {"@timestamp": ts(NOW - timedelta(minutes=minutes_before)),
            "event": {"id": event_id, "dataset": "suricata.eve", "category": ["network", "intrusion_detection"]},
            "source": {"ip": source}, "alert": {"severity": severity}}


@pytest.fixture()
def world(tmp_path):
    fake = FakeElastic()
    private, _ = generate_key_pair(tmp_path / "keys", "decision-test")
    signer = Ed25519CommandAuthenticator.signer(private, "decision-test")
    verifier = Ed25519CommandAuthenticator.verifier(tmp_path / "keys")
    catalog = PolicyCatalog.from_path(ROOT / "response/policies/default.yaml")
    sent = []
    state = DecisionState(tmp_path / "decision" / "state.sqlite")
    runner = DecisionRunner(elastic=ElasticClient(fake), engine=DecisionEngine(catalog, signer), state=state,
                            mode="enforce", send_command=sent.append, clock=lambda: NOW,
                            protected_assets=["172.16.50.1"])
    store = SQLiteResponseStore(tmp_path / "response" / "journal.sqlite")
    adapter = FakeAdapter()
    orchestrator = ResponseOrchestrator(catalog=catalog, authenticator=verifier, store=store,
                                        adapters=[adapter, FakeAdapter("wazuh", "isolate_host")])
    clock = {"now": NOW}
    service = ResponseService(orchestrator=orchestrator, exporter=AuditExporter(store, ElasticClient(fake)),
                              mode="enforce", clock=lambda: clock["now"], recover_every=1)
    service.start()
    yield SimpleNamespace(fake=fake, runner=runner, sent=sent, state=state, service=service, adapter=adapter,
                          store=store, clock=clock, catalog=catalog, tmp=tmp_path)
    state.close()
    store.close()


from types import SimpleNamespace  # noqa: E402


def decisions(fake):
    return [d for d in fake.docs_in("soc-response-*") if d.get("schema_version") == "correlation-decision-event-v1"]


def audits(fake):
    return [d for d in fake.docs_in("soc-response-*") if d.get("schema_version") == "response-audit-event-v1"]


def test_anomaly_only_never_creates_a_decision_or_command(world):
    world.fake.add("soc-ai-2026.09.07", "an-1", anomaly())
    assert world.runner.run_once() == {"processed": 1, "retry_pending": 0}
    assert world.sent == [] and decisions(world.fake) == []
    assert world.state.counts() == {"anomaly_only": 1}


def test_corroborated_anomaly_produces_a_validated_decision_and_one_signed_command(world):
    world.fake.add("soc-ai-2026.09.07", "an-1", anomaly())
    world.fake.add("soc-alerts-2026.09.07", "sur-1", suricata_alert())
    world.runner.run_once()
    (decision,) = decisions(world.fake)
    validator("schemas/events/correlation-decision-event-v1.schema.json").validate(decision)
    assert decision["decision"]["outcome"] == "response_requested"
    assert [s["kind"] for s in decision["signals"]] == ["ai_anomaly", "suricata_alert"]
    (command,) = world.sent
    validator("response/schemas/response-command-v1.schema.json").validate(command)
    assert command["target"] == {"type": "ip", "value": ATTACKER} and command["action"] == "block_ip"
    # a second pass over the same evidence neither duplicates the decision nor resends
    world.runner.run_once()
    assert len(world.sent) == 1 and len(decisions(world.fake)) == 1


def test_suricata_severity_one_is_high_and_satisfies_the_policy_floor(world):
    world.fake.add("soc-ai-2026.09.07", "an-1", anomaly())
    world.fake.add("soc-alerts-2026.09.07", "sur-low", suricata_alert("sur-low", severity=3))
    world.runner.run_once()
    # severity 3 (low) normalises to 1 < policy min_severity 2: no corroboration -> store/alert only
    assert world.sent == []
    world.fake.add("soc-ai-2026.09.07", "an-2", anomaly("an-2", minutes_before=1))
    world.fake.add("soc-alerts-2026.09.07", "sur-high", suricata_alert("sur-high", severity=1))
    world.runner.run_once()
    assert len(world.sent) == 1


def test_many_auth_failures_corroborate_via_a_single_count_signal(world):
    world.fake.add("soc-ai-2026.09.07", "an-1", anomaly())
    for index in range(25):
        world.fake.add("soc-auth-2026.09.07", f"auth-{index}", {
            "@timestamp": ts(NOW - timedelta(minutes=4, seconds=index)),
            "event": {"id": f"auth-{index}", "dataset": "freeradius.auth", "category": ["authentication"],
                      "outcome": "failure"},
            "source": {"ip": ATTACKER}})
    world.runner.run_once()
    assert len(world.sent) == 1
    (decision,) = decisions(world.fake)
    assert "authentication_failures" in [s["kind"] for s in decision["signals"]]


def test_observe_mode_records_an_alert_and_sends_nothing(world):
    runner = DecisionRunner(elastic=ElasticClient(world.fake), engine=world.runner._engine, state=world.state,
                            mode="observe", send_command=None, clock=lambda: NOW)
    world.fake.add("soc-ai-2026.09.07", "an-1", anomaly())
    world.fake.add("soc-alerts-2026.09.07", "sur-1", suricata_alert())
    runner.run_once()
    (decision,) = decisions(world.fake)
    validator("schemas/events/correlation-decision-event-v1.schema.json").validate(decision)
    assert decision["decision"] == {**decision["decision"], "outcome": "alert", "action": "none",
                                    "automatic_response_eligible": False}
    assert "response_request_id" not in decision["decision"] and world.sent == []


def test_protected_and_stale_evidence_never_become_commands(world):
    world.fake.add("soc-ai-2026.09.07", "protected", anomaly("protected", entity="172.16.50.1"))
    world.fake.add("soc-alerts-2026.09.07", "sur-p", suricata_alert("sur-p", source="172.16.50.1"))
    world.fake.add("soc-ai-2026.09.07", "stale", anomaly("stale", minutes_before=45))
    world.fake.add("soc-alerts-2026.09.07", "sur-s", suricata_alert("sur-s", minutes_before=46))
    world.runner.run_once()
    assert world.sent == []
    outcomes = {d["target"]["value"]: d["decision"]["outcome"] for d in decisions(world.fake)}
    assert outcomes["172.16.50.1"] == "denied"


def test_retryable_delivery_failure_blocks_the_cursor_then_succeeds(world):
    attempts = {"n": 0}

    def flaky(command):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise DeliveryError("TLS_OR_NETWORK_UNAVAILABLE", retryable=True)
        world.sent.append(command)

    world.runner._send = flaky
    world.fake.add("soc-ai-2026.09.07", "an-1", anomaly())
    world.fake.add("soc-alerts-2026.09.07", "sur-1", suricata_alert())
    assert world.runner.run_once()["retry_pending"] == 1 and world.sent == []
    assert world.runner.run_once()["processed"] == 1 and len(world.sent) == 1
    assert len(decisions(world.fake)) == 1     # the decision document is created exactly once


def test_host_isolation_is_denied_until_a_host_is_explicitly_enrolled(world):
    world.fake.add("soc-ai-2026.09.07", "an-h", anomaly("an-h", entity="dmz-web", entity_type="host"))
    world.fake.add("soc-alerts-2026.09.07", "wz-1", {
        "@timestamp": ts(NOW - timedelta(minutes=3)),
        "event": {"id": "wz-1", "dataset": "wazuh.alerts", "severity": 13}, "host": {"name": "dmz-web"}})
    world.runner.run_once()
    assert world.sent == []
    (decision,) = decisions(world.fake)
    assert decision["decision"]["outcome"] == "denied" and decision["target"] == {"type": "host", "value": "dmz-web"}


# ----------------------------------------------------------- orchestrator service


def run_full_loop(world):
    world.fake.add("soc-ai-2026.09.07", "an-1", anomaly())
    world.fake.add("soc-alerts-2026.09.07", "sur-1", suricata_alert())
    world.runner.run_once()
    return world.service.accept(world.sent[0])


def test_service_applies_verifies_and_exports_a_schema_valid_audit_trail(world):
    accepted = run_full_loop(world)
    assert accepted["accepted"] and accepted["state"] == "REQUESTED"
    report = world.service.tick()
    assert report["applied"] == 1 and report["verified"] == 1 and report["export"]["blocked"] is None
    assert world.service.status(accepted["response_id"])["state"] == "VERIFIED"
    states = [a["state"] for a in sorted(audits(world.fake), key=lambda a: a["transition_number"])]
    assert states == ["REQUESTED", "APPLIED", "VERIFIED"]
    schema = validator("response/schemas/response-audit-event-v1.schema.json")
    for event in audits(world.fake):
        schema.validate(event)
    assert world.adapter.apply_calls == 1
    world.service.tick()
    assert world.adapter.apply_calls == 1 and len(audits(world.fake)) == 3   # idempotent


def test_ttl_expiry_reverts_and_is_exported(world):
    accepted = run_full_loop(world)
    world.service.tick()
    world.clock["now"] = NOW + timedelta(seconds=901)
    report = world.service.tick()
    assert report["reverted"] == 1
    assert world.service.status(accepted["response_id"])["state"] == "EXPIRED"
    assert not world.adapter.active
    assert sorted(a["state"] for a in audits(world.fake))[-1] == "VERIFIED"
    assert "EXPIRED" in {a["state"] for a in audits(world.fake)}


def test_audit_export_outage_does_not_stop_the_lifecycle_and_resumes(world):
    accepted = run_full_loop(world)
    world.fake.fail_create = DeliveryError("TLS_OR_NETWORK_UNAVAILABLE", retryable=True)
    report = world.service.tick()
    assert report["applied"] == 1 and report["export"]["blocked"] == "TLS_OR_NETWORK_UNAVAILABLE"
    assert audits(world.fake) == []
    assert world.service.metrics().count("audit_export_blocked 1") == 1
    world.fake.fail_create = None
    world.service.tick()
    assert len(audits(world.fake)) == 3 and world.service.status(accepted["response_id"])["state"] == "VERIFIED"


def test_observe_mode_service_accepts_nothing_and_applies_nothing(world, tmp_path):
    service = ResponseService(orchestrator=world.service._orchestrator, exporter=None, mode="observe")
    service.start()
    world.fake.add("soc-ai-2026.09.07", "an-1", anomaly())
    world.fake.add("soc-alerts-2026.09.07", "sur-1", suricata_alert())
    world.runner.run_once()
    assert service.accept(world.sent[0])["accepted"] is False
    service.tick()
    assert world.adapter.apply_calls == 0


def test_forged_or_replayed_commands_are_rejected_before_any_adapter_call(world):
    world.fake.add("soc-ai-2026.09.07", "an-1", anomaly())
    world.fake.add("soc-alerts-2026.09.07", "sur-1", suricata_alert())
    world.runner.run_once()
    forged = deepcopy(world.sent[0])
    forged["target"]["value"] = "203.0.113.200"
    assert world.service.accept(forged)["accepted"] is False
    first = world.service.accept(world.sent[0])
    replay = world.service.accept(world.sent[0])
    assert first["accepted"] and replay["deduplicated"]
    world.service.tick()
    assert world.adapter.apply_calls == 1
