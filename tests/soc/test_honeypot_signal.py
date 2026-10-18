"""A DMZ honeypot interaction is an independent corroborating signal - but only one, and never for a protected target."""

from datetime import timedelta
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from response.decision import DecisionEngine
from response.errors import PolicyError
from response.policy import PolicyCatalog, SignalRequirement
from soc.workers.common import ElasticClient

from test_response_service import ATTACKER, NOW, anomaly, decisions, ts, world  # noqa: F401  (world is a fixture)

ROOT = Path(__file__).resolve().parents[2]


def honeypot_event(event_id, severity, source=ATTACKER, minutes_before=3, action="cowrie.login.failed"):
    return {"@timestamp": ts(NOW - timedelta(minutes=minutes_before)),
            "event": {"id": event_id, "dataset": "cowrie.honeypot", "severity": severity, "action": action,
                      "category": ["network", "intrusion_detection", "authentication"]},
            "source": {"ip": source}, "destination": {"ip": "195.1.1.161", "port": 2222}}


def schema(path):
    return Draft202012Validator(json.loads((ROOT / path).read_text()), format_checker=FormatChecker())


def test_a_honeypot_login_attempt_corroborates_an_anomaly(world):
    world.fake.add("soc-ai-2026.09.07", "an-1", anomaly())
    world.fake.add("soc-alerts-2026.09.07", "hp-1", honeypot_event("hp-1", 5))
    world.runner.run_once()
    (decision,) = decisions(world.fake)
    schema("schemas/events/correlation-decision-event-v1.schema.json").validate(decision)
    assert decision["decision"]["outcome"] == "response_requested"
    assert [s["kind"] for s in decision["signals"]] == ["ai_anomaly", "honeypot_interaction"]
    assert len(world.sent) == 1 and world.sent[0]["target"] == {"type": "ip", "value": ATTACKER}


def test_many_honeypot_events_are_one_signal_not_many(world):
    world.fake.add("soc-ai-2026.09.07", "an-1", anomaly())
    for index, severity in enumerate((3, 5, 9, 9, 10)):
        world.fake.add("soc-alerts-2026.09.07", f"hp-{index}", honeypot_event(f"hp-{index}", severity, minutes_before=4 - index * 0.5))
    world.runner.run_once()
    (decision,) = decisions(world.fake)
    honeypot = [s for s in decision["signals"] if s["kind"] == "honeypot_interaction"]
    assert len(honeypot) == 1 and honeypot[0]["reference"].startswith("honeypot:")


def test_a_bare_connection_to_the_honeypot_is_not_enough(world):
    world.fake.add("soc-ai-2026.09.07", "an-1", anomaly())
    world.fake.add("soc-alerts-2026.09.07", "hp-1", honeypot_event("hp-1", 3, action="cowrie.session.connect"))
    world.runner.run_once()
    assert world.sent == []
    assert all(d["decision"]["outcome"] != "response_requested" for d in decisions(world.fake))


def test_honeypot_events_from_another_source_or_outside_the_window_do_not_count(world):
    world.fake.add("soc-ai-2026.09.07", "an-1", anomaly())
    world.fake.add("soc-alerts-2026.09.07", "hp-other", honeypot_event("hp-other", 9, source="203.0.113.77"))
    world.fake.add("soc-alerts-2026.09.07", "hp-old", honeypot_event("hp-old", 9, minutes_before=40))
    world.runner.run_once()
    assert world.sent == []


def test_a_honeypot_hit_never_makes_a_protected_or_transit_address_containable(world):
    for index, target in enumerate(("172.16.50.1", "10.255.0.2")):          # server1, and fw-core's NATed outside address
        world.fake.add("soc-ai-2026.09.07", f"an-{index}", anomaly(f"an-{index}", entity=target))
        world.fake.add("soc-alerts-2026.09.07", f"hp-{index}", honeypot_event(f"hp-{index}", 10, source=target))
    world.runner.run_once()
    assert world.sent == []
    assert {d["target"]["value"]: d["decision"]["outcome"] for d in decisions(world.fake)} == {
        "172.16.50.1": "denied", "10.255.0.2": "denied"}


def test_every_shipped_policy_accepts_the_honeypot_only_with_a_severity_floor():
    for name in ("default", "lab-path-b", "lab-validation", "lab-validation-path-b"):
        policy = PolicyCatalog.from_path(ROOT / f"response/policies/{name}.yaml").policy("COR-001")
        requirements = [r for r in policy.require_any if r.kind == "honeypot"]
        assert len(requirements) == 1 and requirements[0].min_severity == 5, name
    assert SignalRequirement.from_mapping({"type": "honeypot", "min_severity": 5}, "x").matches({"type": "honeypot", "severity": 8})
    with pytest.raises(PolicyError):
        SignalRequirement.from_mapping({"type": "honeypots"}, "x")


def test_the_engine_emits_a_schema_valid_action_request_for_a_honeypot_corroborated_anomaly(world):
    engine: DecisionEngine = world.runner._engine
    target = {"type": "ip", "value": ATTACKER}
    result = engine.evaluate(
        policy_id="COR-001",
        anomaly={"event_id": "an-9", "model_id": "m", "score": 0.97, "threshold": 0.9, "is_anomaly": True,
                 "observed_at": ts(NOW - timedelta(minutes=2)), "target": target},
        independent_signals=[{"type": "honeypot", "reference": "honeypot:abc", "observed_at": ts(NOW - timedelta(minutes=3)),
                              "severity": 9, "count": 4, "target": target}],
        target=target, now=NOW)
    assert result.eligible
    schema("schemas/response/action-request.schema.json").validate(result.action_request)
    schema("schemas/events/correlation-decision-event-v1.schema.json").validate(result.decision_event)
    assert {"type": "honeypot", "reference": "honeypot:abc"} in result.action_request["signals"]


def test_the_live_honeypot_check_uses_the_decision_runners_own_evidence_query(world):
    # scripts/honeypot_e2e.py builds a bare observe-mode DecisionRunner and calls its evidence gathering;
    # keep that coupling honest so the live check cannot silently drift from the real decision code.
    import importlib.util

    spec = importlib.util.spec_from_file_location("honeypot_e2e", ROOT / "scripts/honeypot_e2e.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for index, severity in enumerate((3, 8, 9)):
        world.fake.add("soc-alerts-2026.09.07", f"hp-{index}", honeypot_event(f"hp-{index}", severity, minutes_before=3 - index))
    world.fake.add("soc-alerts-2026.09.07", "hp-other", honeypot_event("hp-other", 10, source="198.51.100.77"))
    (signal,) = module.honeypot_signals(ElasticClient(world.fake), ATTACKER, NOW - timedelta(minutes=10), NOW)
    assert signal["severity"] == 9 and signal["count"] == 3
    assert module.protected("10.255.0.2") and not module.protected(ATTACKER)
