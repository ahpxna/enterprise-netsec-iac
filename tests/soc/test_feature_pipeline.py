"""Feature semantics and the continuous feature worker, using an in-memory Elasticsearch."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ai.features.contracts import validate_vector
from ai.features.engine import FeatureContractError, build_endpoint_vectors, build_network_vectors
from soc.workers import features as worker
from soc.workers.common import ElasticClient
from soc.workers.https import DeliveryError

from fake_elastic import FakeElastic

START = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)
GIT = "0123456789abcdef0123456789abcdef01234567"


def ts(seconds: int) -> str:
    return (START + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def normalized(event_id, seconds, dataset, **extra):
    base = {
        "@timestamp": ts(seconds),
        "event": {"id": event_id, "kind": "event", "dataset": dataset, "category": ["network"]},
        "cxyz": {"schema_version": "soc-event-v1", "ingestion_id": event_id},
        "source": {"ip": "192.168.40.20"},
    }
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key].update(value)
        else:
            base[key] = value
    return base


def sample_network_events():
    return [
        normalized("flow-1", 10, "suricata.eve", event_type="flow", destination={"ip": "10.0.0.1", "port": 443},
                   flow={"bytes_toserver": 1000, "bytes_toclient": 4000}, network={"bytes": 5000}),
        normalized("alert-1", 11, "suricata.eve", event_type="alert", destination={"ip": "10.0.0.1", "port": 443},
                   flow={"bytes_toserver": 900, "bytes_toclient": 100}, alert={"severity": 1},
                   event={"category": ["network", "intrusion_detection"]}),
        normalized("dns-q", 12, "suricata.eve", event_type="dns", dns={"type": "query", "rrname": "Example.COM."}),
        normalized("dns-a", 13, "suricata.eve", event_type="dns", dns={"type": "answer", "rrname": "example.com"}),
        normalized("tls-1", 14, "suricata.eve", event_type="tls"),
        normalized("fw-1", 15, "firewall.syslog", destination={"ip": "172.16.50.1", "port": 22},
                   event={"action": "blocked"}, network={"bytes": 60}),
        normalized("fw-2", 16, "firewall.syslog", destination={"ip": "172.16.50.1", "port": 80},
                   event={"action": "pass"}, network={"bytes": 40}),
        normalized("sys-1", 17, "network.syslog"),
        normalized("auth-1", 18, "freeradius.auth", event={"category": ["authentication"], "outcome": "failure"}),
        normalized("auth-2", 19, "freeradius.auth", event={"category": ["authentication"], "outcome": "success"}),
    ]


def test_network_features_do_not_double_count_one_flow():
    (vector,) = build_network_vectors(
        sample_network_events(), window_start=START, window_end=START + timedelta(minutes=5),
        generator_git_sha=GIT,
    )
    validate_vector(vector)
    features = vector["features"]
    # one Suricata flow + two firewall lines; alert/dns/tls/device syslog are not connections
    assert features["connection_count"] == 3
    assert features["unique_dst_ip"] == 2
    assert features["unique_dst_port"] == 3
    # flow bytes come only from the flow record; the alert's running counters are ignored
    assert features["bytes_out"] == 1000 + 60 + 40
    assert features["bytes_in"] == 4000
    assert features["blocked_ratio"] == pytest.approx(1 / 3)
    assert features["dns_query_count"] == 1
    assert features["unique_domain_count"] == 1
    assert features["tls_count"] == 1
    assert features["suricata_alert_count"] == 1
    assert features["failed_auth_count"] == 1


def test_vectors_are_reproducible_and_order_independent():
    events = sample_network_events()
    first = build_network_vectors(events, window_start=START, window_end=START + timedelta(minutes=5),
                                  generator_git_sha=GIT)
    second = build_network_vectors(list(reversed(events)), window_start=START,
                                   window_end=START + timedelta(minutes=5), generator_git_sha=GIT)
    assert first == second


def test_conflicting_duplicate_event_ids_are_rejected():
    events = sample_network_events()
    clone = dict(events[0])
    clone["flow"] = {"bytes_toserver": 1, "bytes_toclient": 1}
    with pytest.raises(FeatureContractError):
        build_network_vectors([*events, clone], window_start=START, window_end=START + timedelta(minutes=5),
                              generator_git_sha=GIT)


def test_endpoint_baseline_marks_unknown_processes_rare():
    def proc(event_id, seconds, name, **extra):
        return normalized(event_id, seconds, "wazuh.archives", host={"name": "dmz-web"},
                          event={"category": ["host", "process"]}, process={"name": name}, **extra)

    events = [
        proc("p1", 1, "nginx"), proc("p2", 2, "xmrig"), proc("p3", 3, "pwsh"),
        normalized("f1", 4, "wazuh.archives", host={"name": "dmz-web"}, event={"category": ["host", "file"]}),
        normalized("l1", 5, "wazuh.archives", host={"name": "dmz-web"},
                   event={"category": ["host", "authentication"], "outcome": "failure"}),
    ]
    for event in events:
        event.pop("source", None)
    (vector,) = build_endpoint_vectors(
        events, window_start=START, window_end=START + timedelta(minutes=5), generator_git_sha=GIT,
        process_baseline=["nginx", "sshd"],
    )
    validate_vector(vector)
    assert vector["features"]["process_count"] == 3
    assert vector["features"]["rare_process_count"] == 2
    assert vector["features"]["powershell_count"] == 1
    assert vector["features"]["fim_change_count"] == 1
    assert vector["features"]["failed_login_count"] == 1


# ------------------------------------------------------------------ worker


def seed(fake, events, index="soc-network-2026.09.07"):
    for event in events:
        fake.add(index, event["cxyz"]["ingestion_id"], event)


def make_state(tmp_path):
    return worker.FeatureState(tmp_path / "private" / "state.sqlite")


def run(fake, state, **overrides):
    options = dict(
        schemas=["network-window-v1"], git_sha=GIT, now=START + timedelta(minutes=20),
        lag=timedelta(seconds=180), lookback=timedelta(minutes=30), max_windows=24, max_events=1000,
    )
    options.update(overrides)
    return worker.run_once(ElasticClient(fake), state, **options)


def test_worker_emits_validated_vectors_and_is_idempotent(tmp_path):
    fake = FakeElastic()
    seed(fake, sample_network_events())
    state = make_state(tmp_path)
    summary = run(fake, state)
    assert summary["network-window-v1"]["done"] >= 1
    vectors = fake.docs_in("soc-features-*")
    assert len(vectors) == 1
    validate_vector(vectors[0])
    assert vectors[0]["entity"] == "192.168.40.20"
    again = run(fake, state)
    assert not again["network-window-v1"].get("failed")
    assert len(fake.docs_in("soc-features-*")) == 1
    assert state.status()["network-window-v1"]["done"] >= 1
    state.close()


def test_worker_does_not_process_windows_inside_the_lag(tmp_path):
    fake = FakeElastic()
    seed(fake, sample_network_events())
    state = make_state(tmp_path)
    run(fake, state, now=START + timedelta(minutes=6))  # window ends 10:05, lag 3m -> not closed
    assert fake.docs_in("soc-features-*") == []
    state.close()


def test_oversized_window_is_recorded_not_truncated(tmp_path):
    fake = FakeElastic()
    seed(fake, sample_network_events())
    state = make_state(tmp_path)
    summary = run(fake, state, max_events=3)
    assert summary["network-window-v1"].get("oversized") == 1
    assert fake.docs_in("soc-features-*") == []
    assert state.status()["network-window-v1"]["oversized"] == 1
    state.close()


def test_delivery_failure_is_retried_on_the_next_run(tmp_path):
    fake = FakeElastic()
    seed(fake, sample_network_events())
    state = make_state(tmp_path)
    fake.fail_create = DeliveryError("TLS_OR_NETWORK_UNAVAILABLE", retryable=True)
    assert run(fake, state)["network-window-v1"].get("failed") == 1
    assert fake.docs_in("soc-features-*") == []
    fake.fail_create = None
    assert run(fake, state)["network-window-v1"].get("done") >= 1
    assert len(fake.docs_in("soc-features-*")) == 1
    state.close()


def test_endpoint_worker_reads_only_endpoint_indices(tmp_path):
    fake = FakeElastic()
    endpoint = normalized("e1", 5, "wazuh.archives", host={"name": "dmz-web"},
                          event={"category": ["host", "process"]}, process={"name": "nginx"})
    endpoint.pop("source")
    seed(fake, [endpoint], index="soc-endpoint-2026.09.07")
    seed(fake, sample_network_events())
    state = make_state(tmp_path)
    run(fake, state, schemas=["endpoint-window-v1"], process_baseline=["nginx"])
    vectors = fake.docs_in("soc-features-*")
    assert [vector["entity"] for vector in vectors] == ["dmz-web"]
    assert vectors[0]["features"]["rare_process_count"] == 0
    state.close()


def test_closed_windows_are_aligned_and_bounded():
    now = datetime(2026, 9, 7, 10, 20, 30, tzinfo=timezone.utc)
    windows = worker.closed_windows(now=now, lag=timedelta(minutes=3), since=START, max_windows=100)
    assert windows[0] == START and windows[-1] == datetime(2026, 9, 7, 10, 10, tzinfo=timezone.utc)
    assert all(item.minute % 5 == 0 and item.second == 0 for item in windows)
    assert len(worker.closed_windows(now=now, lag=timedelta(minutes=3), since=START, max_windows=2)) == 2
