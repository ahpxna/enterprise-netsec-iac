"""Vector pull from soc-features-* into the durable outbox, with an in-memory ES."""

from datetime import timedelta

import pytest

from ai.features.engine import build_network_vectors
from soc.workers.common import ElasticClient
from soc.workers.enrichment import pull_features, serving_schema
from soc.workers.https import DeliveryError
from soc.workers.outbox import Outbox

from fake_elastic import FakeElastic
from test_feature_pipeline import GIT, START, normalized

APPROVED = "a" * 64


def vectors_for(entity_suffix, window_offset_minutes):
    start = START + timedelta(minutes=window_offset_minutes)
    event = normalized(f"flow-{entity_suffix}-{window_offset_minutes}", 10, "suricata.eve",
                       event_type="flow", flow={"bytes_toserver": 1, "bytes_toclient": 1},
                       destination={"ip": "10.0.0.1", "port": 443})
    event["@timestamp"] = (start + timedelta(seconds=10)).isoformat().replace("+00:00", "Z")
    event["source"] = {"ip": f"192.168.40.{entity_suffix}"}
    return build_network_vectors([event], window_start=start, window_end=start + timedelta(minutes=5),
                                 generator_git_sha=GIT)


def seeded():
    fake = FakeElastic()
    for suffix in (10, 11):
        for minutes in (0, 5):
            for vector in vectors_for(suffix, minutes):
                fake.add("soc-features-2026.09.07", vector["vector_id"], vector)
    return fake


def test_pull_enqueues_each_vector_once_and_resumes_from_the_cursor(tmp_path):
    fake = seeded()
    outbox = Outbox(tmp_path / "private" / "jobs.db")
    client = ElasticClient(fake)
    first = pull_features(outbox, client, feature_schema="network-window-v1",
                          metadata_hash=APPROVED, limit=3, page_size=2)
    assert first == {"pulled": 3, "added": 3, "duplicates": 0, "invalid": 0}
    second = pull_features(outbox, client, feature_schema="network-window-v1",
                           metadata_hash=APPROVED, limit=100)
    assert second["added"] == 1 and second["pulled"] == 1
    assert outbox.status()["pending"] == 4
    third = pull_features(outbox, client, feature_schema="network-window-v1",
                          metadata_hash=APPROVED, limit=100)
    assert third["pulled"] == 0
    outbox.close()


def test_pull_filters_by_the_served_feature_schema(tmp_path):
    fake = seeded()
    outbox = Outbox(tmp_path / "private" / "jobs.db")
    result = pull_features(outbox, ElasticClient(fake), feature_schema="endpoint-window-v1",
                           metadata_hash=APPROVED, limit=100)
    assert result["pulled"] == 0 and outbox.status()["pending"] == 0
    outbox.close()


def test_pull_counts_invalid_documents_without_queueing_them(tmp_path):
    fake = seeded()
    fake.add("soc-features-2026.09.07", "broken", {
        "feature_schema": "network-window-v1", "window_end": "2026-09-07T11:00:00Z", "vector_id": "broken",
    })
    outbox = Outbox(tmp_path / "private" / "jobs.db")
    result = pull_features(outbox, ElasticClient(fake), feature_schema="network-window-v1",
                           metadata_hash=APPROVED, limit=100)
    assert result["invalid"] == 1 and result["added"] == 4
    outbox.close()


@pytest.mark.parametrize("limit", [0, -1, True, 100001])
def test_pull_limit_is_bounded(tmp_path, limit):
    outbox = Outbox(tmp_path / "private" / "jobs.db")
    with pytest.raises(ValueError):
        pull_features(outbox, ElasticClient(FakeElastic()), feature_schema="network-window-v1",
                      metadata_hash=APPROVED, limit=limit)
    outbox.close()


class FakeInference:
    def __init__(self, status, reply):
        self.status, self.reply = status, reply

    def request(self, method, path, payload=None):
        assert (method, path, payload) == ("GET", "/model", None)
        return self.status, self.reply


def test_serving_schema_requires_a_ready_model():
    assert serving_schema(FakeInference(200, {"feature_schema": "network-window-v1"})) == "network-window-v1"
    with pytest.raises(DeliveryError) as caught:
        serving_schema(FakeInference(503, {}))
    assert caught.value.retryable


def test_history_fetcher_returns_the_preceding_windows_oldest_first_with_gaps_as_none():
    from ai.features.sequences import history_window_ends
    from soc.workers.enrichment import make_history_fetcher

    fake = FakeElastic()
    # window starts at +0, +5, +10, +20 minutes for entity .7 (so +15 is a gap) and one window for entity .8
    for minutes in (0, 5, 10, 20):
        for vector in vectors_for(7, minutes):
            fake.add("soc-features-x", f"{vector['vector_id']}", vector)
    for vector in vectors_for(8, 15):
        fake.add("soc-features-x", vector["vector_id"], vector)
    current = vectors_for(7, 25)[0]
    fetch = make_history_fetcher(ElasticClient(fake), 6)
    history = fetch(current)
    assert len(history) == 5                                   # T - 1 preceding windows
    ends = history_window_ends(current["window_end"], 6)
    present = {vector["window_end"]: vector["features"]
               for (_, _), vector in fake.documents.items() if vector["entity"] == current["entity"]}
    assert history == [present.get(end) for end in ends]
    assert [item is None for item in history] == [False, False, False, True, False]   # the +15..+20 window is a gap
    other = fetch(vectors_for(8, 25)[0])
    assert sum(item is not None for item in other) == 1          # only entity .8's own window counts
