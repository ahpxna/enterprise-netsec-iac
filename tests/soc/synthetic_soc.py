"""Deterministic synthetic telemetry for offline end-to-end tests of the AI pipeline.

This is test scaffolding only.  It makes no claim about real traffic, and any
metric computed from it is a unit-test artifact, not a research result.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import random
from typing import Iterator

DAY1 = datetime(2026, 8, 1, tzinfo=timezone.utc)
ENTITIES = [f"192.168.40.{n}" for n in range(10, 16)]


def stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _event(entity: str, moment: datetime, serial: int, dataset: str, **extra) -> dict:
    event_id = f"{entity}-{stamp(moment)}-{serial}"
    document = {
        "@timestamp": stamp(moment),
        "event": {"id": event_id, "kind": "event", "dataset": dataset, "category": ["network"]},
        "cxyz": {"schema_version": "soc-event-v1", "ingestion_id": event_id},
        "source": {"ip": entity},
    }
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(document.get(key), dict):
            document[key].update(value)
        else:
            document[key] = value
    return document


def benign_window(entity: str, start: datetime, rng: random.Random) -> Iterator[dict]:
    serial = 0
    for _ in range(rng.randint(2, 4)):
        serial += 1
        yield _event(
            entity, start + timedelta(seconds=rng.randint(1, 290)), serial, "suricata.eve",
            event_type="flow", destination={"ip": rng.choice(["10.8.0.1", "10.8.0.2", "10.8.0.3"]),
                                             "port": rng.choice([443, 53, 80])},
            flow={"bytes_toserver": rng.randint(200, 2000), "bytes_toclient": rng.randint(1000, 9000)},
        )
    for _ in range(rng.randint(1, 3)):
        serial += 1
        yield _event(
            entity, start + timedelta(seconds=rng.randint(1, 290)), serial, "firewall.syslog",
            destination={"ip": "172.16.50.1", "port": 53}, event={"action": "pass"}, network={"bytes": 80},
        )


def scan_window(entity: str, start: datetime, rng: random.Random) -> Iterator[dict]:
    serial = 0
    for port in range(1, 41):
        serial += 1
        yield _event(
            entity, start + timedelta(seconds=port), serial, "firewall.syslog",
            destination={"ip": "172.16.50.1", "port": port}, event={"action": "blocked"}, network={"bytes": 60},
        )
    for _ in range(3):
        serial += 1
        yield _event(
            entity, start + timedelta(seconds=100 + serial), serial, "suricata.eve",
            event_type="alert", alert={"severity": 1}, destination={"ip": "172.16.50.1", "port": 22},
            event={"category": ["network", "intrusion_detection"]},
        )


def exfil_window(entity: str, start: datetime, rng: random.Random) -> Iterator[dict]:
    serial = 0
    for _ in range(4):
        serial += 1
        yield _event(
            entity, start + timedelta(seconds=10 * serial), serial, "suricata.eve",
            event_type="flow", destination={"ip": "203.0.113.9", "port": 443},
            flow={"bytes_toserver": 50_000_000, "bytes_toclient": 1000},
        )
    for index in range(30):
        serial += 1
        yield _event(
            entity, start + timedelta(seconds=60 + index), serial, "suricata.eve",
            event_type="dns", dns={"type": "query", "rrname": f"x{index}.exfil.example"},
        )


SCENARIOS = {
    # (day offset, entity index, first hour:minute, last hour:minute, kind)
    "scan-validation": (1, 0, (11, 0), (11, 30), "scan"),
    "exfil-validation": (1, 2, (12, 0), (12, 30), "exfil"),
    "scan-test": (2, 1, (11, 15), (11, 45), "scan"),
    "exfil-test": (2, 3, (12, 15), (12, 45), "exfil"),
}


def scenario_windows():
    for name, (day, index, first, last, kind) in SCENARIOS.items():
        start = DAY1 + timedelta(days=day, hours=first[0], minutes=first[1])
        end = DAY1 + timedelta(days=day, hours=last[0], minutes=last[1])
        yield name, ENTITIES[index], start, end, kind


def generate_events(seed: int = 7) -> list[dict]:
    """Three business-hour days: benign traffic everywhere, attacks only on days 2 and 3."""

    rng = random.Random(seed)
    attacks = {}
    for name, entity, start, end, kind in scenario_windows():
        moment = start
        while moment < end:
            attacks[(entity, moment)] = kind
            moment += timedelta(minutes=5)
    events: list[dict] = []
    for day in range(3):
        moment = DAY1 + timedelta(days=day, hours=10)
        end = DAY1 + timedelta(days=day, hours=14)
        while moment < end:
            for entity in ENTITIES:
                kind = attacks.get((entity, moment))
                maker = {"scan": scan_window, "exfil": exfil_window}.get(kind, benign_window)
                events.extend(maker(entity, moment, rng))
            moment += timedelta(minutes=5)
    return events


def scenario_file_payload() -> dict:
    return {
        "schema_version": "scenarios-v1",
        "scenarios": [
            {"id": name, "entity": entity, "start": stamp(start), "end": stamp(end)}
            for name, entity, start, end, _ in scenario_windows()
        ],
    }


def boundaries() -> list[datetime]:
    return [DAY1 + timedelta(days=offset) for offset in range(4)]


def training_arguments(dataset_dir, output, **overrides):
    """Argparse namespace shared by the candidate-training CLIs."""

    import argparse

    values = dict(
        train_vectors=dataset_dir / "train.jsonl", validation_vectors=dataset_dir / "validation.jsonl",
        test_vectors=dataset_dir / "test.jsonl", session_assignments=dataset_dir / "session-assignments.json",
        dataset_manifest=dataset_dir / "dataset-manifest.yaml", labels=dataset_dir / "labels.jsonl",
        feature_schema="network-window-v1", model_id="synthetic-model-1", random_seed=3,
        git_sha="0123456789abcdef0123456789abcdef01234567",
        runtime_image_digest="sha256:" + "a" * 64, library_lock_sha256="b" * 64, output_dir=output,
        max_false_positives_per_hour=1.0, n_estimators=60, contamination="auto",
    )
    values.update(overrides)
    return argparse.Namespace(**values)
