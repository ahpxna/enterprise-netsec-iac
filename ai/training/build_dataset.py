#!/usr/bin/env python3
"""Build a leakage-safe, hashed dataset from normalized events and scenario windows.

Inputs are exported ``soc-event-v1`` JSONL (from ``python -m soc.workers.export_events``
or any capture) plus a ``scenarios-v1`` file describing the controlled attacks that
were run.  Outputs, all written under ``--output-dir`` (keep it outside Git):

* ``train.jsonl`` / ``validation.jsonl`` / ``test.jsonl`` - closed feature vectors
* ``labels.jsonl`` - scenario labels bound to vectors by canonical hash
* ``session-assignments.json`` - per-vector source/session membership ledger
* ``dataset-manifest.yaml`` - ``dataset-manifest-v1`` metadata binding all of the above

The training partition keeps only benign vectors.  A scenario may not straddle a
partition boundary: its vectors would share a session across partitions, which is
exactly the leakage the partition gate refuses.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

import yaml

from ai.evaluation.labels import LABELS_SCHEMA
from ai.features.contracts import feature_schema_sha256, sha256_file, validate_vector
from ai.features.engine import build_endpoint_vectors, build_network_vectors
from ai.training.partitions import canonical_hash

WINDOW = timedelta(minutes=5)
PARTITIONS = ("train", "validation", "test")
LABEL_PROFILES = {"train": "benign_biased", "validation": "mixed", "test": "held_out_attack"}
_SHA = re.compile(r"^[a-fA-F0-9]{7,64}$")


class DatasetBuildError(ValueError):
    """Raised when the capture, scenarios, or split cannot yield a trustworthy dataset."""


def _ts(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise DatasetBuildError("timestamps must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _rfc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _aligned(value: datetime) -> bool:
    return value.second == 0 and value.microsecond == 0 and value.minute % 5 == 0


def load_scenarios(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping) or payload.get("schema_version") != "scenarios-v1":
        raise DatasetBuildError("scenario file must be scenarios-v1")
    scenarios = []
    seen: set[str] = set()
    for item in payload.get("scenarios", []):
        if set(item) - {"id", "entity", "start", "end", "description"} or not {"id", "entity", "start", "end"} <= set(item):
            raise DatasetBuildError("scenario has missing or unsupported fields")
        if item["id"] in seen:
            raise DatasetBuildError(f"duplicate scenario id {item['id']!r}")
        seen.add(item["id"])
        start, end = _ts(item["start"]), _ts(item["end"])
        if end <= start:
            raise DatasetBuildError(f"scenario {item['id']!r} must end after it starts")
        scenarios.append({"id": item["id"], "entity": str(item["entity"]), "start": start, "end": end})
    return scenarios


def _entity_of(event: Mapping[str, Any], schema: str) -> str | None:
    node = event.get("source" if schema == "network-window-v1" else "host")
    key = "ip" if schema == "network-window-v1" else "name"
    value = node.get(key) if isinstance(node, Mapping) else None
    return value if isinstance(value, str) and value else None


def _session(event: Mapping[str, Any], entity: str, scenarios: Sequence[Mapping[str, Any]]) -> str:
    when = _ts(event["@timestamp"])
    for scenario in scenarios:
        if scenario["entity"] == entity and scenario["start"] <= when <= scenario["end"]:
            return f"scenario:{scenario['id']}"
    return f"entity-day:{entity}:{when.date().isoformat()}"


def _attack_scenario(vector: Mapping[str, Any], scenarios: Sequence[Mapping[str, Any]]):
    start, end = _ts(vector["window_start"]), _ts(vector["window_end"])
    hits = [
        item for item in scenarios
        if item["entity"] == vector["entity"] and start < item["end"] and end > item["start"]
    ]
    return min(hits, key=lambda item: item["start"]) if hits else None


def build(
    *,
    events: Iterable[Mapping[str, Any]],
    scenarios: Sequence[Mapping[str, Any]],
    schema: str,
    boundaries: Sequence[datetime],
    git_sha: str,
    process_baseline: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Return partition vectors, labels and ledgers (pure; no filesystem access)."""

    if len(boundaries) != 4 or any(not _aligned(item) for item in boundaries):
        raise DatasetBuildError("four five-minute-aligned boundaries are required")
    if list(boundaries) != sorted(set(boundaries)):
        raise DatasetBuildError("partition boundaries must be strictly increasing")
    by_window: dict[datetime, list[Mapping[str, Any]]] = defaultdict(list)
    for event in events:
        when = _ts(event["@timestamp"])
        if boundaries[0] <= when < boundaries[-1]:
            by_window[when.replace(minute=when.minute // 5 * 5, second=0, microsecond=0)].append(event)
    builder = build_network_vectors if schema == "network-window-v1" else build_endpoint_vectors
    extra: dict[str, Any] = {}
    if schema == "endpoint-window-v1" and process_baseline is not None:
        extra["process_baseline"] = list(process_baseline)

    partitions: dict[str, list[dict[str, Any]]] = {name: [] for name in PARTITIONS}
    members: dict[str, list[dict[str, Any]]] = {name: [] for name in PARTITIONS}
    labels: list[dict[str, Any]] = []
    dropped_attack_from_train = 0
    scenario_partitions: dict[str, set[str]] = defaultdict(set)
    for start in sorted(by_window):
        window_events = by_window[start]
        for vector in builder(
            window_events, window_start=start, window_end=start + WINDOW,
            generator_git_sha=git_sha, **extra,
        ):
            validate_vector(vector)
            name = next(
                partition for partition, (low, high) in zip(PARTITIONS, zip(boundaries, boundaries[1:]))
                if low <= start < high
            )
            scenario = _attack_scenario(vector, scenarios)
            if scenario is not None:
                scenario_partitions[scenario["id"]].add(name)
            if name == "train" and scenario is not None:
                dropped_attack_from_train += 1
                continue
            entity = vector["entity"]
            mine = sorted(
                str(event["event"]["id"])
                for event in window_events
                if _entity_of(event, schema) == entity
            )
            if sha256("\n".join(mine).encode()).hexdigest() != vector["source_event_set_sha256"]:
                raise DatasetBuildError("membership does not reproduce the vector's source-event hash")
            sessions = sorted({
                _session(event, entity, scenarios)
                for event in window_events if _entity_of(event, schema) == entity
            })
            partitions[name].append(vector)
            members[name].append({
                "vector_sha256": canonical_hash(vector),
                "source_event_ids": mine,
                "session_ids": sessions,
            })
            labels.append({
                "schema_version": LABELS_SCHEMA,
                "vector_sha256": canonical_hash(vector),
                "label": 1 if scenario else 0,
                "scenario_id": scenario["id"] if scenario else None,
                "scenario_start": _rfc(scenario["start"]) if scenario else None,
            })
    straddling = sorted(sid for sid, names in scenario_partitions.items() if len(names) > 1)
    if straddling:
        raise DatasetBuildError(
            "scenarios span a partition boundary (session leakage): " + ", ".join(straddling)
        )
    for name in PARTITIONS:
        if not partitions[name]:
            raise DatasetBuildError(f"the {name} partition is empty")
    for name in ("validation", "test"):
        flags = {1 if _attack_scenario(v, scenarios) else 0 for v in partitions[name]}
        if flags != {0, 1}:
            raise DatasetBuildError(f"the {name} partition needs both benign and attack vectors")
    return {
        "partitions": partitions, "members": members, "labels": labels,
        "dropped_attack_from_train": dropped_attack_from_train,
    }


def _jsonl(rows: Iterable[Mapping[str, Any]]) -> bytes:
    return "".join(json.dumps(row, sort_keys=True, allow_nan=False) + "\n" for row in rows).encode()


def write_dataset(
    result: Mapping[str, Any],
    *,
    output_dir: Path,
    dataset_id: str,
    schema: str,
    boundaries: Sequence[datetime],
    git_sha: str,
    sources: Sequence[str],
    events_sha256: str,
    collector_config_sha256: str,
    normalization_schema_sha256: str,
    raw_data_location_class: str,
    created_at: datetime,
    repository_root: Path,
) -> Path:
    output_dir = Path(output_dir)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise DatasetBuildError("output directory must be absent or empty")
    output_dir.mkdir(parents=True, exist_ok=True)
    digests: dict[str, str] = {}
    for name in PARTITIONS:
        path = output_dir / f"{name}.jsonl"
        path.write_bytes(_jsonl(result["partitions"][name]))
        digests[name] = sha256_file(path)
    labels_path = output_dir / "labels.jsonl"
    labels_path.write_bytes(_jsonl(result["labels"]))
    ledger = {
        "schema_version": "partition-membership-v1",
        "partitions": {
            name: {"vectors_sha256": digests[name], "memberships": result["members"][name]}
            for name in PARTITIONS
        },
    }
    ledger_path = output_dir / "session-assignments.json"
    ledger_path.write_text(json.dumps(ledger, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    split: dict[str, Any] = {
        "strategy": "temporal_session_isolated",
        "session_assignment_sha256": sha256_file(ledger_path),
    }
    for name, (low, high) in zip(PARTITIONS, zip(boundaries, boundaries[1:])):
        sessions = sorted({sid for member in result["members"][name] for sid in member["session_ids"]})
        split[name] = {
            "start": _rfc(low), "end": _rfc(high),
            "vector_count": len(result["partitions"][name]),
            "session_ids_sha256": canonical_hash(sessions),
            "label_profile": LABEL_PROFILES[name],
        }
    manifest = {
        "schema_version": "dataset-manifest-v1",
        "dataset_id": dataset_id,
        "created_at": _rfc(created_at),
        "time_range": {"start": _rfc(boundaries[0]), "end": _rfc(boundaries[-1])},
        "sources": list(sources),
        "feature_schema": schema,
        "feature_schema_sha256": feature_schema_sha256(schema, repository_root),
        "sha256": canonical_hash(digests),
        "git_sha": git_sha,
        "raw_data_committed": False,
        "raw_data_location_class": raw_data_location_class,
        "label_source": {
            "method": "scenario_time_window",
            "protocol_version": "soc-labeling-v1",
            "sha256": sha256_file(labels_path),
        },
        "split": split,
        "provenance": {
            "normalization_schema_sha256": normalization_schema_sha256,
            "collector_config_sha256": collector_config_sha256,
            "source_manifest_sha256": events_sha256,
            "feature_engine_git_sha": git_sha,
            "generated_by": "soc-build-dataset-v1",
        },
    }
    path = output_dir / "dataset-manifest.yaml"
    path.write_text(yaml.safe_dump(manifest, sort_keys=True), encoding="utf-8")
    return path


def _collector_digest(root: Path) -> str:
    digest = sha256()
    for path in sorted((root / "soc/logstash/pipelines").glob("*.conf")):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, help="normalized soc-event-v1 JSONL capture")
    parser.add_argument("--scenarios", type=Path, required=True)
    parser.add_argument("--schema", choices=("network-window-v1", "endpoint-window-v1"), required=True)
    parser.add_argument("--dataset-id", required=True)
    parser.add_argument("--start", required=True, help="dataset start (5-minute aligned)")
    parser.add_argument("--train-end", required=True)
    parser.add_argument("--validation-end", required=True)
    parser.add_argument("--test-end", required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--sources", nargs="+", required=True)
    parser.add_argument("--raw-data-location-class", default="local_ignored",
                        choices=("local_ignored", "external_evidence", "approved_object_store"))
    parser.add_argument("--process-baseline", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if not _SHA.fullmatch(args.git_sha):
        raise SystemExit("a valid Git SHA is required")
    boundaries = [_ts(item) for item in (args.start, args.train_end, args.validation_end, args.test_end)]
    events_bytes = args.events.read_bytes()
    events = [json.loads(line) for line in events_bytes.decode().splitlines() if line.strip()]
    baseline = json.loads(args.process_baseline.read_text()) if args.process_baseline else None
    try:
        result = build(
            events=events, scenarios=load_scenarios(args.scenarios), schema=args.schema,
            boundaries=boundaries, git_sha=args.git_sha, process_baseline=baseline,
        )
        manifest = write_dataset(
            result, output_dir=args.output_dir, dataset_id=args.dataset_id, schema=args.schema,
            boundaries=boundaries, git_sha=args.git_sha, sources=args.sources,
            events_sha256=sha256(events_bytes).hexdigest(),
            collector_config_sha256=_collector_digest(root),
            normalization_schema_sha256=sha256_file(root / "schemas/ecs/soc-event.schema.json"),
            raw_data_location_class=args.raw_data_location_class,
            created_at=datetime.now(timezone.utc), repository_root=root,
        )
    except DatasetBuildError as exc:
        raise SystemExit(f"dataset build refused: {exc}") from exc
    print(json.dumps({
        "manifest": str(manifest),
        "vectors": {name: len(result["partitions"][name]) for name in PARTITIONS},
        "attack_vectors_dropped_from_train": result["dropped_attack_from_train"],
    }))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
