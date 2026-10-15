"""Continuous feature worker: normalized events -> closed five-minute vectors.

Run with ``python -m soc.workers.features``.  The worker holds only the
``cxyz_feature_engine_role`` identity: it reads normalized telemetry and creates
documents in ``soc-features-*``.  Feature calculation itself stays in the pure
``ai.features.engine`` module, so a vector can always be reproduced offline
from the same event set.

Windows are aligned to wall-clock five-minute boundaries and processed only
after a configurable lag so late log shipping does not change a window that was
already emitted.  Vector IDs hash the exact source event set, therefore a
retry is idempotent (HTTP 409 means "already delivered").  A window whose event
count exceeds the safety cap is recorded as ``oversized`` and surfaced in
``status``; it is never silently truncated.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Iterable, Sequence

from ai.features.contracts import validate_vector
from ai.features.engine import FeatureContractError, build_endpoint_vectors, build_network_vectors

from .common import (
    ElasticClient,
    ScanLimitExceeded,
    elastic_from_environment,
    open_private_sqlite,
    parse_rfc3339,
    rfc3339,
    single_owner,
    utc_now,
)
from .https import DeliveryError

WINDOW = timedelta(minutes=5)

NETWORK_INDICES = "soc-network-*,soc-alerts-*,soc-auth-*"
ENDPOINT_INDICES = "soc-endpoint-*"
NETWORK_DATASETS = ("suricata.eve", "firewall.syslog", "freeradius.auth")
EVENT_FIELDS = (
    "@timestamp",
    "event.id",
    "event.dataset",
    "event.category",
    "event.action",
    "event.outcome",
    "event.severity",
    "event_type",
    "source.ip",
    "destination.ip",
    "destination.port",
    "network.bytes",
    "network.protocol",
    "network.transport",
    "flow.bytes_toserver",
    "flow.bytes_toclient",
    "dns.type",
    "dns.rrname",
    "dns.question.name",
    "alert.severity",
    "alert.signature_id",
    "host.name",
    "process.name",
    "process.command_line",
    "rule.description",
    "cxyz.schema_version",
)
_GIT_SHA = re.compile(r"^[a-fA-F0-9]{7,64}$")


def floor_window(moment: datetime) -> datetime:
    moment = moment.astimezone(timezone.utc)
    return moment.replace(minute=moment.minute // 5 * 5, second=0, microsecond=0)


def closed_windows(
    *, now: datetime, lag: timedelta, since: datetime, max_windows: int
) -> list[datetime]:
    """Window starts whose end is at least ``lag`` in the past, oldest first."""

    latest_end = floor_window(now - lag)
    start = floor_window(since)
    windows: list[datetime] = []
    while start + WINDOW <= latest_end and len(windows) < max_windows:
        windows.append(start)
        start += WINDOW
    return windows


class FeatureState:
    """Durable per-window outcome ledger (private SQLite)."""

    def __init__(self, path: Path) -> None:
        self.db = open_private_sqlite(path)
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS windows (
                schema TEXT NOT NULL, window_start TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('done','empty','oversized','failed')),
                events INTEGER NOT NULL DEFAULT 0, vectors INTEGER NOT NULL DEFAULT 0,
                error TEXT, updated_at TEXT NOT NULL,
                PRIMARY KEY(schema, window_start)
            );
            """
        )

    def record(
        self, schema: str, start: datetime, status: str, *, events: int = 0, vectors: int = 0,
        error: str | None = None,
    ) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO windows(schema,window_start,status,events,vectors,error,updated_at)"
                " VALUES(?,?,?,?,?,?,?) ON CONFLICT(schema,window_start) DO UPDATE SET"
                " status=excluded.status,events=excluded.events,vectors=excluded.vectors,"
                " error=excluded.error,updated_at=excluded.updated_at",
                (schema, rfc3339(start), status, events, vectors, error, rfc3339(utc_now())),
            )

    def last_done(self, schema: str) -> datetime | None:
        row = self.db.execute(
            "SELECT MAX(window_start) AS value FROM windows WHERE schema=? AND status!='failed'",
            (schema,),
        ).fetchone()
        return parse_rfc3339(row["value"]) if row and row["value"] else None

    def pending(self, schema: str, candidates: Sequence[datetime]) -> list[datetime]:
        done = {
            row["window_start"]
            for row in self.db.execute(
                "SELECT window_start FROM windows WHERE schema=? AND status!='failed'", (schema,)
            )
        }
        return [item for item in candidates if rfc3339(item) not in done]

    def status(self) -> dict[str, Any]:
        counts: dict[str, dict[str, int]] = {}
        for row in self.db.execute(
            "SELECT schema,status,COUNT(*) AS n FROM windows GROUP BY schema,status"
        ):
            counts.setdefault(row["schema"], {})[row["status"]] = row["n"]
        return counts

    def close(self) -> None:
        self.db.close()


def _query(start: datetime, end: datetime, schema: str) -> dict[str, Any]:
    window = {"range": {"@timestamp": {"gte": rfc3339(start), "lt": rfc3339(end)}}}
    if schema == "network-window-v1":
        return {
            "bool": {
                "filter": [
                    window,
                    {"terms": {"event.dataset": list(NETWORK_DATASETS)}},
                    {"exists": {"field": "source.ip"}},
                ]
            }
        }
    return {"bool": {"filter": [window, {"exists": {"field": "host.name"}}]}}


def fetch_window_events(
    elastic: ElasticClient, schema: str, start: datetime, *, max_events: int, page_size: int = 2000
) -> list[dict[str, Any]]:
    index = NETWORK_INDICES if schema == "network-window-v1" else ENDPOINT_INDICES
    events: list[dict[str, Any]] = []
    for hit in elastic.scan(
        index,
        _query(start, start + WINDOW, schema),
        [{"@timestamp": "asc"}, {"cxyz.ingestion_id": "asc"}],
        source=EVENT_FIELDS,
        page_size=page_size,
        limit=max_events,
    ):
        source = hit.get("_source")
        if isinstance(source, dict):
            events.append(_expand(source))
    return events


def _expand(source: dict[str, Any]) -> dict[str, Any]:
    """Elasticsearch returns dotted ``_source`` keys unchanged when they were indexed
    nested; flatten-safe expansion keeps the engine's nested accessors working."""

    expanded: dict[str, Any] = {}
    for key, value in source.items():
        if "." in key:
            node = expanded
            *parents, leaf = key.split(".")
            for part in parents:
                node = node.setdefault(part, {})
            node[leaf] = value
        else:
            existing = expanded.get(key)
            if isinstance(existing, dict) and isinstance(value, dict):
                existing.update(value)
            else:
                expanded[key] = value
    return expanded


def load_process_baseline(path: Path | None) -> list[str] | None:
    if path is None:
        return None
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
        raise ValueError("process baseline must be a JSON list of process names")
    return payload


def process_window(
    elastic: ElasticClient,
    state: FeatureState,
    schema: str,
    start: datetime,
    *,
    git_sha: str,
    max_events: int,
    process_baseline: Iterable[str] | None = None,
) -> str:
    """Build and deliver all vectors for one closed window; return the outcome."""

    try:
        events = fetch_window_events(elastic, schema, start, max_events=max_events)
    except ScanLimitExceeded as exc:
        state.record(schema, start, "oversized", events=exc.limit, error=str(exc))
        return "oversized"
    if not events:
        state.record(schema, start, "empty")
        return "empty"
    builder = build_network_vectors if schema == "network-window-v1" else build_endpoint_vectors
    kwargs: dict[str, Any] = {}
    if schema == "endpoint-window-v1" and process_baseline is not None:
        kwargs["process_baseline"] = list(process_baseline)
    try:
        vectors = builder(
            events,
            window_start=start,
            window_end=start + WINDOW,
            generator_git_sha=git_sha,
            **kwargs,
        )
        for vector in vectors:
            validate_vector(vector)
    except Exception as exc:  # contract violations are permanent and must stay visible
        state.record(schema, start, "failed", events=len(events), error=type(exc).__name__ + ": " + str(exc)[:500])
        return "failed"
    index = "soc-features-" + (start + WINDOW).strftime("%Y.%m.%d")
    try:
        for vector in vectors:
            elastic.create(index, vector["vector_id"], vector)
    except DeliveryError as exc:
        state.record(schema, start, "failed", events=len(events), error=exc.code)
        return "failed"
    state.record(schema, start, "done", events=len(events), vectors=len(vectors))
    return "done"


def run_once(
    elastic: ElasticClient,
    state: FeatureState,
    *,
    schemas: Sequence[str],
    git_sha: str,
    now: datetime,
    lag: timedelta,
    lookback: timedelta,
    max_windows: int,
    max_events: int,
    process_baseline: Iterable[str] | None = None,
) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    baseline = list(process_baseline) if process_baseline is not None else None
    for schema in schemas:
        last = state.last_done(schema)
        since = last + WINDOW if last else floor_window(now - lookback)
        candidates = closed_windows(now=now, lag=lag, since=since, max_windows=max_windows)
        # Retry failed windows first, then advance.
        failed = [
            parse_rfc3339(row["window_start"])
            for row in state.db.execute(
                "SELECT window_start FROM windows WHERE schema=? AND status='failed' ORDER BY window_start",
                (schema,),
            )
        ][: max(1, max_windows // 4)]
        outcomes: dict[str, int] = {}
        for start in dict.fromkeys([*failed, *state.pending(schema, candidates)]):
            outcome = process_window(
                elastic, state, schema, start, git_sha=git_sha, max_events=max_events,
                process_baseline=baseline,
            )
            outcomes[outcome] = outcomes.get(outcome, 0) + 1
        summary[schema] = outcomes
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path("soc/runtime/features/state.sqlite"))
    parser.add_argument(
        "--schema", action="append", choices=("network-window-v1", "endpoint-window-v1"),
        help="repeatable; default is both schemas",
    )
    parser.add_argument("--git-sha", default=os.environ.get("SOC_GIT_SHA", ""))
    parser.add_argument("--lag-seconds", type=int, default=180)
    parser.add_argument("--lookback-minutes", type=int, default=60)
    parser.add_argument("--max-windows", type=int, default=24)
    parser.add_argument("--max-events", type=int, default=200000)
    parser.add_argument("--process-baseline", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    run = commands.add_parser("run")
    run.add_argument("--loop", action="store_true")
    run.add_argument("--interval", type=int, default=60)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    os.umask(0o077)
    state_path = args.state
    with single_owner(state_path):
        state = FeatureState(state_path)
        try:
            if args.command == "status":
                print(json.dumps(state.status(), sort_keys=True))
                return 0
            if not _GIT_SHA.fullmatch(args.git_sha or ""):
                raise SystemExit("a valid generator Git SHA is required (--git-sha or SOC_GIT_SHA)")
            for name, low, high in (
                ("--lag-seconds", 30, 3600), ("--lookback-minutes", 5, 10080),
                ("--max-windows", 1, 2016), ("--max-events", 1000, 5000000),
            ):
                value = getattr(args, name[2:].replace("-", "_"))
                if not low <= value <= high:
                    raise SystemExit(f"{name} must be between {low} and {high}")
            elastic = elastic_from_environment()
            schemas = args.schema or ["network-window-v1", "endpoint-window-v1"]
            baseline = load_process_baseline(args.process_baseline)
            exit_code = 0
            while True:
                summary = run_once(
                    elastic, state, schemas=schemas, git_sha=args.git_sha, now=utc_now(),
                    lag=timedelta(seconds=args.lag_seconds),
                    lookback=timedelta(minutes=args.lookback_minutes),
                    max_windows=args.max_windows, max_events=args.max_events,
                    process_baseline=baseline,
                )
                print(json.dumps({"run": summary}, sort_keys=True), flush=True)
                if any(o.get("failed") or o.get("oversized") for o in summary.values()):
                    exit_code = 2
                if not args.loop:
                    return exit_code
                time.sleep(args.interval)
        finally:
            state.close()


if __name__ == "__main__":
    raise SystemExit(main())
