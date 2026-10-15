"""Deterministic feature extraction from already-normalized SOC events.

This module deliberately has no Elasticsearch client.  A narrowly privileged
feature worker may read normalized indices and pass documents here, but feature
calculation itself remains pure and reproducible from the supplied event set.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import ipaddress
import json
from typing import Any, Iterable, Mapping, Sequence

from .contracts import feature_schema_sha256


class FeatureContractError(ValueError):
    """Raised when telemetry cannot safely form a deterministic feature vector."""


UTC = timezone.utc
FIVE_MINUTES = timedelta(minutes=5)


def _nested(record: Mapping[str, Any], *path: str) -> Any:
    value: Any = record
    for key in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def _as_utc(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise FeatureContractError("timestamps must be RFC3339 strings or datetime instances")
    if parsed.tzinfo is None:
        raise FeatureContractError("timestamps must include an explicit UTC offset")
    return parsed.astimezone(UTC)


def _rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _numeric(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return 0
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise FeatureContractError(f"telemetry byte/count field is not numeric: {value!r}") from exc
    return max(0, parsed)


def _categories(event: Mapping[str, Any]) -> set[str]:
    value = _nested(event, "event", "category")
    if isinstance(value, str):
        return {value}
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return {str(item) for item in value}
    return set()


def _event_id(event: Mapping[str, Any]) -> str:
    value = _nested(event, "event", "id")
    if not isinstance(value, str) or not value:
        raise FeatureContractError("normalized event is missing event.id")
    return value


def _event_timestamp(event: Mapping[str, Any]) -> datetime:
    value = event.get("@timestamp")
    if not isinstance(value, str):
        raise FeatureContractError(f"event {_event_id(event)} is missing @timestamp")
    return _as_utc(value)


def _canonical_event(event: Mapping[str, Any]) -> str:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), default=str)


def _validate_and_select(
    events: Iterable[Mapping[str, Any]],
    window_start: datetime,
    window_end: datetime,
) -> list[Mapping[str, Any]]:
    """Select a half-open time window and reject contradictory duplicate IDs."""

    selected: dict[str, Mapping[str, Any]] = {}
    fingerprints: dict[str, str] = {}
    for event in events:
        if not isinstance(event, Mapping):
            raise FeatureContractError("feature input must contain JSON objects")
        schema = _nested(event, "cxyz", "schema_version")
        if schema != "soc-event-v1":
            raise FeatureContractError("feature input must be normalized soc-event-v1 telemetry")
        timestamp = _event_timestamp(event)
        if not (window_start <= timestamp < window_end):
            continue
        event_id = _event_id(event)
        fingerprint = _canonical_event(event)
        previous = fingerprints.get(event_id)
        if previous is not None and previous != fingerprint:
            raise FeatureContractError(
                f"event.id {event_id!r} resolves to conflicting normalized telemetry"
            )
        selected[event_id] = event
        fingerprints[event_id] = fingerprint
    return [selected[event_id] for event_id in sorted(selected)]


def _source_event_set_sha256(events: Sequence[Mapping[str, Any]]) -> str:
    event_ids = [_event_id(event) for event in events]
    if not event_ids:
        raise FeatureContractError("cannot create an empty feature vector")
    return sha256("\n".join(sorted(event_ids)).encode("utf-8")).hexdigest()


def _vector_id(
    feature_schema: str,
    entity_type: str,
    entity: str,
    window_start: datetime,
    window_end: datetime,
    source_event_set_sha256: str,
) -> str:
    seed = "|".join(
        (
            feature_schema,
            entity_type,
            entity,
            _rfc3339(window_start),
            _rfc3339(window_end),
            source_event_set_sha256,
        )
    )
    return f"{feature_schema}:{sha256(seed.encode('utf-8')).hexdigest()[:40]}"


def _window_bounds(
    window_start: str | datetime,
    window_end: str | datetime,
) -> tuple[datetime, datetime]:
    start = _as_utc(window_start)
    end = _as_utc(window_end)
    if end <= start:
        raise FeatureContractError("window_end must be after window_start")
    if end - start != FIVE_MINUTES:
        raise FeatureContractError("v1 feature contracts permit exactly one five-minute window")
    return start, end


def _dataset(event: Mapping[str, Any]) -> str:
    value = _nested(event, "event", "dataset")
    return value if isinstance(value, str) else ""


def _blocked(event: Mapping[str, Any]) -> bool:
    action = _nested(event, "event", "action")
    if not isinstance(action, str):
        return False
    return action.lower() in {"block", "blocked", "deny", "denied", "drop", "reject"}


def _suricata_type(event: Mapping[str, Any]) -> str:
    value = event.get("event_type")
    return value.lower() if isinstance(value, str) else ""


def _is_connection_record(event: Mapping[str, Any]) -> bool:
    """A record that represents exactly one network connection.

    Firewall log lines and Suricata ``flow`` records are connection records.
    Suricata alert/dns/http/tls records describe the same flow again and device
    syslog is not a connection at all, so counting them would multiply one
    connection by the number of sensors/event types that observed it.
    """

    dataset = _dataset(event)
    if dataset == "firewall.syslog":
        return True
    return dataset == "suricata.eve" and _suricata_type(event) == "flow"


def _event_bytes(event: Mapping[str, Any]) -> tuple[int, int]:
    """Return source-to-destination and destination-to-source bytes.

    Only a Suricata ``flow`` record carries the *final* per-direction counters
    for a flow.  Alert/dns/http records embed running counters of the same flow,
    so using them would double count.  A firewall record only supplies the
    logged packet length; the logged initiator is the source side, so it is
    assigned to bytes_out deterministically rather than guessed.
    """

    if _dataset(event) == "suricata.eve":
        if _suricata_type(event) != "flow":
            return 0, 0
        return (
            _numeric(_nested(event, "flow", "bytes_toserver")),
            _numeric(_nested(event, "flow", "bytes_toclient")),
        )
    return _numeric(_nested(event, "network", "bytes")), 0


def _domain(event: Mapping[str, Any]) -> str | None:
    for path in (("dns", "question", "name"), ("dns", "rrname"), ("dns", "query")):
        value = _nested(event, *path)
        if isinstance(value, str) and value:
            return value.lower().rstrip(".")
    return None


def _is_dns_query(event: Mapping[str, Any]) -> bool:
    if _dataset(event) != "suricata.eve" or _suricata_type(event) != "dns":
        return False
    kind = _nested(event, "dns", "type")
    return kind is None or (isinstance(kind, str) and kind.lower() in {"query", "request"})


def _network_features(events: Sequence[Mapping[str, Any]]) -> dict[str, int | float]:
    connections = [event for event in events if _is_connection_record(event)]
    destinations = {
        value
        for event in connections
        if isinstance((value := _nested(event, "destination", "ip")), str) and value
    }
    ports = {
        int(value)
        for event in connections
        if isinstance((value := _nested(event, "destination", "port")), (int, float, str))
        and str(value).isdigit()
    }
    dns_queries = [event for event in events if _is_dns_query(event)]
    domains = {domain for event in dns_queries if (domain := _domain(event))}
    bytes_out = 0
    bytes_in = 0
    for event in connections:
        outbound, inbound = _event_bytes(event)
        bytes_out += outbound
        bytes_in += inbound
    denominator = len(connections)
    return {
        "connection_count": denominator,
        "unique_dst_ip": len(destinations),
        "unique_dst_port": len(ports),
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "blocked_ratio": (sum(1 for event in connections if _blocked(event)) / denominator)
        if denominator
        else 0.0,
        "dns_query_count": len(dns_queries),
        "unique_domain_count": len(domains),
        "tls_count": sum(
            1 for event in events if _dataset(event) == "suricata.eve" and _suricata_type(event) == "tls"
        ),
        "suricata_alert_count": sum(
            1
            for event in events
            if _dataset(event) == "suricata.eve"
            and (_suricata_type(event) == "alert" or isinstance(event.get("alert"), Mapping))
        ),
        "failed_auth_count": sum(
            1
            for event in events
            if "authentication" in _categories(event)
            and str(_nested(event, "event", "outcome")).lower() == "failure"
        ),
    }


def build_network_vectors(
    events: Iterable[Mapping[str, Any]],
    *,
    window_start: str | datetime,
    window_end: str | datetime,
    generator_git_sha: str,
    generated_at: str | datetime | None = None,
) -> list[dict[str, Any]]:
    """Build one exact ``network-window-v1`` vector per source IP.

    ``generated_at`` defaults to the deterministic window end, so repeated
    execution over the same immutable event set yields byte-equivalent vectors.
    """

    start, end = _window_bounds(window_start, window_end)
    selected = _validate_and_select(events, start, end)
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for event in selected:
        entity = _nested(event, "source", "ip")
        if isinstance(entity, str) and entity:
            try:
                ipaddress.ip_address(entity)
            except ValueError as exc:
                raise FeatureContractError(f"source.ip is not an IP address: {entity!r}") from exc
            grouped[entity].append(event)
    emitted_at = _as_utc(generated_at) if generated_at is not None else end
    schema = "network-window-v1"
    schema_hash = feature_schema_sha256(schema)
    vectors: list[dict[str, Any]] = []
    for entity in sorted(grouped, key=lambda value: (ipaddress.ip_address(value).version, value)):
        entity_events = grouped[entity]
        event_hash = _source_event_set_sha256(entity_events)
        vectors.append(
            {
                "schema_version": schema,
                "feature_schema": schema,
                "feature_schema_sha256": schema_hash,
                "vector_id": _vector_id(schema, "src_ip", entity, start, end, event_hash),
                "entity_type": "src_ip",
                "entity": entity,
                "window_start": _rfc3339(start),
                "window_end": _rfc3339(end),
                "window_duration": "5m",
                "source_event_count": len(entity_events),
                "source_event_set_sha256": event_hash,
                "generator_git_sha": generator_git_sha,
                "generated_at": _rfc3339(emitted_at),
                "features": _network_features(entity_events),
            }
        )
    return vectors


def _event_action_text(event: Mapping[str, Any]) -> str:
    values = [
        _nested(event, "event", "action"),
        _nested(event, "process", "name"),
        _nested(event, "process", "command_line"),
        _nested(event, "rule", "description"),
    ]
    return " ".join(str(value).lower() for value in values if value is not None)


def _endpoint_features(
    events: Sequence[Mapping[str, Any]],
    *,
    rare_processes: set[str],
    process_baseline: set[str] | None = None,
) -> dict[str, int]:
    process_events = [event for event in events if "process" in _categories(event)]
    powershell = 0
    rare = 0
    for event in process_events:
        process_name = _nested(event, "process", "name")
        normalized_name = process_name.lower() if isinstance(process_name, str) else ""
        action_text = _event_action_text(event)
        if normalized_name and (
            normalized_name in rare_processes
            or (process_baseline is not None and normalized_name not in process_baseline)
        ):
            rare += 1
        if "powershell" in action_text or "pwsh" in action_text:
            powershell += 1
    return {
        "process_count": len(process_events),
        "rare_process_count": rare,
        "powershell_count": powershell,
        "failed_login_count": sum(
            1
            for event in events
            if "authentication" in _categories(event)
            and str(_nested(event, "event", "outcome")).lower() == "failure"
        ),
        "fim_change_count": sum(1 for event in events if "file" in _categories(event)),
        "account_change_count": sum(
            1
            for event in events
            if any(token in _event_action_text(event) for token in ("account", "useradd", "usermod", "userdel"))
        ),
        "privilege_change_count": sum(
            1
            for event in events
            if any(token in _event_action_text(event) for token in ("privilege", "sudo", "setuid", "capability"))
        ),
    }


def build_endpoint_vectors(
    events: Iterable[Mapping[str, Any]],
    *,
    window_start: str | datetime,
    window_end: str | datetime,
    generator_git_sha: str,
    rare_processes: Iterable[str] = (),
    process_baseline: Iterable[str] | None = None,
    generated_at: str | datetime | None = None,
) -> list[dict[str, Any]]:
    """Build one exact ``endpoint-window-v1`` vector per endpoint host.

    ``rare_processes`` names processes that are rare by definition;
    ``process_baseline`` is the set of processes seen in a benign baseline, so
    any other name counts as rare.  Both are inputs, not hidden state, which
    keeps the vector reproducible from the event set plus these two sets.
    """

    start, end = _window_bounds(window_start, window_end)
    selected = _validate_and_select(events, start, end)
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for event in selected:
        host = _nested(event, "host", "name")
        if isinstance(host, str) and host:
            grouped[host].append(event)
    emitted_at = _as_utc(generated_at) if generated_at is not None else end
    schema = "endpoint-window-v1"
    schema_hash = feature_schema_sha256(schema)
    known_rare_processes = {process.lower() for process in rare_processes if process}
    baseline = (
        {process.lower() for process in process_baseline if process}
        if process_baseline is not None
        else None
    )
    vectors: list[dict[str, Any]] = []
    for entity in sorted(grouped):
        entity_events = grouped[entity]
        event_hash = _source_event_set_sha256(entity_events)
        vectors.append(
            {
                "schema_version": schema,
                "feature_schema": schema,
                "feature_schema_sha256": schema_hash,
                "vector_id": _vector_id(schema, "host", entity, start, end, event_hash),
                "entity_type": "host",
                "entity": entity,
                "window_start": _rfc3339(start),
                "window_end": _rfc3339(end),
                "window_duration": "5m",
                "source_event_count": len(entity_events),
                "source_event_set_sha256": event_hash,
                "generator_git_sha": generator_git_sha,
                "generated_at": _rfc3339(emitted_at),
                "features": _endpoint_features(
                    entity_events, rare_processes=known_rare_processes, process_baseline=baseline
                ),
            }
        )
    return vectors
