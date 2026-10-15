"""Decision runner: scored anomalies + independent corroboration -> signed commands.

Reads ``soc-ai-*`` anomalies and the independent telemetry already stored by
Logstash, asks the pure :class:`~response.decision.DecisionEngine` for a verdict,
appends the verdict to ``soc-response-*`` and, only in ``enforce`` mode, delivers
the signed command to the orchestrator.  The runner holds the decision signing
key and an Elasticsearch identity limited to reading telemetry and creating
response documents; it holds no firewall or Wazuh credential.

``observe`` mode (the default) records what the engine *would* have requested as
an analyst alert and sends nothing, which is the safe way to measure false
positives before automatic containment is enabled.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from soc.workers.common import ElasticClient, open_private_sqlite, parse_rfc3339, rfc3339, utc_now
from soc.workers.https import DeliveryError

from ..decision import DecisionEngine, DecisionResult
from ..errors import CorrelationRejected, PolicyError

WINDOW = timedelta(minutes=5)
SIGNAL_SLACK = timedelta(minutes=5)
MAX_SIGNALS_PER_TYPE = 3
POLICY_BY_TARGET = {"ip": "COR-001", "host": "COR-002"}


def _alert_severity(alert_severity: Any) -> int:
    """Suricata 1 = high ... 3 = low; policies use "higher is worse"."""

    return max(0, 4 - int(alert_severity))


def _digest(parts: Iterable[str]) -> str:
    return sha256("\n".join(sorted(parts)).encode()).hexdigest()[:24]


class DecisionState:
    """Durable cursor and per-anomaly outcome ledger (private SQLite)."""

    def __init__(self, path: Path) -> None:
        self.db = open_private_sqlite(path)
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS decisions (
                anomaly_event_id TEXT PRIMARY KEY, outcome TEXT NOT NULL,
                decision_event_id TEXT, detail TEXT, updated_at TEXT NOT NULL
            );
            """
        )

    def cursor(self) -> list | None:
        row = self.db.execute("SELECT value FROM meta WHERE key='cursor'").fetchone()
        return json.loads(row["value"]) if row else None

    def set_cursor(self, value: list) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO meta(key,value) VALUES('cursor',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (json.dumps(value),),
            )

    def record(self, anomaly_id: str, outcome: str, decision_event_id: str | None = None, detail: str = "") -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO decisions(anomaly_event_id,outcome,decision_event_id,detail,updated_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(anomaly_event_id) DO UPDATE SET outcome=excluded.outcome,"
                "decision_event_id=excluded.decision_event_id,detail=excluded.detail,updated_at=excluded.updated_at",
                (anomaly_id, outcome, decision_event_id, detail[:500], rfc3339(utc_now())),
            )

    def counts(self) -> dict[str, int]:
        return {
            row["outcome"]: row["n"]
            for row in self.db.execute("SELECT outcome, COUNT(*) AS n FROM decisions GROUP BY outcome")
        }

    def close(self) -> None:
        self.db.close()


class DecisionRunner:
    def __init__(
        self,
        *,
        elastic: ElasticClient,
        engine: DecisionEngine,
        state: DecisionState,
        mode: str,
        send_command: Callable[[Mapping[str, Any]], None] | None,
        min_score: float = 0.90,
        protected_assets: Iterable[str] = (),
        threat_intel: Iterable[str] = (),
        policy_by_target: Mapping[str, str] = POLICY_BY_TARGET,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if mode not in {"observe", "enforce"}:
            raise ValueError("mode must be observe or enforce")
        if mode == "enforce" and send_command is None:
            raise ValueError("enforce mode needs an orchestrator sender")
        self._elastic, self._engine, self._state = elastic, engine, state
        self._mode, self._send = mode, send_command
        self._min_score = float(min_score)
        self._assets = frozenset(protected_assets)
        self._intel = frozenset(threat_intel)
        self._policies = dict(policy_by_target)
        self._clock = clock
        self._intel_hash = _digest(self._intel) if self._intel else ""

    # ---------------------------------------------------------------- evidence
    def _alerts(self, dataset: str, field: str, value: str, start: datetime, end: datetime) -> list[dict]:
        hits = self._elastic.search("soc-alerts-*", {
            "size": 50, "sort": [{"@timestamp": "asc"}],
            "query": {"bool": {"filter": [
                {"term": {"event.dataset": dataset}}, {"term": {field: value}},
                {"range": {"@timestamp": {"gte": rfc3339(start), "lt": rfc3339(end)}}},
            ]}},
            "_source": ["@timestamp", "event.id", "event.severity", "alert.severity", "host.name", "source.ip"],
        })
        return [hit["_source"] for hit in hits if isinstance(hit.get("_source"), dict)]

    @staticmethod
    def _dig(document: Mapping[str, Any], dotted: str) -> Any:
        value: Any = document
        for part in dotted.split("."):
            if not isinstance(value, Mapping) or part not in value:
                return None
            value = value[part]
        return value

    def _signals(self, target: Mapping[str, str], window_start: datetime, window_end: datetime) -> list[dict]:
        start, end = window_start - SIGNAL_SLACK, window_end + SIGNAL_SLACK
        entity = target["value"]
        signals: list[dict] = []

        def signal(kind: str, reference: str, observed: str, **extra: Any) -> None:
            signals.append({"type": kind, "reference": reference, "observed_at": observed,
                            "target": deepcopy(dict(target)), **extra})

        if target["type"] == "ip":
            suricata = self._alerts("suricata.eve", "source.ip", entity, start, end)
            ranked = sorted(
                (a for a in suricata if self._dig(a, "alert.severity") is not None),
                key=lambda a: int(self._dig(a, "alert.severity")),
            )
            for alert in ranked[:MAX_SIGNALS_PER_TYPE]:
                signal("suricata", str(self._dig(alert, "event.id")), str(alert["@timestamp"]),
                       severity=_alert_severity(self._dig(alert, "alert.severity")))
            wazuh = self._alerts("wazuh.alerts", "source.ip", entity, start, end)
            auth_index, auth_filter = "soc-auth-*", [{"term": {"source.ip": entity}}]
            # A honeypot has no legitimate users: any interaction from this source is hostile by construction.
            # All of it collapses into ONE signal (worst severity, event count) so a chatty attacker cannot
            # look like several independent observations.
            honeypot = self._alerts("cowrie.honeypot", "source.ip", entity, start, end)
            if honeypot:
                ids = [str(self._dig(hit, "event.id")) for hit in honeypot]
                worst = max(int(self._dig(hit, "event.severity") or 0) for hit in honeypot)
                latest = max(str(hit["@timestamp"]) for hit in honeypot)
                signal("honeypot", "honeypot:" + _digest(ids), latest, severity=worst, count=len(ids))
        else:
            wazuh = self._alerts("wazuh.alerts", "host.name", entity, start, end)
            auth_index = "soc-endpoint-*"
            auth_filter = [{"term": {"host.name": entity}}, {"term": {"event.category": "authentication"}}]
        for alert in sorted(wazuh, key=lambda a: -int(self._dig(a, "event.severity") or 0))[:MAX_SIGNALS_PER_TYPE]:
            if self._dig(alert, "event.severity") is None:
                continue
            signal("wazuh", str(self._dig(alert, "event.id")), str(alert["@timestamp"]),
                   severity=int(self._dig(alert, "event.severity")))

        failures = self._elastic.search(auth_index, {
            "size": 500, "sort": [{"@timestamp": "asc"}],
            "query": {"bool": {"filter": [
                *auth_filter, {"term": {"event.outcome": "failure"}},
                {"range": {"@timestamp": {"gte": rfc3339(start), "lt": rfc3339(end)}}},
            ]}},
            "_source": ["@timestamp", "event.id"],
        })
        if failures:
            ids = [str(self._dig(hit["_source"], "event.id")) for hit in failures]
            latest = max(str(hit["_source"]["@timestamp"]) for hit in failures)
            signal("authentication", "auth-failures:" + _digest(ids), latest, count=len(ids))

        if entity in self._intel:
            signal("threat_intel", f"intel:{self._intel_hash[:12]}:{entity}", rfc3339(window_end))

        if target["type"] == "ip" and self._assets:
            flows = self._elastic.search("soc-network-*", {
                "size": 50, "sort": [{"@timestamp": "asc"}],
                "query": {"bool": {"filter": [
                    {"term": {"source.ip": entity}}, {"terms": {"destination.ip": sorted(self._assets)}},
                    {"range": {"@timestamp": {"gte": rfc3339(window_start), "lt": rfc3339(window_end)}}},
                ]}},
                "_source": ["destination.ip", "@timestamp"],
            })
            if flows:
                asset = str(self._dig(flows[0]["_source"], "destination.ip"))
                signal("protected_asset", f"asset:{asset}:{rfc3339(window_end)}", rfc3339(window_end))
        return signals

    # ----------------------------------------------------------------- decide
    @staticmethod
    def _target(feature_vector: Mapping[str, Any]) -> dict[str, str] | None:
        kind = {"src_ip": "ip", "host": "host"}.get(str(feature_vector.get("entity_type")))
        entity = feature_vector.get("entity")
        return {"type": kind, "value": str(entity)} if kind and isinstance(entity, str) and entity else None

    def _observe_event(self, event: dict) -> dict:
        """Downgrade a would-be request to an analyst alert; nothing may act on it."""

        event = deepcopy(event)
        decision = event["decision"]
        decision.update(outcome="alert", action="none", automatic_response_eligible=False,
                        reason="observe mode: eligible for automatic response, which is disabled")
        decision.pop("response_request_id", None)
        return event

    def _write_decision(self, event: Mapping[str, Any]) -> None:
        when = parse_rfc3339(event["@timestamp"])
        self._elastic.create("soc-response-" + when.strftime("%Y.%m.%d"), event["event"]["id"], event)

    def handle(self, anomaly_doc: Mapping[str, Any]) -> bool:
        """Process one anomaly document; ``False`` means "retry later" (nothing is skipped)."""

        anomaly_id = str(self._dig(anomaly_doc, "event.id"))
        vector = anomaly_doc.get("feature_vector") or {}
        ai = anomaly_doc.get("ai") or {}
        target = self._target(vector)
        if target is None:
            self._state.record(anomaly_id, "unsupported_entity")
            return True
        policy_id = self._policies.get(target["type"])
        if policy_id is None:
            self._state.record(anomaly_id, "no_policy")
            return True
        window_start = parse_rfc3339(vector["window_start"])
        window_end = parse_rfc3339(vector["window_end"])
        anomaly = {
            "event_id": anomaly_id, "model_id": ai.get("model_id"), "score": ai.get("score"),
            "threshold": ai.get("threshold"), "is_anomaly": ai.get("is_anomaly"),
            "observed_at": rfc3339(window_end), "target": deepcopy(target),
        }
        try:
            signals = self._signals(target, window_start, window_end)
            result: DecisionResult = self._engine.evaluate(
                policy_id=policy_id, anomaly=anomaly, independent_signals=signals,
                target=target, now=self._clock(),
            )
        except DeliveryError as exc:
            return not exc.retryable and self._record_and_continue(anomaly_id, "evidence_error", exc.code)
        except (CorrelationRejected, PolicyError) as exc:
            self._state.record(anomaly_id, "rejected", detail=str(exc))
            return True
        if result.decision_event is None:
            self._state.record(anomaly_id, "anomaly_only", detail=result.reason)
            return True
        event = result.decision_event
        try:
            if result.eligible and self._mode == "enforce":
                self._write_decision(event)
                self._send(result.command)  # type: ignore[misc,arg-type]
                self._state.record(anomaly_id, "response_requested", event["event"]["id"])
            else:
                if result.eligible:
                    event = self._observe_event(event)
                self._write_decision(event)
                self._state.record(anomaly_id, event["decision"]["outcome"], event["event"]["id"], result.reason)
        except DeliveryError as exc:
            if exc.retryable:
                return False
            self._state.record(anomaly_id, "delivery_failed", detail=exc.code)
        return True

    def _record_and_continue(self, anomaly_id: str, outcome: str, detail: str) -> bool:
        self._state.record(anomaly_id, outcome, detail=detail)
        return True

    def run_once(self, *, limit: int = 200) -> dict[str, int]:
        cursor = self._state.cursor()
        processed = retried = 0
        hits = self._elastic.search("soc-ai-*", {
            "size": limit,
            "sort": [{"@timestamp": "asc"}, {"event.id": "asc"}],
            "query": {"bool": {"filter": [
                {"term": {"ai.is_anomaly": True}}, {"range": {"ai.score": {"gte": self._min_score}}},
            ]}},
            **({"search_after": cursor} if cursor else {}),
        })
        for hit in hits:
            if not self.handle(hit["_source"]):
                retried += 1
                break  # preserve order: nothing after a retryable failure is skipped
            processed += 1
            self._state.set_cursor(hit["sort"])
        return {"processed": processed, "retry_pending": retried}
