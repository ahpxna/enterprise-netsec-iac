"""Orchestrator service core: intake, scheduled lifecycle, and audit export.

``ResponseService`` is transport-agnostic so it can be tested without HTTP.  It
never invents a transition: it calls the orchestrator's public operations in the
order the lifecycle defines.

* ``observe`` mode accepts nothing and applies nothing.
* ``enforce`` mode applies each admitted command, verifies it, reverts it at TTL
  expiry, and compensates unfinished operations after a restart.
* Every committed audit event is delivered, at least once and idempotently, to
  ``soc-response-*`` with the event ID as the document ID.
"""

from __future__ import annotations

from datetime import datetime
from threading import RLock
from typing import Any, Callable, Mapping

from soc.workers.common import ElasticClient, parse_rfc3339, utc_now
from soc.workers.https import DeliveryError

from ..errors import CommandRejected
from ..orchestrator.engine import OrchestrationResult, ResponseOrchestrator
from ..orchestrator.store import SQLiteResponseStore


class AuditExporter:
    def __init__(self, store: SQLiteResponseStore, elastic: ElasticClient) -> None:
        self._store, self._elastic = store, elastic

    def export(self, limit: int = 200) -> dict[str, Any]:
        delivered = 0
        for audit_id, event in self._store.unexported_events(limit):
            index = "soc-response-" + parse_rfc3339(event["@timestamp"]).strftime("%Y.%m.%d")
            try:
                self._elastic.create(index, event["audit_event_id"], event)
            except DeliveryError as exc:
                return {"delivered": delivered, "blocked": exc.code}
            self._store.mark_exported(audit_id)
            delivered += 1
        return {"delivered": delivered, "blocked": None}


def _summary(result: OrchestrationResult) -> dict[str, Any]:
    return {
        "response_id": result.response_id, "state": result.state, "accepted": result.accepted,
        "deduplicated": result.deduplicated, "message": result.message,
    }


class ResponseService:
    def __init__(
        self,
        *,
        orchestrator: ResponseOrchestrator,
        exporter: AuditExporter | None,
        mode: str,
        clock: Callable[[], datetime] = utc_now,
        recover_every: int = 6,
    ) -> None:
        if mode not in {"observe", "enforce"}:
            raise ValueError("mode must be observe or enforce")
        self._orchestrator, self._exporter = orchestrator, exporter
        self.mode, self._clock = mode, clock
        self._recover_every, self._ticks = max(1, int(recover_every)), 0
        self._lock = RLock()
        self.started = False
        self.counters: dict[str, int] = {"accepted": 0, "rejected": 0, "applied": 0, "verified": 0,
                                         "reverted": 0, "failed": 0, "recovered": 0}
        self.last_export: dict[str, Any] = {"delivered": 0, "blocked": None}

    def start(self) -> None:
        """Compensate unfinished operations before any new work is accepted."""

        with self._lock:
            recovered = self._orchestrator.recover_pending(now=self._clock())
            self.counters["recovered"] += len(recovered)
            self.started = True

    def accept(self, command: Mapping[str, Any]) -> dict[str, Any]:
        if self.mode != "enforce":
            self.counters["rejected"] += 1
            return {"accepted": False, "state": None, "message": "service is in observe mode; no command accepted"}
        if not self.started:
            raise RuntimeError("service has not completed startup recovery")
        with self._lock:
            try:
                result = self._orchestrator.submit(command, now=self._clock())
            except CommandRejected as exc:
                self.counters["rejected"] += 1
                return {"accepted": False, "state": None, "message": str(exc)}
            self.counters["accepted" if result.accepted else "rejected"] += 1
            return _summary(result)

    def status(self, response_id: str) -> Mapping[str, Any]:
        return self._orchestrator.snapshot(response_id)

    def tick(self) -> dict[str, Any]:
        """One scheduler pass: apply, verify, expire, recover, export."""

        report: dict[str, Any] = {"applied": 0, "verified": 0, "reverted": 0, "failed": 0}
        with self._lock:
            now = self._clock()
            if self.mode == "enforce":
                for response_id in self._orchestrator.pending_apply():
                    outcome = self._orchestrator.apply(response_id, now=now)
                    report["applied" if outcome.state == "APPLIED" else "failed"] += 1
                for response_id in self._orchestrator.awaiting_verification():
                    outcome = self._orchestrator.verify(response_id, now=now)
                    key = {"VERIFIED": "verified", "ROLLED_BACK": "reverted"}.get(outcome.state, "failed")
                    report[key] += 1
                for outcome in self._orchestrator.expire_due(now=now):
                    report["reverted" if outcome.accepted else "failed"] += 1
                self._ticks += 1
                if self._ticks % self._recover_every == 0:  # back off while a peer is down
                    for outcome in self._orchestrator.recover_pending(now=now):
                        report["reverted" if outcome.accepted else "failed"] += 1
            for key, value in report.items():
                self.counters[key] += value
        if self._exporter is not None:
            try:
                self.last_export = self._exporter.export()
            except Exception:  # audit export must never stop containment lifecycle work
                self.last_export = {"delivered": 0, "blocked": "EXPORT_ERROR"}
        report["export"] = self.last_export
        return report

    def metrics(self) -> str:
        lines = []
        for name, value in sorted(self.counters.items()):
            lines += [f"# TYPE cxyz_soc_response_{name}_total counter", f"cxyz_soc_response_{name}_total {value}"]
        blocked = 1 if self.last_export.get("blocked") else 0
        lines += ["# TYPE cxyz_soc_response_audit_export_blocked gauge",
                  f"cxyz_soc_response_audit_export_blocked {blocked}", ""]
        return "\n".join(lines)
