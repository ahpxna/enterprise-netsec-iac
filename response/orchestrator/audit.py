"""Append-only response lifecycle audit primitives.

The in-memory ledger is intentionally only a source-level reference.  A real
deployment must supply an append-only persistent implementation before it can
claim response evidence.  The transition validation here is shared semantics,
not a replacement for durable storage.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Mapping, Protocol

from ..errors import CommandRejected


STATE_REQUESTED = "REQUESTED"
STATE_APPLIED = "APPLIED"
STATE_VERIFIED = "VERIFIED"
STATE_EXPIRED = "EXPIRED"
STATE_ROLLED_BACK = "ROLLED_BACK"
STATE_FAILED = "FAILED"

# FAILED can still require recovery when an earlier action was applied.
TERMINAL_STATES = frozenset({STATE_EXPIRED, STATE_ROLLED_BACK})
_ALLOWED = {
    None: {STATE_REQUESTED},
    STATE_REQUESTED: {STATE_APPLIED, STATE_FAILED, STATE_ROLLED_BACK},
    STATE_APPLIED: {STATE_VERIFIED, STATE_ROLLED_BACK, STATE_FAILED},
    STATE_VERIFIED: {STATE_EXPIRED, STATE_ROLLED_BACK, STATE_FAILED},
    STATE_FAILED: {STATE_FAILED, STATE_ROLLED_BACK},
}


def _rfc3339(value: datetime) -> str:
    if value.tzinfo is None:
        raise CommandRejected("audit timestamps must include a timezone")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _event_id(response_id: str, transition_number: int, state: str) -> str:
    material = f"{response_id}:{transition_number}:{state}".encode()
    return f"audit-{sha256(material).hexdigest()[:24]}"


class AppendOnlyAuditLedger(Protocol):
    """Persistence contract required by the orchestrator.

    Implementations must reject mutation/deletion of prior events and retain
    them in the audit stream.  They must not coalesce transitions into a single
    mutable response document.
    """

    def append(self, event: Mapping[str, Any]) -> None:
        """Persist exactly one immutable state transition."""

    def latest(self, response_id: str) -> Mapping[str, Any] | None:
        """Return the current event without exposing mutable internal state."""

    def events(self, response_id: str) -> tuple[Mapping[str, Any], ...]:
        """Return the immutable transition history in order."""

    def claim_apply(self, response_id: str) -> None:
        """Record intent before side effects; reject a second attempt forever."""

    def requested_since(self, policy_id: str, since: datetime) -> int:
        """Count durable submission attempts, including denied requests."""

    def save_command(self, response_id: str, command: Mapping[str, Any]) -> None:
        """Persist immutable signed recovery input before its first transition."""

    def commands(self) -> tuple[tuple[str, Mapping[str, Any]], ...]:
        """Read signed recovery inputs without exposing mutable storage."""


def validate_transition(payload: Mapping[str, Any], history) -> None:
    """Shared lifecycle checks for memory and transactional persistent stores."""
    response_id = payload.get("response_id")
    state = payload.get("state")
    previous_state = payload.get("previous_state")
    if not isinstance(response_id, str) or not response_id:
        raise CommandRejected("audit event lacks response_id")
    if not isinstance(state, str) or state not in {STATE_REQUESTED, STATE_APPLIED, STATE_VERIFIED, STATE_EXPIRED, STATE_ROLLED_BACK, STATE_FAILED}:
        raise CommandRejected("audit event uses an unsupported state")
    actual_previous = history[-1]["state"] if history else None
    if previous_state != actual_previous:
        raise CommandRejected("audit event previous_state does not match append-only history")
    if state not in _ALLOWED.get(actual_previous, set()):
        raise CommandRejected(f"invalid response transition {actual_previous!r} -> {state!r}")
    if actual_previous == STATE_FAILED or (actual_previous == STATE_REQUESTED and state == STATE_ROLLED_BACK):
        has_application = any(item["state"] == STATE_APPLIED for item in history)
        has_intent = isinstance(payload.get("action_intent"), Mapping)
        if not has_application and not has_intent:
            raise CommandRejected("recovery requires an application or recorded action intent")
    if payload.get("transition_number") != len(history) + 1:
        raise CommandRejected("audit event transition_number is not monotonic")


class InMemoryAuditLedger:
    """Strict reference ledger for local wiring, never a production evidence store."""

    def __init__(self) -> None:
        self._by_response: dict[str, list[dict[str, Any]]] = {}

        self._apply_intents: set[str] = set()
        self._commands: dict[str, dict[str, Any]] = {}

    def save_command(self, response_id: str, command: Mapping[str, Any]) -> None:
        payload = deepcopy(dict(command))
        if response_id in self._commands and self._commands[response_id] != payload:
            raise CommandRejected("recovery command is immutable")
        self._commands[response_id] = payload

    def commands(self) -> tuple[tuple[str, Mapping[str, Any]], ...]:
        return tuple((key, deepcopy(value)) for key, value in self._commands.items())


    def claim_apply(self, response_id: str) -> None:
        if response_id in self._apply_intents:
            raise CommandRejected("application already attempted; reconciliation required")
        latest = self.latest(response_id)
        if latest is None or latest["state"] != STATE_REQUESTED:
            raise CommandRejected("application intent requires REQUESTED audit state")
        self._apply_intents.add(response_id)

    def requested_since(self, policy_id: str, since: datetime) -> int:
        return sum(1 for history in self._by_response.values() for event in history
                   if event["state"] == STATE_REQUESTED and event.get("policy_id") == policy_id
                   and datetime.fromisoformat(event["@timestamp"].replace("Z", "+00:00")) > since)

    def append(self, event: Mapping[str, Any]) -> None:
        payload = deepcopy(dict(event))
        response_id = payload.get("response_id")
        if not isinstance(response_id, str) or not response_id:
            raise CommandRejected("audit event lacks response_id")
        history = self._by_response.get(response_id, [])
        validate_transition(payload, history)
        history.append(payload)
        self._by_response[response_id] = history

    def latest(self, response_id: str) -> Mapping[str, Any] | None:
        history = self._by_response.get(response_id)
        return deepcopy(history[-1]) if history else None

    def events(self, response_id: str) -> tuple[Mapping[str, Any], ...]:
        return tuple(deepcopy(item) for item in self._by_response.get(response_id, ()))


@dataclass(frozen=True)
class AuditEventFactory:
    """Build schema-compatible, standalone response audit events."""

    command: Mapping[str, Any]
    response_id: str
    expires_at: datetime
    adapter: str | None = None

    def build(
        self,
        *,
        state: str,
        previous_state: str | None,
        transition_number: int,
        timestamp: datetime,
        application: Mapping[str, Any] | None = None,
        verification: Mapping[str, Any] | None = None,
        rollback: Mapping[str, Any] | None = None,
        failure: Mapping[str, Any] | None = None,
        action_intent: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        action = self.command["action"]
        adapter = self.adapter or ("opnsense" if action == "block_ip" else "wazuh")
        audit_event_id = _event_id(self.response_id, transition_number, state)
        event: dict[str, Any] = {
            "@timestamp": _rfc3339(timestamp),
            "schema_version": "response-audit-event-v1",
            "event": {
                "id": audit_event_id,
                "kind": "event",
                "category": ["response"],
                "dataset": "soc.response.audit",
            },
            "audit_event_id": audit_event_id,
            "response_id": self.response_id,
            "transition_number": transition_number,
            "decision_event_id": self.command["decision_event_id"],
            "correlation_id": self.command["correlation_id"],
            "policy_id": self.command["policy"]["id"],
            "idempotency_key": self.command["idempotency_key"],
            "target": deepcopy(self.command["target"]),
            "action": action,
            "adapter": adapter,
            "state": state,
            "previous_state": previous_state,
            "ttl_seconds": self.command["ttl_seconds"],
            "expires_at": _rfc3339(self.expires_at),
            "allowlist_checked": True,
            "rollback_required": True,
        }
        if application is not None:
            event["application"] = deepcopy(dict(application))
        if verification is not None:
            event["verification"] = deepcopy(dict(verification))
        if rollback is not None:
            event["rollback"] = deepcopy(dict(rollback))
        if failure is not None:
            event["failure"] = deepcopy(dict(failure))
        if action_intent is not None:
            event["action_intent"] = deepcopy(dict(action_intent))
        return event
