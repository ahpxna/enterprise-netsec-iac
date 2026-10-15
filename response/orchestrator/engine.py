"""Fail-closed, reversible response lifecycle orchestrator.

This is the sole component allowed to invoke constrained adapters.  It never
imports an AI model and it does not expose a generic network, firewall, or
shell interface.  Submission and enforcement are deliberately separate so a
signed decision can be audited before any privileged side effect occurs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import ipaddress
from functools import wraps
from threading import RLock
from typing import Any, Mapping, Sequence

from ..adapters.base import AdapterOutcome, ContainmentAdapter
from ..decision import CommandAuthenticator
from ..errors import CommandRejected, CorrelationRejected, PolicyError
from ..policy import PolicyCatalog
from .store import SQLiteResponseStore
from .audit import (
    AppendOnlyAuditLedger,
    AuditEventFactory,
    STATE_APPLIED,
    STATE_EXPIRED,
    STATE_FAILED,
    STATE_REQUESTED,
    STATE_ROLLED_BACK,
    STATE_VERIFIED,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime:
    candidate = value or _utc_now()
    if candidate.tzinfo is None:
        raise CommandRejected("orchestrator timestamps must include a timezone")
    return candidate.astimezone(timezone.utc)


def _rfc3339(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_rfc3339(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise CommandRejected(f"{label} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CommandRejected(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise CommandRejected(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _response_id(idempotency_key: str) -> str:
    return f"resp-{sha256(idempotency_key.encode()).hexdigest()[:24]}"


def _serialized(method):
    @wraps(method)
    def invoke(self, *args, **kwargs):
        with self._mutex:
            if self._storage_failed:
                raise RuntimeError("response persistence failed; close and reopen the store before recovery")
            if self._store is not None:
                with self._store.exclusive():
                    return method(self, *args, **kwargs)
            return method(self, *args, **kwargs)
    return invoke


@dataclass(frozen=True)
class OrchestrationResult:
    """A caller-visible lifecycle result; only VERIFIED means containment proved."""

    response_id: str
    state: str
    accepted: bool
    deduplicated: bool = False
    message: str | None = None
    audit_event: Mapping[str, Any] | None = None


@dataclass
class _ResponseRecord:
    response_id: str
    command: dict[str, Any]
    expires_at: datetime
    state: str
    transition_number: int
    adapter_reference: str | None = None
    authorized: bool = False
    pending_operation: str | None = None
    operation_started_at: str | None = None


class ResponseOrchestrator:
    """Validate, audit, apply, verify, expire, and revert constrained commands."""

    def __init__(
        self,
        *,
        catalog: PolicyCatalog,
        authenticator: CommandAuthenticator,
        ledger: AppendOnlyAuditLedger | None = None,
        adapters: Sequence[ContainmentAdapter],
        store: SQLiteResponseStore | None = None,
    ) -> None:
        by_action = {adapter.action: adapter for adapter in adapters}
        # Each action is bound to a reviewed set of constrained backends; the
        # firewall backend is a deployment choice (Path A nftables, Path B VyOS,
        # production OPNsense) but the action surface is identical.
        permitted_adapter_names = {
            "block_ip": frozenset({"opnsense", "nftables", "vyos"}),
            "isolate_host": frozenset({"wazuh"}),
        }
        if len(by_action) != len(adapters) or set(by_action) != set(permitted_adapter_names):
            raise ValueError("exactly one constrained adapter is required for block_ip and isolate_host")
        if any(by_action[action].name not in names for action, names in permitted_adapter_names.items()):
            raise ValueError("response action is bound to an unexpected privileged adapter")
        self._catalog = catalog
        self._authenticator = authenticator
        if store is None and ledger is None:
            raise ValueError("an audit ledger or persistent response store is required")
        if store is not None and ledger is not None and ledger is not store:
            raise ValueError("persistent state and audit must use the same response store")
        self._store = store
        self._ledger = store if store is not None else ledger
        self._mutex = RLock()
        self._storage_failed = False
        self._adapters = by_action
        self._records: dict[str, _ResponseRecord] = {}
        self._dedup: dict[str, tuple[str, datetime]] = {}
        if store is not None:
            store.claim()
            snapshots = store.load()
            for snapshot in snapshots:
                snapshot["expires_at"] = _parse_rfc3339(snapshot["expires_at"], "checkpoint.expires_at")
                record = _ResponseRecord(**snapshot)
                if record.response_id != _response_id(record.command["idempotency_key"]):
                    raise CommandRejected("checkpoint response identity is invalid")
                history = self._ledger.events(record.response_id)
                self._authenticator.verify(record.command, now=_parse_rfc3339(
                    history[0]["@timestamp"], "checkpoint.accepted_at"))
                for event in history:
                    if (event["target"] != record.command["target"]
                            or event["action"] != record.command["action"]
                            or event["idempotency_key"] != record.command["idempotency_key"]
                            or event["expires_at"] != _rfc3339(record.expires_at)):
                        raise CommandRejected("checkpoint audit differs from signed command")
                self._records[record.response_id] = record

    @_serialized
    def submit(self, command: Mapping[str, Any], *, now: datetime | None = None) -> OrchestrationResult:
        """Accept a signed command into REQUESTED; do not apply it yet."""

        timestamp = _as_utc(now)
        normalized = self._validate_command(command, now=timestamp)
        idempotency_key = normalized["idempotency_key"]
        self._prune_dedup(timestamp)
        duplicate = self._dedup.get(idempotency_key)
        response_id = _response_id(idempotency_key)
        # IDs and audit histories outlive the short dedup cache. Never replace
        # an existing lifecycle when the same evidence is signed again later.
        if duplicate is None and response_id in self._records:
            duplicate = (response_id, timestamp)
        if duplicate is not None:
            response_id, _ = duplicate
            record = self._record(response_id)
            return OrchestrationResult(
                response_id=response_id,
                state=record.state,
                accepted=record.authorized and record.state != STATE_FAILED and record.pending_operation is None,
                deduplicated=True,
                message="duplicate command did not create another privileged action",
                audit_event=self._ledger.latest(response_id),
            )

        expires_at = timestamp + timedelta(seconds=normalized["ttl_seconds"])
        record = _ResponseRecord(
            response_id=response_id,
            command=normalized,
            expires_at=expires_at,
            state=STATE_REQUESTED,
            transition_number=0,
        )
        if self._store is None:
            self._ledger.save_command(response_id, normalized)
        requested = self._transition(record, state=STATE_REQUESTED, timestamp=timestamp)
        self._records[response_id] = record
        self._dedup[idempotency_key] = (
            response_id,
            timestamp + timedelta(seconds=self._catalog.dedup_seconds),
        )

        # Defense in depth: a current local target check is authoritative even
        # when the Decision Engine marked allowlist_checked=true earlier.
        try:
            self._catalog.protections.assert_target_allowed(
                action=normalized["action"],
                target_type=normalized["target"]["type"],
                target_value=normalized["target"]["value"],
            )
        except PolicyError as exc:
            failed = self._fail(record, timestamp=timestamp, code="TARGET_PROTECTED", message=str(exc))
            return OrchestrationResult(
                response_id=response_id,
                state=STATE_FAILED,
                accepted=False,
                message="orchestrator rejected protected target",
                audit_event=failed,
            )

        # Count committed submission attempts, including denied requests.
        if self._ledger.requested_since(
            normalized["policy"]["id"],
            timestamp - timedelta(seconds=self._catalog.rate_limit.window_seconds),
        ) > self._catalog.rate_limit.max_actions:
            failed = self._fail(
                record,
                timestamp=timestamp,
                code="RATE_LIMITED",
                message="automatic response rate limit reached; no adapter was invoked",
            )
            return OrchestrationResult(
                response_id=response_id,
                state=STATE_FAILED,
                accepted=False,
                message="automatic response rate limited",
                audit_event=failed,
            )

        record.authorized = True
        self._checkpoint(record)
        return OrchestrationResult(
            response_id=response_id,
            state=STATE_REQUESTED,
            accepted=True,
            audit_event=requested,
        )

    @_serialized
    def restore_recovery(self) -> tuple[str, ...]:
        """Restore rollback-only records without reapplying any signed command.

        Expired authorization may still authorize reversal of its own action.
        Verify the original signature at acceptance time, not against current
        policy/allowlists which could otherwise strand an old containment.
        Uncertain writes lacking an APPLIED reference remain manual reconciliation.
        """
        if self._records:
            raise CommandRejected("recovery requires a fresh orchestrator")
        restored = {}
        for response_id, command in self._ledger.commands():
            history = self._ledger.events(response_id)
            if not history:
                continue  # Persisted input alone never proves accepted or applied.
            first, latest = history[0], history[-1]
            accepted_at = _parse_rfc3339(first["@timestamp"], "acceptance timestamp")
            self._authenticator.verify(command, now=accepted_at)
            if _response_id(command["idempotency_key"]) != response_id:
                raise CommandRejected("recovery command identity mismatch")
            for event in history:
                if (event["target"] != command["target"] or event["action"] != command["action"]
                        or event["idempotency_key"] != command["idempotency_key"]
                        or event["expires_at"] != first["expires_at"]):
                    raise CommandRejected("recovery audit differs from signed command")
            application = next((event["application"] for event in reversed(history)
                                if event.get("application")), None)
            restored[response_id] = _ResponseRecord(
                response_id=response_id, command=deepcopy(dict(command)),
                expires_at=_parse_rfc3339(first["expires_at"], "containment expiry"),
                state=latest["state"], transition_number=latest["transition_number"],
                adapter_reference=application["adapter_reference"] if application else None,
                authorized=False,
            )
        self._records = restored
        return tuple(restored)

    @_serialized
    def apply(self, response_id: str, *, now: datetime | None = None) -> OrchestrationResult:
        """Invoke the one adapter allowed by the already-audited action type."""

        timestamp = _as_utc(now)
        record = self._record(response_id)
        self._require_state(record, STATE_REQUESTED)
        if not record.authorized:
            raise CommandRejected("response submission did not complete authorization")
        if record.adapter_reference is not None:
            raise CommandRejected("prior adapter application requires audit reconciliation")
        # A queued request may outlive its authorization or containment TTL.
        # Recheck at the privileged side effect, not only at submission.
        if timestamp >= record.expires_at:
            event = self._fail(record, timestamp=timestamp, code="EXPIRED_BEFORE_APPLY",
                               message="containment TTL elapsed before adapter invocation")
            return OrchestrationResult(response_id, STATE_FAILED, False, audit_event=event)
        try:
            self._validate_command(record.command, now=timestamp)
            self._catalog.protections.assert_target_allowed(
                action=record.command["action"], target_type=record.command["target"]["type"],
                target_value=record.command["target"]["value"])
        except (CommandRejected, PolicyError):
            event = self._fail(record, timestamp=timestamp, code="REAUTHORIZATION_FAILED",
                               message="queued command no longer authorized")
            return OrchestrationResult(response_id, STATE_FAILED, False, audit_event=event)
        adapter = self._adapters[record.command["action"]]
        self._assert_target_available(record)
        reference = adapter.recovery_reference(deepcopy(record.command))
        if not isinstance(reference, str) or not reference:
            raise CommandRejected("adapter must provide a stable recovery reference before apply")
        record.adapter_reference = reference
        if self._store is None:
            self._ledger.claim_apply(response_id)
        self._begin_operation(record, operation="apply", timestamp=timestamp)
        outcome = self._invoke(adapter.apply, record.command, error_code="APPLICATION_OUTCOME_UNKNOWN")
        if not outcome.ok or not isinstance(outcome.adapter_reference, str) or not outcome.adapter_reference:
            failed = self._fail_from_outcome(record, timestamp=timestamp, outcome=outcome, fallback="ADAPTER_APPLY_FAILED")
            return OrchestrationResult(
                response_id=response_id,
                state=STATE_FAILED,
                accepted=False,
                message=outcome.message or "adapter apply failed",
                audit_event=failed,
            )
        record.adapter_reference = outcome.adapter_reference
        event = self._transition(
            record,
            state=STATE_APPLIED,
            timestamp=timestamp,
            application={"applied_at": _rfc3339(timestamp), "adapter_reference": outcome.adapter_reference},
            clear_intent=True,
        )
        return OrchestrationResult(
            response_id=response_id,
            state=STATE_APPLIED,
            accepted=True,
            message="action applied; containment is not successful until verification",
            audit_event=event,
        )

    @_serialized
    def verify(self, response_id: str, *, now: datetime | None = None) -> OrchestrationResult:
        """Promote APPLIED to VERIFIED only after adapter evidence is present."""

        timestamp = _as_utc(now)
        record = self._record(response_id)
        self._require_state(record, STATE_APPLIED)
        if record.pending_operation is not None:
            raise CommandRejected("unfinished adapter operation must be recovered before verification")
        if timestamp >= record.expires_at:
            return self._revert(record, timestamp=timestamp, terminal_state=STATE_ROLLED_BACK,
                                cause="ttl_expired")
        assert record.adapter_reference is not None
        adapter = self._adapters[record.command["action"]]
        outcome = self._invoke(adapter.verify, record.command, adapter_reference=record.adapter_reference)
        if outcome.ok and outcome.evidence_refs:
            event = self._transition(
                record,
                state=STATE_VERIFIED,
                timestamp=timestamp,
                application={"applied_at": self._applied_at(record), "adapter_reference": record.adapter_reference},
                verification={
                    "verified": True,
                    "verified_at": _rfc3339(timestamp),
                    "evidence_refs": list(outcome.evidence_refs),
                },
            )
            return OrchestrationResult(
                response_id=response_id,
                state=STATE_VERIFIED,
                accepted=True,
                message="containment verified",
                audit_event=event,
            )

        # A verification failure must not be presented as an applied action.  A
        # best-effort immediate rollback is attempted and the resulting audit
        # record captures both the failure and the reversible outcome.
        self._begin_operation(record, operation="revert", timestamp=timestamp)
        rollback = self._invoke(adapter.revert, record.command, adapter_reference=record.adapter_reference)
        if rollback.ok and rollback.evidence_refs:
            event = self._transition(
                record,
                state=STATE_ROLLED_BACK,
                timestamp=timestamp,
                application={"applied_at": self._applied_at(record), "adapter_reference": record.adapter_reference},
                rollback={
                    "completed_at": _rfc3339(timestamp),
                    "cause": "failed_verification",
                    "evidence_refs": list(rollback.evidence_refs),
                },
                failure=self._failure_payload(
                    timestamp,
                    outcome.code or "VERIFICATION_FAILED",
                    outcome.message or "adapter did not prove containment",
                ),
                clear_intent=True,
            )
            return OrchestrationResult(
                response_id=response_id,
                state=STATE_ROLLED_BACK,
                accepted=False,
                message="verification failed; action rolled back",
                audit_event=event,
            )
        failed = self._fail_from_outcome(
            record,
            timestamp=timestamp,
            outcome=rollback,
            fallback="VERIFY_AND_ROLLBACK_FAILED",
        )
        return OrchestrationResult(
            response_id=response_id,
            state=STATE_FAILED,
            accepted=False,
            message="verification failed and rollback could not be proven",
            audit_event=failed,
        )

    @_serialized
    def expire_due(self, *, now: datetime | None = None) -> tuple[OrchestrationResult, ...]:
        """Revert due actions, including previously failed rollback attempts."""

        timestamp = _as_utc(now)
        results: list[OrchestrationResult] = []
        for record in tuple(self._records.values()):
            recoverable = record.pending_operation is not None or (record.state == STATE_FAILED and record.adapter_reference is not None)
            if ((record.state not in {STATE_APPLIED, STATE_VERIFIED} and not recoverable)
                    or timestamp < record.expires_at):
                continue
            terminal = STATE_EXPIRED if record.state == STATE_VERIFIED else STATE_ROLLED_BACK
            results.append(self._revert(record, timestamp=timestamp, terminal_state=terminal, cause="ttl_expired"))
        return tuple(results)

    @_serialized
    def rollback(self, response_id: str, *, cause: str = "manual", now: datetime | None = None) -> OrchestrationResult:
        """Reverse an applied action, including one with a failed rollback."""

        if cause not in {"manual", "recovery"}:
            raise CommandRejected("manual rollback cause must be manual or recovery")
        timestamp = _as_utc(now)
        record = self._record(response_id)
        recoverable = record.pending_operation is not None or (record.state == STATE_FAILED and record.adapter_reference is not None)
        if record.state not in {STATE_APPLIED, STATE_VERIFIED} and not recoverable:
            raise CommandRejected(f"response {response_id} cannot be rolled back from {record.state}")
        return self._revert(record, timestamp=timestamp, terminal_state=STATE_ROLLED_BACK, cause=cause)

    @_serialized
    def recover_pending(self, *, now: datetime | None = None) -> tuple[OrchestrationResult, ...]:
        """Compensate unfinished operations; never replay an uncertain apply.

        Call on startup and after transient adapter failures. Recovery removes
        only this operation's ownership, even if the original authorization
        has expired or the active policy changed.
        """
        timestamp = _as_utc(now)
        return tuple(self._revert(record, timestamp=timestamp, terminal_state=STATE_ROLLED_BACK,
                                  cause="recovery") for record in tuple(self._records.values())
                     if record.pending_operation is not None)

    @_serialized
    def pending_apply(self) -> tuple[str, ...]:
        """Authorized REQUESTED responses that have not touched an adapter yet."""

        return tuple(
            record.response_id for record in self._records.values()
            if record.state == STATE_REQUESTED and record.authorized
            and record.adapter_reference is None and record.pending_operation is None
        )

    @_serialized
    def awaiting_verification(self) -> tuple[str, ...]:
        """APPLIED responses with no unfinished adapter operation."""

        return tuple(
            record.response_id for record in self._records.values()
            if record.state == STATE_APPLIED and record.pending_operation is None
        )

    @_serialized
    def snapshot(self, response_id: str) -> Mapping[str, Any]:
        """Caller-safe view of one response: state, target, action, expiry."""

        record = self._record(response_id)
        return {
            "response_id": record.response_id,
            "state": record.state,
            "action": record.command["action"],
            "target": dict(record.command["target"]),
            "expires_at": _rfc3339(record.expires_at),
            "authorized": record.authorized,
            "pending_operation": record.pending_operation,
        }

    @_serialized
    def audit_history(self, response_id: str) -> tuple[Mapping[str, Any], ...]:
        """Return the immutable state-transition history for the response."""

        self._record(response_id)
        return self._ledger.events(response_id)

    def _revert(
        self,
        record: _ResponseRecord,
        *,
        timestamp: datetime,
        terminal_state: str,
        cause: str,
    ) -> OrchestrationResult:
        assert record.adapter_reference is not None
        adapter = self._adapters[record.command["action"]]
        self._begin_operation(record, operation="revert", timestamp=timestamp)
        outcome = self._invoke(adapter.revert, record.command, adapter_reference=record.adapter_reference)
        if not outcome.ok or not outcome.evidence_refs:
            failed = self._fail_from_outcome(record, timestamp=timestamp, outcome=outcome, fallback="ADAPTER_REVERT_FAILED")
            return OrchestrationResult(
                response_id=record.response_id,
                state=STATE_FAILED,
                accepted=False,
                message=outcome.message or "rollback failed",
                audit_event=failed,
            )
        event = self._transition(
            record,
            state=terminal_state,
            timestamp=timestamp,
            application=self._application(record),
            rollback={
                "completed_at": _rfc3339(timestamp),
                "cause": cause,
                "evidence_refs": list(outcome.evidence_refs),
            },
            clear_intent=True,
        )
        return OrchestrationResult(
            response_id=record.response_id,
            state=terminal_state,
            accepted=True,
            message="action reversed and verified by the adapter",
            audit_event=event,
        )

    def _validate_command(self, command: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
        if not isinstance(command, Mapping):
            raise CommandRejected("response command must be an object")
        required = {
            "schema_version",
            "request_id",
            "decision_event_id",
            "correlation_id",
            "policy",
            "target",
            "action",
            "ttl_seconds",
            "allowlist_checked",
            "rollback_required",
            "idempotency_key",
            "authorization",
        }
        if set(command) != required:
            raise CommandRejected("response command has missing or unsupported fields")
        normalized = deepcopy(dict(command))
        if normalized["schema_version"] != "response-command-v1":
            raise CommandRejected("unsupported response command schema")
        for field in ("request_id", "decision_event_id", "correlation_id", "idempotency_key"):
            if not isinstance(normalized[field], str) or not normalized[field]:
                raise CommandRejected(f"response command {field} must be non-empty")
        if normalized["allowlist_checked"] is not True or normalized["rollback_required"] is not True:
            raise CommandRejected("response command must require allowlist checking and rollback")
        policy_data = normalized["policy"]
        if not isinstance(policy_data, Mapping) or set(policy_data) != {"id", "version", "sha256"}:
            raise CommandRejected("response command policy is malformed")
        try:
            policy = self._catalog.policy(policy_data["id"])
        except (PolicyError, KeyError, TypeError) as exc:
            raise CommandRejected("response command policy is unknown") from exc
        if dict(policy_data) != {"id": policy.id, "version": policy.version, "sha256": policy.sha256}:
            raise CommandRejected("response command policy version or hash does not match active policy")
        if normalized["action"] != policy.action:
            raise CommandRejected("response command action differs from active policy")
        if normalized["ttl_seconds"] != policy.ttl_seconds:
            raise CommandRejected("response command TTL differs from active policy")
        target = normalized["target"]
        if not isinstance(target, Mapping) or set(target) != {"type", "value"}:
            raise CommandRejected("response command target is malformed")
        if (
            not isinstance(target.get("type"), str)
            or target.get("type") not in {"ip", "host"}
            or not isinstance(target.get("value"), str)
            or not target["value"]
            or len(target["value"]) > 255
        ):
            raise CommandRejected("response command target has an unsupported type or value")
        if normalized["action"] == "block_ip" and target["type"] != "ip":
            raise CommandRejected("block_ip command must target an IP address")
        if normalized["action"] == "block_ip":
            try:
                ipaddress.ip_address(target["value"])
            except ValueError as exc:
                raise CommandRejected("block_ip command target is not a valid IP address") from exc
        if normalized["action"] == "isolate_host" and target["type"] != "host":
            raise CommandRejected("isolate_host command must target a host")
        authorization = normalized["authorization"]
        if not isinstance(authorization, Mapping) or set(authorization) != {"issuer", "key_id", "signature", "issued_at", "expires_at"}:
            raise CommandRejected("response command authorization is malformed")
        if authorization.get("issuer") != "decision_engine":
            raise CommandRejected("response command issuer is not trusted")
        issued_at = _parse_rfc3339(authorization.get("issued_at"), "authorization.issued_at")
        expires_at = _parse_rfc3339(authorization.get("expires_at"), "authorization.expires_at")
        if expires_at <= issued_at:
            raise CommandRejected("response command authorization expiry must follow issuance")
        if issued_at > now + timedelta(seconds=60):
            raise CommandRejected("response command authorization is issued too far in the future")
        if expires_at - issued_at > timedelta(seconds=self._catalog.command_valid_for_seconds):
            raise CommandRejected("response command authorization lifetime exceeds active policy")
        try:
            self._authenticator.verify(command, now=now)
        except CorrelationRejected as exc:
            raise CommandRejected(str(exc)) from exc
        return normalized

    def _transition(
        self,
        record: _ResponseRecord,
        *,
        state: str,
        timestamp: datetime,
        application: Mapping[str, Any] | None = None,
        verification: Mapping[str, Any] | None = None,
        rollback: Mapping[str, Any] | None = None,
        failure: Mapping[str, Any] | None = None,
        clear_intent: bool = False,
    ) -> Mapping[str, Any]:
        factory = AuditEventFactory(
            record.command, record.response_id, record.expires_at,
            adapter=self._adapters[record.command["action"]].name,
        )
        event = factory.build(
            state=state,
            previous_state=record.state if record.transition_number else None,
            transition_number=record.transition_number + 1,
            timestamp=timestamp,
            application=application,
            verification=verification,
            rollback=rollback,
            failure=failure,
            action_intent={
                "operation": record.pending_operation,
                "started_at": record.operation_started_at,
                "adapter_reference": record.adapter_reference,
            } if record.pending_operation else None,
        )
        updated = replace(record, state=state, transition_number=record.transition_number + 1)
        if clear_intent:
            updated.pending_operation = None
            updated.operation_started_at = None
        if self._store is not None:
            self._checkpoint(updated, event=event)
        else:
            self._ledger.append(event)
        record.state = state
        record.transition_number += 1
        record.pending_operation = updated.pending_operation
        record.operation_started_at = updated.operation_started_at
        return event

    def _checkpoint(self, record: _ResponseRecord, *, event=None) -> None:
        if self._store is None:
            return
        snapshot = asdict(record)
        snapshot["expires_at"] = _rfc3339(record.expires_at)
        try:
            self._store.checkpoint(snapshot, event=event)
        except BaseException:
            # Do not continue on possibly stale RAM after any ambiguous commit.
            self._storage_failed = True
            raise

    def _begin_operation(self, record, *, operation, timestamp):
        record.pending_operation = operation
        record.operation_started_at = _rfc3339(timestamp)
        self._checkpoint(record)

    @staticmethod
    def _invoke(method, command, *, error_code="ADAPTER_OUTCOME_UNKNOWN", **kwargs):
        try:
            outcome = method(deepcopy(command), **kwargs)
        except Exception:
            return AdapterOutcome.failure(code=error_code,
                                          message="adapter outcome is unknown; recovery is required")
        if (not isinstance(outcome, AdapterOutcome) or type(outcome.ok) is not bool
                or not isinstance(outcome.evidence_refs, tuple)
                or any(not isinstance(ref, str) or not ref for ref in outcome.evidence_refs)):
            return AdapterOutcome.failure(code="ADAPTER_INVALID_OUTCOME",
                                          message="adapter returned no valid outcome; recovery is required")
        return outcome

    def _assert_target_available(self, record):
        def identity(command):
            target = command["target"]
            value = str(ipaddress.ip_address(target["value"])) if target["type"] == "ip" else target["value"].strip().lower()
            return command["action"], value
        for other in self._records.values():
            if other.response_id == record.response_id:
                continue
            unresolved = other.pending_operation is not None or (
                other.state == STATE_FAILED and other.adapter_reference is not None)
            if (unresolved or other.state in {STATE_APPLIED, STATE_VERIFIED}) and identity(other.command) == identity(record.command):
                raise CommandRejected("target has an active or unresolved containment operation")

    def _application(self, record):
        for event in reversed(self._ledger.events(record.response_id)):
            if isinstance(event.get("application"), Mapping):
                return dict(event["application"])
        # An uncertain apply must not invent evidence that application occurred.
        return None

    def _fail(
        self,
        record: _ResponseRecord,
        *,
        timestamp: datetime,
        code: str,
        message: str,
    ) -> Mapping[str, Any]:
        return self._transition(
            record,
            state=STATE_FAILED,
            timestamp=timestamp,
            failure=self._failure_payload(timestamp, code, message),
        )

    def _fail_from_outcome(
        self,
        record: _ResponseRecord,
        *,
        timestamp: datetime,
        outcome: AdapterOutcome,
        fallback: str,
    ) -> Mapping[str, Any]:
        return self._fail(
            record,
            timestamp=timestamp,
            code=outcome.code or fallback,
            message=outcome.message or "constrained adapter failed without a message",
        )

    @staticmethod
    def _failure_payload(timestamp: datetime, code: str, message: str) -> dict[str, str]:
        return {
            "code": str(code)[:128],
            "message": str(message)[:2048],
            "failed_at": _rfc3339(timestamp),
        }

    @staticmethod
    def _require_state(record: _ResponseRecord, expected: str) -> None:
        if record.state != expected:
            raise CommandRejected(f"response {record.response_id} is {record.state}, expected {expected}")

    def _record(self, response_id: str) -> _ResponseRecord:
        try:
            return self._records[response_id]
        except KeyError as exc:
            raise CommandRejected(f"unknown response: {response_id}") from exc

    def _prune_dedup(self, now: datetime) -> None:
        self._dedup = {
            key: value for key, value in self._dedup.items() if value[1] > now
        }

    def _applied_at(self, record: _ResponseRecord) -> str:
        for event in reversed(self._ledger.events(record.response_id)):
            application = event.get("application")
            if isinstance(application, Mapping) and isinstance(application.get("applied_at"), str):
                return application["applied_at"]
        raise CommandRejected("response audit history lacks an applied timestamp")
