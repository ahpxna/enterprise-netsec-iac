"""Correlation-gated decision engine for SOC containment requests.

The only way this module produces a response command is when a model anomaly
and a separately observed corroborating signal satisfy a versioned policy.
It contains no adapter imports, network calls, firewall credentials, or shell
execution capabilities.
"""

from __future__ import annotations

from base64 import urlsafe_b64encode
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import hmac
import ipaddress
import math
import re
from typing import Any, Mapping, Protocol, Sequence

from .errors import CorrelationRejected, PolicyError
from .policy import PolicyCatalog, ResponsePolicy, canonical_json, sha256_hex


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime:
    candidate = value or _utc_now()
    if candidate.tzinfo is None:
        raise CorrelationRejected("timestamps must include a timezone")
    return candidate.astimezone(timezone.utc)


def _rfc3339(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _finite_number(value: object, label: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CorrelationRejected(f"{label} must be a finite number")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise CorrelationRejected(f"{label} must be a finite number")
    return value


def _identifier(prefix: str, material: Mapping[str, Any]) -> str:
    return f"{prefix}-{sha256(canonical_json(material)).hexdigest()[:24]}"


def _signature_payload(command: Mapping[str, Any]) -> bytes:
    """Sign every command field except the signature value itself."""

    authorization = command.get("authorization")
    if not isinstance(authorization, Mapping):
        raise CorrelationRejected("response command is missing authorization")
    unsigned_authorization = dict(authorization)
    unsigned_authorization.pop("signature", None)
    payload = dict(command)
    payload["authorization"] = unsigned_authorization
    return canonical_json(payload)


def _parse_rfc3339(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise CorrelationRejected(f"{label} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CorrelationRejected(f"{label} is not a valid timestamp") from exc
    if parsed.tzinfo is None:
        raise CorrelationRejected(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


class CommandAuthenticator(Protocol):
    """Decision-to-orchestrator signing boundary.

    Production deployments should provide a rotated asymmetric implementation
    backed by an approved key service.  The standard-library HMAC reference
    implementation below exists for isolated lab wiring only.
    """

    def sign(self, command: Mapping[str, Any]) -> str:
        """Return a signature over an unsigned response command."""

    def verify(self, command: Mapping[str, Any], *, now: datetime | None = None) -> None:
        """Raise on an invalid, untrusted, or expired command."""


class HmacCommandAuthenticator:
    """Injected-key HMAC authenticator for local integration only.

    No key is read from source code or an environment variable here.  Callers
    must inject key material from a secret mechanism and should replace this
    reference authenticator with an asymmetric verifier before production use.
    """

    def __init__(self, *, keys: Mapping[str, bytes], signing_key_id: str) -> None:
        if not keys or signing_key_id not in keys:
            raise ValueError("a non-empty key ring and known signing key are required")
        if any(not isinstance(key, bytes) or len(key) < 32 for key in keys.values()):
            raise ValueError("command-authentication keys must be at least 32 bytes")
        self._keys = dict(keys)
        self.signing_key_id = signing_key_id

    def sign(self, command: Mapping[str, Any]) -> str:
        digest = hmac.new(self._keys[self.signing_key_id], _signature_payload(command), sha256).digest()
        return urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def verify(self, command: Mapping[str, Any], *, now: datetime | None = None) -> None:
        authorization = command.get("authorization")
        if not isinstance(authorization, Mapping):
            raise CorrelationRejected("response command has no authorization")
        key_id = authorization.get("key_id")
        signature = authorization.get("signature")
        if not isinstance(key_id, str) or key_id not in self._keys:
            raise CorrelationRejected("response command uses an unknown authorization key")
        if not isinstance(signature, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", signature):
            raise CorrelationRejected("response command has an invalid authorization signature")
        expected = urlsafe_b64encode(
            hmac.new(self._keys[key_id], _signature_payload(command), sha256).digest()
        ).decode("ascii").rstrip("=")
        if not hmac.compare_digest(signature, expected):
            raise CorrelationRejected("response command signature verification failed")
        issued_at = _parse_rfc3339(authorization.get("issued_at"), "authorization.issued_at")
        expires_at = _parse_rfc3339(authorization.get("expires_at"), "authorization.expires_at")
        current = _as_utc(now)
        if expires_at <= issued_at or current >= expires_at:
            raise CorrelationRejected("response command authorization is expired")


@dataclass(frozen=True)
class DecisionResult:
    """A policy result that callers can persist as a correlation decision."""

    eligible: bool
    reason: str
    decision_event: Mapping[str, Any] | None = None
    action_request: Mapping[str, Any] | None = None
    command: Mapping[str, Any] | None = None


class DecisionEngine:
    """Evaluate anomaly plus corroboration without privileged side effects."""

    def __init__(
        self,
        catalog: PolicyCatalog,
        authenticator: CommandAuthenticator,
        *,
        signing_key_id: str | None = None,
    ) -> None:
        self._catalog = catalog
        self._authenticator = authenticator
        key_id = signing_key_id or getattr(authenticator, "signing_key_id", None)
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("a signing_key_id is required for the response command authorization")
        self._signing_key_id = key_id

    def evaluate(
        self,
        *,
        policy_id: str,
        anomaly: Mapping[str, Any],
        independent_signals: Sequence[Mapping[str, Any]],
        target: Mapping[str, Any],
        now: datetime | None = None,
        correlation_id: str | None = None,
    ) -> DecisionResult:
        """Return a command only for a high-confidence, hybrid decision.

        ``independent_signals`` must never contain an ``ai`` item.  The model
        anomaly is represented exactly once by the engine itself, so callers
        cannot make one model output appear to be two independent signals.
        """

        policy = self._catalog.policy(policy_id)
        timestamp = _as_utc(now)
        anomaly_data = self._validate_anomaly(anomaly)
        target_data = self._validate_target(target)
        signal_data = self._validate_independent_signals(independent_signals)
        if anomaly_data["target"] != target_data:
            raise CorrelationRejected("anomaly target differs from the requested response target")
        for signal in signal_data:
            if signal["target"] != target_data:
                raise CorrelationRejected("corroborating signal target differs from the response target")
            if signal["reference"] == anomaly_data["event_id"]:
                raise CorrelationRejected("AI output cannot corroborate itself under another signal type")

        # The AI event already exists in soc-ai-*.  Without a second observed
        # signal there is no correlation record to create and, critically, no
        # action request that could enter the privileged response plane.
        if not signal_data:
            return DecisionResult(
                eligible=False,
                reason="anomaly-only evidence is alert-only and cannot request containment",
            )

        decision_material = {
            "policy_id": policy.id,
            "policy_sha256": policy.sha256,
            "anomaly_event_id": anomaly_data["event_id"],
            "target": target_data,
            "signals": signal_data,
        }
        decision_event_id = _identifier("dec", decision_material)
        correlation = _identifier("cor", decision_material) if correlation_id is None else correlation_id
        if not isinstance(correlation, str) or not correlation.strip() or len(correlation.strip()) > 256:
            raise CorrelationRejected("correlation_id must be a non-empty string up to 256 characters")
        correlation = correlation.strip()

        rejection = self._rejection_reason(policy, anomaly_data, signal_data, target_data, now=timestamp)
        if rejection is not None:
            outcome = "denied" if rejection.startswith("target protection") else (
                "alert" if anomaly_data["is_anomaly"] else "store_only"
            )
            return DecisionResult(
                eligible=False,
                reason=rejection,
                decision_event=self._decision_event(
                    policy=policy,
                    anomaly=anomaly_data,
                    signals=signal_data,
                    target=target_data,
                    decision_event_id=decision_event_id,
                    correlation_id=correlation,
                    timestamp=timestamp,
                    outcome=outcome,
                    action="none",
                    automatic_response_eligible=False,
                    response_request_id=None,
                    reason=rejection,
                ),
            )

        request_material = {
            "decision_event_id": decision_event_id,
            # Correlation is a tracing label, not a new containment identity.
            "policy_sha256": policy.sha256,
            "target": target_data,
            "anomaly_event_id": anomaly_data["event_id"],
            "signals": signal_data,
        }
        request_id = _identifier("req", request_material)
        idempotency_key = f"idemp-{sha256_hex(request_material)}"
        signals = [
            {"type": "ai", "reference": anomaly_data["event_id"]},
            *[{"type": item["type"], "reference": item["reference"]} for item in signal_data],
        ]
        action_request = {
            "schema_version": "response-request-v1",
            "correlation_id": correlation,
            "decision_event_id": decision_event_id,
            "policy_id": policy.id,
            "policy_sha256": policy.sha256,
            "idempotency_key": idempotency_key,
            "issued_by": "decision_engine",
            "entity": {"type": target_data["type"], "id": target_data["value"]},
            "action": policy.action,
            "reason": "hybrid correlation: anomaly plus independent corroboration",
            "ai_score": anomaly_data["score"],
            "model_id": anomaly_data["model_id"],
            "signals": signals,
            "ttl_seconds": policy.ttl_seconds,
            "allowlist_checked": True,
            "rollback_required": True,
            "requested_at": _rfc3339(timestamp),
        }
        authorization = {
            "issuer": "decision_engine",
            "key_id": self._signing_key_id,
            "issued_at": _rfc3339(timestamp),
            "expires_at": _rfc3339(timestamp + timedelta(seconds=self._catalog.command_valid_for_seconds)),
        }
        command = {
            "schema_version": "response-command-v1",
            "request_id": request_id,
            "decision_event_id": decision_event_id,
            "correlation_id": correlation,
            "policy": {"id": policy.id, "version": policy.version, "sha256": policy.sha256},
            "target": target_data,
            "action": policy.action,
            "ttl_seconds": policy.ttl_seconds,
            "allowlist_checked": True,
            "rollback_required": True,
            "idempotency_key": idempotency_key,
            "authorization": authorization,
        }
        signed = dict(command)
        signed["authorization"] = {**authorization, "signature": self._authenticator.sign(command)}
        return DecisionResult(
            eligible=True,
            reason="hybrid policy conditions satisfied",
            decision_event=self._decision_event(
                policy=policy,
                anomaly=anomaly_data,
                signals=signal_data,
                target=target_data,
                decision_event_id=decision_event_id,
                correlation_id=correlation,
                timestamp=timestamp,
                outcome="response_requested",
                action=policy.action,
                automatic_response_eligible=True,
                response_request_id=request_id,
                reason="hybrid policy conditions satisfied",
            ),
            action_request=action_request,
            command=signed,
        )

    def _rejection_reason(
        self,
        policy: ResponsePolicy,
        anomaly: Mapping[str, Any],
        signals: Sequence[Mapping[str, Any]],
        target: Mapping[str, Any],
        *,
        now: datetime,
    ) -> str | None:
        oldest = now - timedelta(seconds=self._catalog.evidence_max_age_seconds)
        latest = now + timedelta(seconds=60)
        for evidence in (anomaly, *signals):
            observed = _parse_rfc3339(evidence["observed_at"], "evidence.observed_at")
            if observed < oldest:
                return "evidence is older than the active correlation freshness limit"
            if observed > latest:
                return "evidence timestamp exceeds the allowed future clock skew"
        if anomaly["is_anomaly"] is not True:
            return "AI event is not marked anomalous"
        if anomaly["score"] < policy.min_ai_score:
            return f"AI score below policy threshold {policy.min_ai_score:.2f}"
        if not any(requirement.matches(signal) for requirement in policy.require_any for signal in signals):
            return "no independent corroborating signal satisfied the policy"
        try:
            self._catalog.protections.assert_target_allowed(
                action=policy.action,
                target_type=target["type"],
                target_value=target["value"],
            )
        except PolicyError as exc:
            return f"target protection rejected the response: {exc}"
        return None

    @staticmethod
    def _validate_anomaly(value: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise CorrelationRejected("anomaly must be an object")
        event_id = value.get("event_id")
        model_id = value.get("model_id")
        score = value.get("score")
        threshold = value.get("threshold")
        is_anomaly = value.get("is_anomaly")
        observed_at = value.get("observed_at")
        if not isinstance(event_id, str) or not event_id:
            raise CorrelationRejected("anomaly.event_id is required")
        if not isinstance(model_id, str) or not model_id:
            raise CorrelationRejected("anomaly.model_id is required")
        score = _finite_number(score, "anomaly.score")
        if not 0 <= score <= 1:
            raise CorrelationRejected("anomaly.score must be between 0 and 1")
        threshold = _finite_number(threshold, "anomaly.threshold")
        if not 0 <= threshold <= 1:
            raise CorrelationRejected("anomaly.threshold must be between 0 and 1")
        if not isinstance(is_anomaly, bool):
            raise CorrelationRejected("anomaly.is_anomaly must be boolean")
        if is_anomaly != (score >= threshold):
            raise CorrelationRejected("anomaly flag disagrees with score and model threshold")
        observed_at = _rfc3339(_parse_rfc3339(observed_at, "anomaly.observed_at"))
        return {
            "event_id": event_id,
            "model_id": model_id,
            "score": float(score),
            "threshold": float(threshold),
            "is_anomaly": is_anomaly,
            "observed_at": observed_at,
            "target": DecisionEngine._validate_target(value.get("target")),
        }

    @staticmethod
    def _validate_target(value: Mapping[str, Any]) -> dict[str, str]:
        if not isinstance(value, Mapping):
            raise CorrelationRejected("target must be an object")
        if set(value) != {"type", "value"}:
            raise CorrelationRejected("target must contain only type and value")
        target_type = value.get("type")
        target_value = value.get("value")
        if (
            not isinstance(target_type, str)
            or target_type not in {"ip", "host"}
            or not isinstance(target_value, str)
            or not target_value.strip()
            or len(target_value.strip()) > 255
        ):
            raise CorrelationRejected("target must contain a supported type and non-empty value")
        normalized_value = target_value.strip()
        if target_type == "ip":
            try:
                normalized_value = str(ipaddress.ip_address(normalized_value))
            except ValueError as exc:
                raise CorrelationRejected("IP target must be a valid IPv4 or IPv6 address") from exc
        else:
            normalized_value = normalized_value.lower()
        return {"type": target_type, "value": normalized_value}

    @staticmethod
    def _validate_independent_signals(value: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], ...]:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            raise CorrelationRejected("independent_signals must be a list")
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        for index, signal in enumerate(value):
            if not isinstance(signal, Mapping):
                raise CorrelationRejected(f"independent_signals[{index}] must be an object")
            allowed = {"type", "reference", "severity", "count", "observed_at", "confidence", "target"}
            unknown = set(signal) - allowed
            if unknown:
                raise CorrelationRejected(f"independent_signals[{index}] has unsupported fields: {sorted(unknown)}")
            signal_type = signal.get("type")
            reference = signal.get("reference")
            if signal_type == "ai":
                raise CorrelationRejected("AI output cannot corroborate itself")
            if not isinstance(signal_type, str) or signal_type not in {
                "suricata", "wazuh", "authentication", "threat_intel", "protected_asset", "honeypot"
            }:
                raise CorrelationRejected(f"independent_signals[{index}] has an unsupported type")
            if not isinstance(reference, str) or not reference.strip():
                raise CorrelationRejected(f"independent_signals[{index}].reference is required")
            observed_at = signal.get("observed_at")
            observed_at = _rfc3339(_parse_rfc3339(observed_at, f"independent_signals[{index}].observed_at"))
            identity = reference.strip()
            if identity in seen:
                raise CorrelationRejected("duplicate corroborating signal")
            seen.add(identity)
            item: dict[str, Any] = {
                "type": signal_type,
                "reference": reference.strip(),
                "observed_at": observed_at,
                "target": DecisionEngine._validate_target(signal.get("target")),
            }
            for field in ("severity", "count", "confidence"):
                if field not in signal:
                    continue
                number = _finite_number(signal[field], f"independent_signals[{index}].{field}")
                if number < 0:
                    raise CorrelationRejected(f"independent_signals[{index}].{field} cannot be negative")
                if field == "confidence" and number > 1:
                    raise CorrelationRejected(f"independent_signals[{index}].confidence cannot exceed 1")
                if field in {"severity", "count"}:
                    if number != int(number):
                        raise CorrelationRejected(f"independent_signals[{index}].{field} must be an integer")
                    item[field] = int(number)
                else:
                    item[field] = float(number)
            normalized.append(item)
        return tuple(sorted(normalized, key=lambda item: (item["type"], item["reference"])))

    @staticmethod
    def _decision_event(
        *,
        policy: ResponsePolicy,
        anomaly: Mapping[str, Any],
        signals: Sequence[Mapping[str, Any]],
        target: Mapping[str, Any],
        decision_event_id: str,
        correlation_id: str,
        timestamp: datetime,
        outcome: str,
        action: str,
        automatic_response_eligible: bool,
        response_request_id: str | None,
        reason: str,
    ) -> dict[str, Any]:
        """Emit a standalone correlation record, never an overwritten raw event."""

        return {
            "@timestamp": _rfc3339(timestamp),
            "schema_version": "correlation-decision-event-v1",
            "event": {
                "id": decision_event_id,
                "kind": "event",
                "category": ["correlation"],
                "dataset": "soc.correlation.decision",
            },
            "correlation_id": correlation_id,
            "anomaly": {
                "event_id": anomaly["event_id"],
                "model_id": anomaly["model_id"],
                "score": anomaly["score"],
                "threshold": anomaly["threshold"],
                "is_anomaly": anomaly["is_anomaly"],
            },
            "signals": [
                {
                    "kind": "ai_anomaly",
                    "reference": anomaly["event_id"],
                    "observed_at": anomaly["observed_at"],
                    "confidence": anomaly["score"],
                },
                *[
                    {
                        "kind": {
                            "suricata": "suricata_alert",
                            "wazuh": "wazuh_alert",
                            "authentication": "authentication_failures",
                            "threat_intel": "threat_intel_match",
                            "protected_asset": "protected_asset_context",
                            "honeypot": "honeypot_interaction",
                        }[item["type"]],
                        "reference": item["reference"],
                        "observed_at": item["observed_at"],
                        **({"confidence": item["confidence"]} if "confidence" in item else {}),
                    }
                    for item in signals
                ],
            ],
            "policy": {"id": policy.id, "version": policy.version, "sha256": policy.sha256},
            "target": dict(target),
            "decision": {
                "outcome": outcome,
                "action": action,
                "automatic_response_eligible": automatic_response_eligible,
                **({"response_request_id": response_request_id} if response_request_id else {}),
                "confidence": anomaly["score"],
                "reason": reason,
            },
        }
