"""Versioned, fail-closed response-policy loading and target protections.

Policies are data, not executable code.  This module deliberately accepts a
small fixed vocabulary so an edited YAML file cannot introduce arbitrary
commands, endpoints, or response types.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
import ipaddress
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from .errors import PolicyError


SUPPORTED_ACTIONS = frozenset({"block_ip", "isolate_host"})
SUPPORTED_SIGNAL_TYPES = frozenset(
    {"suricata", "wazuh", "authentication", "threat_intel", "protected_asset"}
)


def canonical_json(value: object) -> bytes:
    """Return stable bytes for policy identities and idempotency calculations."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_hex(value: object) -> str:
    return sha256(canonical_json(value)).hexdigest()


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PolicyError(f"{label} must be a mapping")
    return value


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{label} must be a non-empty string")
    return value.strip()


def _require_positive_int(value: object, label: str, *, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise PolicyError(f"{label} must be an integer >= {minimum}")
    return value


def _string_list(value: object, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise PolicyError(f"{label} must be a list of strings")
    values = tuple(_require_string(item, f"{label} item") for item in value)
    if len(set(values)) != len(values):
        raise PolicyError(f"{label} must not contain duplicate values")
    return values


@dataclass(frozen=True)
class SignalRequirement:
    """One independently observed condition that can corroborate an anomaly."""

    kind: str
    min_severity: int | None = None
    min_count: int | None = None

    @classmethod
    def from_mapping(cls, value: object, label: str) -> "SignalRequirement":
        data = _require_mapping(value, label)
        allowed = {"type", "min_severity", "min_count"}
        unknown = set(data) - allowed
        if unknown:
            raise PolicyError(f"{label} has unsupported fields: {sorted(unknown)}")
        kind = _require_string(data.get("type"), f"{label}.type")
        if kind not in SUPPORTED_SIGNAL_TYPES:
            raise PolicyError(f"{label}.type must be an independent signal type")
        min_severity = data.get("min_severity")
        min_count = data.get("min_count")
        if min_severity is not None:
            min_severity = _require_positive_int(min_severity, f"{label}.min_severity", minimum=0)
        if min_count is not None:
            min_count = _require_positive_int(min_count, f"{label}.min_count")
        return cls(kind=kind, min_severity=min_severity, min_count=min_count)

    def matches(self, signal: Mapping[str, Any]) -> bool:
        if signal.get("type") != self.kind:
            return False
        if self.min_severity is not None:
            severity = signal.get("severity")
            if isinstance(severity, bool) or not isinstance(severity, (int, float)):
                return False
            if severity < self.min_severity:
                return False
        if self.min_count is not None:
            count = signal.get("count")
            if isinstance(count, bool) or not isinstance(count, (int, float)):
                return False
            if count < self.min_count:
                return False
        return True


@dataclass(frozen=True)
class ProtectionPolicy:
    """Targets that automatic containment is never allowed to affect."""

    allowlisted_ips: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]
    allowlisted_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    protected_ips: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]
    protected_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    protected_hosts: frozenset[str]
    allowed_isolation_hosts: frozenset[str]
    block_private_ip_targets: bool

    @classmethod
    def from_mapping(cls, value: object) -> "ProtectionPolicy":
        data = _require_mapping(value, "defaults.protections")
        allowed = {
            "allowlisted_ips",
            "allowlisted_networks",
            "protected_ips",
            "protected_networks",
            "protected_hosts",
            "allowed_isolation_hosts",
            "block_private_ip_targets",
        }
        unknown = set(data) - allowed
        if unknown:
            raise PolicyError(f"defaults.protections has unsupported fields: {sorted(unknown)}")

        def addresses(name: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
            try:
                return tuple(ipaddress.ip_address(item) for item in _string_list(data.get(name), name))
            except ValueError as exc:
                raise PolicyError(f"{name} contains an invalid IP address") from exc

        def networks(name: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
            try:
                return tuple(
                    ipaddress.ip_network(item, strict=False)
                    for item in _string_list(data.get(name), name)
                )
            except ValueError as exc:
                raise PolicyError(f"{name} contains an invalid CIDR") from exc

        private = data.get("block_private_ip_targets", False)
        if not isinstance(private, bool):
            raise PolicyError("block_private_ip_targets must be boolean")
        return cls(
            allowlisted_ips=addresses("allowlisted_ips"),
            allowlisted_networks=networks("allowlisted_networks"),
            protected_ips=addresses("protected_ips"),
            protected_networks=networks("protected_networks"),
            protected_hosts=frozenset(host.lower() for host in _string_list(data.get("protected_hosts"), "protected_hosts")),
            allowed_isolation_hosts=frozenset(
                host.lower() for host in _string_list(data.get("allowed_isolation_hosts"), "allowed_isolation_hosts")
            ),
            block_private_ip_targets=private,
        )

    def assert_target_allowed(self, *, action: str, target_type: str, target_value: str) -> None:
        """Reject protected or ambiguous targets before any adapter invocation."""

        if action == "block_ip":
            if target_type != "ip":
                raise PolicyError("block_ip requires an IP target")
            try:
                address = ipaddress.ip_address(target_value)
            except ValueError as exc:
                raise PolicyError("block_ip target is not a valid IP address") from exc
            if address.is_unspecified or address.is_loopback or address.is_link_local or address.is_multicast:
                raise PolicyError("automatic containment cannot target special-use IP addresses")
            if address.is_reserved:
                raise PolicyError("automatic containment cannot target reserved IP addresses")
            if self.block_private_ip_targets and address.is_private:
                raise PolicyError("automatic containment of private IP addresses is disabled")
            if address in self.allowlisted_ips or any(address in network for network in self.allowlisted_networks):
                raise PolicyError("target is explicitly allowlisted")
            if address in self.protected_ips:
                raise PolicyError("target is protected DNS, NTP, RADIUS, SOC, or management infrastructure")
            if any(address in network for network in self.protected_networks):
                raise PolicyError("target is in a protected management or SOC network")
            return

        if action == "isolate_host":
            if target_type != "host":
                raise PolicyError("isolate_host requires a host target")
            host = _require_string(target_value, "host target").lower()
            if host in self.protected_hosts:
                raise PolicyError("target is a protected management or SOC host")
            if host not in self.allowed_isolation_hosts:
                raise PolicyError("host is not explicitly eligible for controlled isolation")
            return

        raise PolicyError(f"unsupported response action: {action}")


@dataclass(frozen=True)
class RateLimit:
    max_actions: int
    window_seconds: int

    @classmethod
    def from_mapping(cls, value: object) -> "RateLimit":
        data = _require_mapping(value, "defaults.rate_limit")
        if set(data) != {"max_actions", "window_seconds"}:
            raise PolicyError("defaults.rate_limit must contain only max_actions and window_seconds")
        return cls(
            max_actions=_require_positive_int(data.get("max_actions"), "defaults.rate_limit.max_actions"),
            window_seconds=_require_positive_int(data.get("window_seconds"), "defaults.rate_limit.window_seconds"),
        )


@dataclass(frozen=True)
class ResponsePolicy:
    """A policy can only nominate an action after non-AI corroboration."""

    id: str
    version: str
    action: str
    ttl_seconds: int
    min_ai_score: float
    require_any: tuple[SignalRequirement, ...]
    sha256: str

    @classmethod
    def from_mapping(cls, value: object, index: int) -> "ResponsePolicy":
        data = _require_mapping(value, f"policies[{index}]")
        allowed = {"id", "version", "enabled", "action", "ttl_seconds", "when"}
        unknown = set(data) - allowed
        if unknown:
            raise PolicyError(f"policies[{index}] has unsupported fields: {sorted(unknown)}")
        if data.get("enabled") is not True:
            raise PolicyError(f"policies[{index}] must set enabled: true")
        identifier = _require_string(data.get("id"), f"policies[{index}].id")
        version = _require_string(data.get("version"), f"policies[{index}].version")
        action = _require_string(data.get("action"), f"policies[{index}].action")
        if action not in SUPPORTED_ACTIONS:
            raise PolicyError(f"policies[{index}].action is unsupported")
        ttl = _require_positive_int(data.get("ttl_seconds"), f"policies[{index}].ttl_seconds", minimum=60)
        if ttl > 86400:
            raise PolicyError(f"policies[{index}].ttl_seconds exceeds one day")
        when = _require_mapping(data.get("when"), f"policies[{index}].when")
        if set(when) != {"ai_score_gte", "require_any"}:
            raise PolicyError(f"policies[{index}].when must contain ai_score_gte and require_any")
        score = when.get("ai_score_gte")
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0.9 <= float(score) <= 1:
            raise PolicyError(
                f"policies[{index}].when.ai_score_gte must be between 0.90 and 1; "
                "automatic response may not be authorized below the global hybrid threshold"
            )
        require_any_raw = when.get("require_any")
        if not isinstance(require_any_raw, Sequence) or isinstance(require_any_raw, (str, bytes)) or not require_any_raw:
            raise PolicyError(f"policies[{index}].when.require_any must contain an independent signal")
        requirements = tuple(
            SignalRequirement.from_mapping(item, f"policies[{index}].when.require_any[{item_index}]")
            for item_index, item in enumerate(require_any_raw)
        )
        normalized = {
            "id": identifier,
            "version": version,
            "enabled": True,
            "action": action,
            "ttl_seconds": ttl,
            "when": {
                "ai_score_gte": float(score),
                "require_any": [
                    {
                        "type": item.kind,
                        **({"min_severity": item.min_severity} if item.min_severity is not None else {}),
                        **({"min_count": item.min_count} if item.min_count is not None else {}),
                    }
                    for item in requirements
                ],
            },
        }
        return cls(
            id=identifier,
            version=version,
            action=action,
            ttl_seconds=ttl,
            min_ai_score=float(score),
            require_any=requirements,
            sha256=sha256_hex(normalized),
        )


@dataclass(frozen=True)
class PolicyCatalog:
    """All response policy and protection state required by both boundaries."""

    schema_version: str
    protections: ProtectionPolicy
    rate_limit: RateLimit
    dedup_seconds: int
    command_valid_for_seconds: int
    evidence_max_age_seconds: int
    policies: Mapping[str, ResponsePolicy]
    source_sha256: str

    @classmethod
    def from_path(cls, path: str | Path) -> "PolicyCatalog":
        source = Path(path).read_bytes()
        try:
            document = yaml.safe_load(source)
        except yaml.YAMLError as exc:
            raise PolicyError(f"policy YAML cannot be parsed: {path}") from exc
        return cls.from_mapping(document, source_sha256=sha256(source).hexdigest())

    @classmethod
    def from_mapping(cls, value: object, *, source_sha256: str = "in-memory") -> "PolicyCatalog":
        data = _require_mapping(value, "policy document")
        required = {"schema_version", "defaults", "policies"}
        if set(data) != required:
            raise PolicyError("policy document must contain only schema_version, defaults, and policies")
        if data.get("schema_version") != "response-policy-set-v1":
            raise PolicyError("unsupported response policy schema version")
        defaults = _require_mapping(data.get("defaults"), "defaults")
        if set(defaults) != {"protections", "rate_limit", "dedup_seconds", "command_valid_for_seconds", "evidence_max_age_seconds"}:
            raise PolicyError("defaults has unsupported or missing fields")
        dedup_seconds = _require_positive_int(defaults.get("dedup_seconds"), "defaults.dedup_seconds", minimum=60)
        command_valid = _require_positive_int(
            defaults.get("command_valid_for_seconds"),
            "defaults.command_valid_for_seconds",
            minimum=30,
        )
        if command_valid > 900:
            raise PolicyError("defaults.command_valid_for_seconds must be <= 900")
        evidence_max_age = _require_positive_int(
            defaults.get("evidence_max_age_seconds"), "defaults.evidence_max_age_seconds", minimum=30,
        )
        if evidence_max_age > 86400:
            raise PolicyError("defaults.evidence_max_age_seconds must be <= 86400")
        protections = ProtectionPolicy.from_mapping(defaults.get("protections"))
        rate_limit = RateLimit.from_mapping(defaults.get("rate_limit"))
        # Every command must bind the safeguards used to authorize it, not just
        # the per-rule threshold/action. Normalize parsed semantics, not YAML.
        safeguard_material = {
            "protections": {
                name: sorted(str(item) for item in getattr(protections, name))
                for name in ("allowlisted_ips", "allowlisted_networks", "protected_ips",
                             "protected_networks", "protected_hosts", "allowed_isolation_hosts")
            },
            "block_private_ip_targets": protections.block_private_ip_targets,
            "rate_limit": {"max_actions": rate_limit.max_actions, "window_seconds": rate_limit.window_seconds},
            "dedup_seconds": dedup_seconds,
            "command_valid_for_seconds": command_valid,
            "evidence_max_age_seconds": evidence_max_age,
        }
        raw_policies = data.get("policies")
        if not isinstance(raw_policies, Sequence) or isinstance(raw_policies, (str, bytes)) or not raw_policies:
            raise PolicyError("policies must be a non-empty list")
        rules = tuple(ResponsePolicy.from_mapping(item, index) for index, item in enumerate(raw_policies))
        policies = tuple(replace(rule, sha256=sha256_hex({
            "rule_sha256": rule.sha256, "safeguards": safeguard_material,
        })) for rule in rules)
        by_id = {policy.id: policy for policy in policies}
        if len(by_id) != len(policies):
            raise PolicyError("policy identifiers must be unique")
        return cls(
            schema_version="response-policy-set-v1",
            protections=protections,
            rate_limit=rate_limit,
            dedup_seconds=dedup_seconds,
            command_valid_for_seconds=command_valid,
            evidence_max_age_seconds=evidence_max_age,
            policies=by_id,
            source_sha256=source_sha256,
        )

    def policy(self, policy_id: str) -> ResponsePolicy:
        try:
            return self.policies[policy_id]
        except KeyError as exc:
            raise PolicyError(f"unknown response policy: {policy_id}") from exc
