"""Controlled Wazuh Active Response adapter with no shell escape hatch."""

from __future__ import annotations

from typing import Mapping, Protocol

from .base import AdapterOutcome


ISOLATE_ACTION = "cxyz-isolate-endpoint"
RECOVER_ACTION = "cxyz-restore-endpoint"


class WazuhControlledResponseClient(Protocol):
    """A transport facade restricted to two pre-approved response names."""

    def start_isolation(self, *, host: str, correlation_id: str) -> str:
        """Invoke only the installed cxyz-isolate-endpoint Active Response."""

    def isolation_is_enforced(self, *, host: str, correlation_id: str) -> bool:
        """Read controlled isolation status; it must not execute a probe command."""

    def restore_isolation(self, *, host: str, correlation_id: str) -> str:
        """Release only this operation's isolation; repeat safely after a timeout."""

    def isolation_is_removed(self, *, host: str, correlation_id: str) -> bool:
        """Read controlled recovery status; it must not execute a probe command."""


class WazuhIsolationAdapter:
    """Contain/restore only an explicitly eligible endpoint through Wazuh."""

    name = "wazuh"
    action = "isolate_host"

    def __init__(self, *, client: WazuhControlledResponseClient) -> None:
        self._client = client

    def recovery_reference(self, command: Mapping[str, object]) -> str:
        _, operation_id = self._command_host(command)
        return f"wazuh:{ISOLATE_ACTION}:{operation_id}"

    def apply(self, command: Mapping[str, object]) -> AdapterOutcome:
        host, correlation_id = self._command_host(command)
        try:
            reference = self._client.start_isolation(host=host, correlation_id=correlation_id)
        except Exception:
            return AdapterOutcome.failure(
                code="WAZUH_ISOLATE_FAILED",
                message="controlled Wazuh isolation request failed",
            )
        return AdapterOutcome.success(
            adapter_reference=self.recovery_reference(command),
            evidence_refs=(f"wazuh:{ISOLATE_ACTION}:{reference}",),
        )

    def verify(self, command: Mapping[str, object], *, adapter_reference: str) -> AdapterOutcome:
        host, correlation_id = self._command_host(command)
        try:
            enforced = self._client.isolation_is_enforced(host=host, correlation_id=correlation_id)
        except Exception:
            return AdapterOutcome.failure(
                code="WAZUH_ISOLATE_VERIFY_ERROR",
                message="cannot verify controlled Wazuh isolation",
            )
        if enforced is not True:
            return AdapterOutcome.failure(
                code="WAZUH_ISOLATE_VERIFY_FAILED",
                message="Wazuh did not prove endpoint isolation",
            )
        return AdapterOutcome.success(
            adapter_reference=adapter_reference,
            evidence_refs=(f"wazuh:{ISOLATE_ACTION}:verified",),
        )

    def revert(self, command: Mapping[str, object], *, adapter_reference: str) -> AdapterOutcome:
        host, correlation_id = self._command_host(command)
        try:
            reference = self._client.restore_isolation(host=host, correlation_id=correlation_id)
            removed = self._client.isolation_is_removed(host=host, correlation_id=correlation_id)
        except Exception:
            return AdapterOutcome.failure(
                code="WAZUH_RECOVER_FAILED",
                message="controlled Wazuh recovery failed",
            )
        if removed is not True:
            return AdapterOutcome.failure(
                code="WAZUH_RECOVER_VERIFY_FAILED",
                message="Wazuh did not prove endpoint recovery",
            )
        return AdapterOutcome.success(
            adapter_reference=adapter_reference,
            evidence_refs=(f"wazuh:{RECOVER_ACTION}:{reference}", f"wazuh:{RECOVER_ACTION}:verified"),
        )

    @staticmethod
    def _command_host(command: Mapping[str, object]) -> tuple[str, str]:
        target = command.get("target")
        if command.get("action") != "isolate_host" or not isinstance(target, Mapping) or target.get("type") != "host":
            raise ValueError("Wazuh adapter accepts only isolate_host commands for host targets")
        host = target.get("value")
        # Use the stable operation identity, never a caller-supplied trace label.
        correlation_id = command.get("idempotency_key")
        if not isinstance(host, str) or not host or not isinstance(correlation_id, str) or not correlation_id:
            raise ValueError("Wazuh command lacks host or correlation identity")
        return host, correlation_id
