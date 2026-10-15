"""Adapter contracts with no arbitrary configuration or shell surface."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol


@dataclass(frozen=True)
class AdapterOutcome:
    """A non-secret result from one narrowly scoped containment operation."""

    ok: bool
    adapter_reference: str | None = None
    evidence_refs: tuple[str, ...] = ()
    code: str | None = None
    message: str | None = None

    @classmethod
    def success(cls, *, adapter_reference: str, evidence_refs: tuple[str, ...]) -> "AdapterOutcome":
        return cls(ok=True, adapter_reference=adapter_reference, evidence_refs=evidence_refs)

    @classmethod
    def failure(cls, *, code: str, message: str, evidence_refs: tuple[str, ...] = ()) -> "AdapterOutcome":
        return cls(ok=False, code=code, message=message, evidence_refs=evidence_refs)


class ContainmentAdapter(Protocol):
    """The only privileged operations the orchestrator is allowed to invoke."""

    name: str
    action: str

    def recovery_reference(self, command: Mapping[str, object]) -> str:
        """Return a deterministic local reference without contacting a peer."""

    def apply(self, command: Mapping[str, object]) -> AdapterOutcome:
        """Apply exactly the adapter's one permitted containment action."""

    def verify(self, command: Mapping[str, object], *, adapter_reference: str) -> AdapterOutcome:
        """Produce evidence that the permitted action is enforced."""

    def revert(self, command: Mapping[str, object], *, adapter_reference: str) -> AdapterOutcome:
        """Reverse exactly the earlier permitted action."""
