"""Fixed-set IP blocklist adapter shared by every firewall backend.

The adapter can only add, remove and read membership of one fixed set
(``SOC_BLOCKLIST``) on every configured peer.  It accepts no URL, credential,
alias name or rule definition: backends supply a three-method client bound to
that set.  All peers must agree before an action is reported applied or
verified, and a partial apply is compensated before the failure is returned.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Mapping, Protocol, Sequence

from .base import AdapterOutcome

SOC_BLOCKLIST_ALIAS = "SOC_BLOCKLIST"
# The firewall-side lifetime is a backstop only: if the orchestrator dies, the
# entry still disappears.  The orchestrator's own TTL/rollback remains authoritative.
BACKSTOP_GRACE_SECONDS = 300


class BlocklistClient(Protocol):
    """Deliberately tiny interface to a preconfigured, TLS-verified firewall peer."""

    def add_soc_blocklist_address(
        self, *, address: str, idempotency_key: str, max_lifetime_seconds: int | None = None
    ) -> str:
        """Add one address to the fixed set and return an opaque reference.

        ``max_lifetime_seconds`` asks backends that support element timeouts to
        expire the entry on their own as a dead-man backstop.
        """

    def remove_soc_blocklist_address(self, *, address: str, idempotency_key: str) -> str:
        """Release only this key's ownership; never remove pre-existing/other owners' entries.

        Repeated release must be safe, including after an ambiguous add timeout.
        """

    def soc_blocklist_contains(self, *, address: str) -> bool:
        """Read back membership from the fixed set."""


@dataclass(frozen=True)
class BlocklistPeer:
    """A preconfigured firewall peer; credentials live in its injected client only."""

    name: str
    client: BlocklistClient


class BlocklistAdapter:
    """Apply/revert an IP on all peers using only fixed-set operations."""

    action = "block_ip"
    name = "firewall"

    def __init__(self, *, peers: Sequence[BlocklistPeer], name: str | None = None) -> None:
        names = [peer.name for peer in peers]
        if len(peers) < 2 or any(not item for item in names) or len(set(names)) != len(names):
            raise ValueError("at least two uniquely named firewall peers are required")
        if name is not None:
            self.name = name
        self._peers = tuple(peers)

    def recovery_reference(self, command: Mapping[str, object]) -> str:
        self._command_address(command)
        return f"{self.name}-ha:{SOC_BLOCKLIST_ALIAS}:{self._idempotency_key(command)}"

    def apply(self, command: Mapping[str, object]) -> AdapterOutcome:
        address = self._command_address(command)
        key = self._idempotency_key(command)
        lifetime = self._lifetime(command)
        applied: list[BlocklistPeer] = []
        refs: list[str] = []
        try:
            for peer in self._peers:
                applied.append(peer)
                # Include the in-flight peer: a timeout may follow a successful add.
                peer_ref = peer.client.add_soc_blocklist_address(
                    address=address, idempotency_key=key, max_lifetime_seconds=lifetime
                )
                refs.append(self._evidence_ref(peer, "add", peer_ref))
                if peer.client.soc_blocklist_contains(address=address) is not True:
                    raise RuntimeError(f"{peer.name} did not report fixed-set membership")
                refs.append(self._evidence_ref(peer, "membership", SOC_BLOCKLIST_ALIAS))
        except Exception:  # Adapter boundary converts transport errors to a safe outcome.
            rollback_refs = self._rollback_peers(applied, address=address, idempotency_key=key)
            return AdapterOutcome.failure(
                code=f"{self.name.upper()}_HA_APPLY_FAILED",
                message="SOC_BLOCKLIST apply failed; applied peers were reverted where possible",
                evidence_refs=tuple(refs + rollback_refs),
            )
        return AdapterOutcome.success(
            adapter_reference=self.recovery_reference(command), evidence_refs=tuple(refs)
        )

    def verify(self, command: Mapping[str, object], *, adapter_reference: str) -> AdapterOutcome:
        address = self._command_address(command)
        missing: list[str] = []
        refs: list[str] = []
        for peer in self._peers:
            try:
                present = peer.client.soc_blocklist_contains(address=address)
            except Exception:
                return AdapterOutcome.failure(
                    code=f"{self.name.upper()}_HA_VERIFY_ERROR",
                    message=f"cannot verify {peer.name} fixed-set membership",
                    evidence_refs=tuple(refs),
                )
            refs.append(self._evidence_ref(peer, "verify", SOC_BLOCKLIST_ALIAS))
            if present is not True:
                missing.append(peer.name)
        if missing:
            return AdapterOutcome.failure(
                code=f"{self.name.upper()}_HA_VERIFY_FAILED",
                message=f"SOC_BLOCKLIST is absent on peer(s): {', '.join(missing)}",
                evidence_refs=tuple(refs),
            )
        return AdapterOutcome.success(adapter_reference=adapter_reference, evidence_refs=tuple(refs))

    def revert(self, command: Mapping[str, object], *, adapter_reference: str) -> AdapterOutcome:
        address = self._command_address(command)
        key = self._idempotency_key(command)
        refs: list[str] = []
        failures: list[str] = []
        for peer in self._peers:
            try:
                peer_ref = peer.client.remove_soc_blocklist_address(address=address, idempotency_key=key)
                refs.append(self._evidence_ref(peer, "remove", peer_ref))
                if peer.client.soc_blocklist_contains(address=address) is not False:
                    # Another owner or a pre-existing entry legitimately keeps the
                    # address blocked; ownership-aware clients say so explicitly.
                    if self._released_without_removal(peer_ref):
                        refs.append(self._evidence_ref(peer, "released", SOC_BLOCKLIST_ALIAS))
                    else:
                        failures.append(peer.name)
                else:
                    refs.append(self._evidence_ref(peer, "absence", SOC_BLOCKLIST_ALIAS))
            except Exception:
                failures.append(peer.name)
        if failures:
            return AdapterOutcome.failure(
                code=f"{self.name.upper()}_HA_REVERT_FAILED",
                message=f"SOC_BLOCKLIST removal could not be verified on peer(s): {', '.join(failures)}",
                evidence_refs=tuple(refs),
            )
        return AdapterOutcome.success(adapter_reference=adapter_reference, evidence_refs=tuple(refs))

    @staticmethod
    def _released_without_removal(reference: str) -> bool:
        return isinstance(reference, str) and reference.startswith(("shared:", "preexisting:"))

    @staticmethod
    def _lifetime(command: Mapping[str, object]) -> int | None:
        ttl = command.get("ttl_seconds")
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
            return None
        return ttl + BACKSTOP_GRACE_SECONDS

    @staticmethod
    def _command_address(command: Mapping[str, object]) -> str:
        target = command.get("target")
        if command.get("action") != "block_ip" or not isinstance(target, Mapping) or target.get("type") != "ip":
            raise ValueError("firewall adapters accept only block_ip commands for IP targets")
        value = target.get("value")
        if not isinstance(value, str):
            raise ValueError("firewall target must be a string IP address")
        return str(ipaddress.ip_address(value))

    @staticmethod
    def _idempotency_key(command: Mapping[str, object]) -> str:
        key = command.get("idempotency_key")
        if not isinstance(key, str) or not key:
            raise ValueError("firewall command has no idempotency key")
        return key

    def _evidence_ref(self, peer: BlocklistPeer, operation: str, reference: str) -> str:
        # Peer-side references are opaque to avoid copying transport internals
        # or credentials into the analytics/audit plane.
        return f"{self.name}:{peer.name}:{SOC_BLOCKLIST_ALIAS}:{operation}:{reference}"

    def _rollback_peers(
        self, peers: list[BlocklistPeer], *, address: str, idempotency_key: str
    ) -> list[str]:
        refs: list[str] = []
        for peer in reversed(peers):
            try:
                reference = peer.client.remove_soc_blocklist_address(
                    address=address, idempotency_key=idempotency_key
                )
                refs.append(f"{self.name}:{peer.name}:{SOC_BLOCKLIST_ALIAS}:compensate:{reference}")
            except Exception:
                refs.append(f"{self.name}:{peer.name}:{SOC_BLOCKLIST_ALIAS}:compensate:failed")
        return refs


class NftablesBlocklistAdapter(BlocklistAdapter):
    """Path A: nftables ``soc_blocklist`` sets on both firewalls (fw-core and fw-dmz)."""

    name = "nftables"

    def __init__(self, *, peers: Sequence[BlocklistPeer]) -> None:
        super().__init__(peers=peers, name="nftables")


class VyosBlocklistAdapter(BlocklistAdapter):
    """Path B: VyOS ``SOC_BLOCKLIST`` address-group on both firewalls."""

    name = "vyos"

    def __init__(self, *, peers: Sequence[BlocklistPeer]) -> None:
        super().__init__(peers=peers, name="vyos")
