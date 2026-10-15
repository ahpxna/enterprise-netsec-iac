"""Scoped OPNsense alias adapter; it cannot alter firewall configuration.

The transport implementation is intentionally injected (see
``response.transports.opnsense``).  It must use TLS with CA/SAN validation and an
OPNsense identity limited to the SOC_BLOCKLIST alias.  This module does not
accept URLs, passwords, tokens, generic endpoints, or arbitrary alias names.
"""

from __future__ import annotations

from dataclasses import dataclass

from .blocklist import SOC_BLOCKLIST_ALIAS, BlocklistAdapter, BlocklistClient, BlocklistPeer

__all__ = [
    "SOC_BLOCKLIST_ALIAS",
    "OPNsenseAliasClient",
    "OPNsensePeer",
    "OPNsenseBlocklistAdapter",
]

# Historical name kept for callers and type hints written against the original API.
OPNsenseAliasClient = BlocklistClient


@dataclass(frozen=True)
class OPNsensePeer(BlocklistPeer):
    """A preconfigured HA peer; credentials live in its injected client only."""


class OPNsenseBlocklistAdapter(BlocklistAdapter):
    """Apply/revert an IP on both HA peers using only SOC_BLOCKLIST operations."""

    name = "opnsense"

    def __init__(self, *, primary: BlocklistPeer, secondary: BlocklistPeer) -> None:
        if not primary.name or not secondary.name or primary.name == secondary.name:
            raise ValueError("two uniquely named OPNsense HA peers are required")
        super().__init__(peers=(primary, secondary), name="opnsense")
