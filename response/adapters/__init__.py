"""Narrow privileged adapter interfaces for the response orchestrator only."""

from .base import AdapterOutcome, ContainmentAdapter
from .blocklist import BlocklistAdapter, BlocklistPeer, NftablesBlocklistAdapter, VyosBlocklistAdapter
from .opnsense import OPNsenseBlocklistAdapter, OPNsensePeer
from .wazuh import WazuhIsolationAdapter

__all__ = [
    "AdapterOutcome",
    "BlocklistAdapter",
    "BlocklistPeer",
    "ContainmentAdapter",
    "NftablesBlocklistAdapter",
    "VyosBlocklistAdapter",
    "OPNsenseBlocklistAdapter",
    "OPNsensePeer",
    "WazuhIsolationAdapter",
]
