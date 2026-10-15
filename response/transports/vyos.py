"""VyOS 1.4 HTTPS-API backend for the fixed ``SOC_BLOCKLIST`` address-group.

Only ``set``/``delete`` of one address under ``firewall group address-group
SOC_BLOCKLIST address`` and a read of that subtree are ever issued.  Changes are
committed to the running configuration and deliberately never saved, so a router
reboot clears a transient containment instead of persisting it.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..adapters.blocklist import SOC_BLOCKLIST_ALIAS
from .http import DeliveryError, FormHTTPS

_PATH = ["firewall", "group", "address-group", SOC_BLOCKLIST_ALIAS, "address"]


class VyosRawSet:
    def __init__(self, http: FormHTTPS, api_key: str) -> None:
        if not api_key or any(char.isspace() for char in api_key):
            raise ValueError("VyOS API key must be a single token")
        self._http = http
        self._key = api_key

    @classmethod
    def from_files(cls, *, url: str, ca: str, api_key_file: str) -> "VyosRawSet":
        return cls(FormHTTPS(url, ca=ca), Path(api_key_file).read_text(encoding="utf-8").strip())

    def _call(self, endpoint: str, operation: dict) -> dict:
        status, reply = self._http.post_form(
            endpoint, {"data": json.dumps(operation, separators=(",", ":")), "key": self._key}
        )
        if status != 200:
            raise DeliveryError("VYOS_API_STATUS", retryable=True)
        return reply

    def contains(self, address: str) -> bool:
        reply = self._call("/retrieve", {"op": "returnValues", "path": _PATH})
        if reply.get("success") is not True:
            error = str(reply.get("error", "")).lower()
            if "empty" in error or "does not exist" in error:
                return False  # the group has no addresses yet
            raise DeliveryError("VYOS_RETRIEVE_FAILED", retryable=True)
        data = reply.get("data")
        values = data if isinstance(data, list) else [data] if isinstance(data, str) else []
        return address in values

    def add(self, address: str, max_lifetime_seconds: int | None) -> None:
        # VyOS has no per-element timeout; the orchestrator TTL is authoritative.
        reply = self._call("/configure", {"op": "set", "path": [*_PATH, address]})
        if reply.get("success") is not True:
            raise DeliveryError("VYOS_SET_FAILED", retryable=True)

    def remove(self, address: str) -> None:
        reply = self._call("/configure", {"op": "delete", "path": [*_PATH, address]})
        if reply.get("success") is not True:
            error = str(reply.get("error", "")).lower()
            if "nothing to delete" not in error and "not exist" not in error:
                raise DeliveryError("VYOS_DELETE_FAILED", retryable=True)
