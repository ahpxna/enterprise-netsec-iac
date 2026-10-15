"""OPNsense ``alias_util`` backend for the fixed ``SOC_BLOCKLIST`` alias.

Uses OPNsense's alias utility API, which updates the live pf table directly, so a
successful add/delete is enforcement-plane state rather than only configuration
state.  The API key identity must be limited to this alias.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

from ..adapters.blocklist import SOC_BLOCKLIST_ALIAS
from .http import DeliveryError, JsonHTTPS, basic_authorization


class OPNsenseRawSet:
    def __init__(self, http: JsonHTTPS) -> None:
        self._http = http
        self._base = f"/api/firewall/alias_util"

    @classmethod
    def from_files(cls, *, url: str, ca: str, credentials_file: str) -> "OPNsenseRawSet":
        """``credentials_file`` holds ``<api_key>:<api_secret>`` on a single line."""

        key, _, secret = Path(credentials_file).read_text(encoding="utf-8").strip().partition(":")
        if not key or not secret:
            raise ValueError("OPNsense credentials file must contain key:secret")
        return cls(JsonHTTPS(url, ca=ca, authorization=basic_authorization(key, secret)))

    def contains(self, address: str) -> bool:
        status, reply = self._http.request("GET", f"{self._base}/list/{SOC_BLOCKLIST_ALIAS}")
        rows = reply.get("rows") if status == 200 else None
        if not isinstance(rows, list):
            raise DeliveryError("OPNSENSE_LIST_CONTRACT", retryable=True)
        target = ipaddress.ip_address(address)
        for row in rows:
            value = row.get("ip") if isinstance(row, dict) else None
            try:
                if value is not None and ipaddress.ip_address(str(value).split("/")[0]) == target:
                    return True
            except ValueError:
                continue
        return False

    def add(self, address: str, max_lifetime_seconds: int | None) -> None:
        # alias_util has no per-entry timeout; the orchestrator TTL is authoritative here.
        status, reply = self._http.request(
            "POST", f"{self._base}/add/{SOC_BLOCKLIST_ALIAS}", {"address": address}
        )
        if status != 200 or reply.get("status") != "done":
            raise DeliveryError("OPNSENSE_ADD_NOT_ACKNOWLEDGED", retryable=True)

    def remove(self, address: str) -> None:
        status, reply = self._http.request(
            "POST", f"{self._base}/delete/{SOC_BLOCKLIST_ALIAS}", {"address": address}
        )
        if status != 200 or reply.get("status") not in {"done", "not_found"}:
            raise DeliveryError("OPNSENSE_DELETE_NOT_ACKNOWLEDGED", retryable=True)
