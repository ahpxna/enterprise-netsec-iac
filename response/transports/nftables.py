"""Client for the constrained nftables enforcement agent running on a firewall node.

The agent (``docker/enforcer/nft_enforcer.py``) exposes exactly three operations
on one fixed set and requires a client certificate.  Elements carry an nftables
``timeout`` so a dead orchestrator cannot leave a permanent block.
"""

from __future__ import annotations

from .http import DeliveryError, JsonHTTPS


class NftablesRawSet:
    def __init__(self, http: JsonHTTPS) -> None:
        self._http = http

    @classmethod
    def from_files(cls, *, url: str, ca: str, client_cert: str, client_key: str) -> "NftablesRawSet":
        return cls(JsonHTTPS(url, ca=ca, cert=client_cert, key=client_key))

    def contains(self, address: str) -> bool:
        status, reply = self._http.request("POST", "/v1/contains", {"address": address})
        present = reply.get("present") if status == 200 else None
        if type(present) is not bool:
            raise DeliveryError("NFT_AGENT_CONTAINS_CONTRACT", retryable=True)
        return present

    def add(self, address: str, max_lifetime_seconds: int | None) -> None:
        body: dict[str, object] = {"address": address}
        if max_lifetime_seconds is not None:
            body["max_lifetime_seconds"] = int(max_lifetime_seconds)
        status, reply = self._http.request("POST", "/v1/add", body)
        if status != 200 or reply.get("ok") is not True:
            raise DeliveryError("NFT_AGENT_ADD_NOT_ACKNOWLEDGED", retryable=True)

    def remove(self, address: str) -> None:
        status, reply = self._http.request("POST", "/v1/remove", {"address": address})
        if status != 200 or reply.get("ok") is not True:
            raise DeliveryError("NFT_AGENT_REMOVE_NOT_ACKNOWLEDGED", retryable=True)
