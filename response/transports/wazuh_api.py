"""Wazuh manager API backend for the two fixed Active Response operations.

Only ``!cxyz-isolate-endpoint`` and ``!cxyz-restore-endpoint`` can be requested,
each with a single operation-id argument.  The target agent is resolved by exact
name and must be unique and active.  Verification never executes anything on the
endpoint: it reads Wazuh's FIM inventory for the marker file that the Active
Response script writes only after its nftables ruleset is active (see
``docker/wazuh/active-response/cxyz_endpoint_isolation.py``).
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import time
from typing import Callable
from urllib.parse import quote

from .http import DeliveryError, JsonHTTPS, basic_authorization

ISOLATE_SCRIPT = "!cxyz-isolate-endpoint"
RESTORE_SCRIPT = "!cxyz-restore-endpoint"
MARKER_DIR = "/var/ossec/var/cxyz-isolation"
TOKEN_TTL_SECONDS = 600


def marker_path(operation_id: str) -> str:
    return f"{MARKER_DIR}/{sha256(operation_id.encode()).hexdigest()[:40]}"


class WazuhApiClient:
    """Implements ``WazuhControlledResponseClient``."""

    def __init__(
        self,
        http: JsonHTTPS,
        *,
        user: str,
        password: str,
        verify_timeout_seconds: float = 25.0,
        poll_seconds: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._basic = http.with_authorization(basic_authorization(user, password))
        self._http = http
        self._token: str | None = None
        self._token_at = 0.0
        self._timeout, self._poll = verify_timeout_seconds, poll_seconds
        self._clock, self._sleep = clock, sleep

    @classmethod
    def from_files(cls, *, url: str, ca: str, credentials_file: str, **kwargs) -> "WazuhApiClient":
        """``credentials_file`` holds ``<user>:<password>`` for an API user limited to
        active-response, agent read and syscheck read."""

        user, _, password = Path(credentials_file).read_text(encoding="utf-8").strip().partition(":")
        if not user or not password:
            raise ValueError("Wazuh credentials file must contain user:password")
        return cls(JsonHTTPS(url, ca=ca), user=user, password=password, **kwargs)

    # ------------------------------------------------------------------ auth
    def _bearer(self) -> JsonHTTPS:
        if self._token is None or self._clock() - self._token_at > TOKEN_TTL_SECONDS:
            status, reply = self._basic.request("POST", "/security/user/authenticate")
            token = reply.get("data", {}).get("token") if status == 200 else None
            if not isinstance(token, str) or not token:
                raise DeliveryError("WAZUH_AUTH_FAILED", retryable=True)
            self._token, self._token_at = token, self._clock()
        return self._http.with_authorization("Bearer " + self._token)

    def _call(self, method: str, path: str, payload: dict | None = None) -> dict:
        try:
            status, reply = self._bearer().request(method, path, payload)
        except DeliveryError as exc:
            if exc.status == 401:
                self._token = None  # expired token: re-authenticate once
                status, reply = self._bearer().request(method, path, payload)
            else:
                raise
        if status != 200:
            raise DeliveryError("WAZUH_API_STATUS", retryable=True)
        return reply

    # ----------------------------------------------------------------- agents
    def _agent_id(self, host: str) -> str:
        reply = self._call("GET", f"/agents?name={quote(host, safe='')}&select=id,name,status&limit=2")
        items = reply.get("data", {}).get("affected_items", [])
        if len(items) != 1 or items[0].get("name") != host or items[0].get("status") != "active":
            raise DeliveryError("WAZUH_AGENT_NOT_UNIQUE_ACTIVE", retryable=False)
        return str(items[0]["id"])

    def _trigger(self, script: str, host: str, operation_id: str) -> str:
        agent = self._agent_id(host)
        reply = self._call(
            "PUT", f"/active-response?agents_list={quote(agent, safe='')}",
            {"command": script, "custom": True, "arguments": [operation_id]},
        )
        data = reply.get("data", {})
        if data.get("total_failed_items", 1) != 0 or agent not in map(str, data.get("affected_items", [])):
            raise DeliveryError("WAZUH_ACTIVE_RESPONSE_NOT_ACCEPTED", retryable=True)
        return f"ar:{agent}:{sha256(operation_id.encode()).hexdigest()[:12]}"

    def start_isolation(self, *, host: str, correlation_id: str) -> str:
        return self._trigger(ISOLATE_SCRIPT, host, correlation_id)

    def restore_isolation(self, *, host: str, correlation_id: str) -> str:
        return self._trigger(RESTORE_SCRIPT, host, correlation_id)

    # ----------------------------------------------------------- verification
    def _marker_present(self, host: str, operation_id: str) -> bool:
        agent = self._agent_id(host)
        reply = self._call(
            "GET", f"/syscheck/{quote(agent, safe='')}?file={quote(marker_path(operation_id), safe='')}&limit=1"
        )
        return reply.get("data", {}).get("total_affected_items", 0) > 0

    def _await(self, host: str, operation_id: str, present: bool) -> bool:
        deadline = self._clock() + self._timeout
        while True:
            if self._marker_present(host, operation_id) is present:
                return True
            if self._clock() >= deadline:
                return False
            self._sleep(self._poll)  # FIM reports asynchronously

    def isolation_is_enforced(self, *, host: str, correlation_id: str) -> bool:
        return self._await(host, correlation_id, True)

    def isolation_is_removed(self, *, host: str, correlation_id: str) -> bool:
        return self._await(host, correlation_id, False)
