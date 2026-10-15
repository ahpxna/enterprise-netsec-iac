"""Verified-TLS HTTP helpers for firewall and Wazuh control APIs.

Re-exports the origin-bound JSON transport used by the SOC workers (no proxy, no
redirect, TLS >= 1.2, bounded bodies) and adds a form-encoded variant for the
VyOS HTTPS API.  Callers can only reach the fixed origin passed at construction.
"""

from __future__ import annotations

import json
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request

from soc.workers.https import DeliveryError, JsonHTTPS

__all__ = ["DeliveryError", "FormHTTPS", "JsonHTTPS", "basic_authorization"]


def basic_authorization(user: str, secret: str) -> str:
    from base64 import b64encode

    return "Basic " + b64encode(f"{user}:{secret}".encode()).decode("ascii")


class FormHTTPS(JsonHTTPS):
    """``application/x-www-form-urlencoded`` POSTs that answer with JSON (VyOS API)."""

    def post_form(self, path: str, fields: dict[str, str]) -> tuple[int, dict]:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("request path must be origin-relative")
        request = Request(
            self.origin + path,
            data=urlencode(fields).encode(),
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        )
        try:
            with self._opener.open(request, timeout=15) as reply:
                body = reply.read(2 * 1024 * 1024 + 1)
                if len(body) > 2 * 1024 * 1024:
                    raise DeliveryError("RESPONSE_TOO_LARGE", retryable=False)
                decoded = json.loads(body)
                if not isinstance(decoded, dict):
                    raise DeliveryError("RESPONSE_NOT_OBJECT", retryable=False)
                return reply.status, decoded
        except HTTPError as exc:
            status = exc.code
            exc.close()
            raise DeliveryError(f"HTTP_{status}", status=status,
                                retryable=status in (408, 425, 429) or status >= 500) from None
        except (URLError, TimeoutError, OSError):
            raise DeliveryError("TLS_OR_NETWORK_UNAVAILABLE", retryable=True) from None
        except HTTPException:
            raise DeliveryError("INCOMPLETE_HTTP_RESPONSE", retryable=True) from None
        except (ValueError, UnicodeError):
            raise DeliveryError("INVALID_JSON_RESPONSE", retryable=False) from None
