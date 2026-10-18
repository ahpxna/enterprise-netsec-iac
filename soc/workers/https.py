"""TLS-verifying, origin-bound JSON transport with no proxy or redirect fallback."""

from __future__ import annotations

import json
from http.client import HTTPException
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener
from typing import Callable


class DeliveryError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool, status: int | None = None):
        super().__init__(code)
        self.code, self.retryable, self.status = code, retryable, status


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class JsonHTTPS:
    def __init__(self, origin: str, *, ca: str, cert: str | None = None,
                 key: str | None = None, authorization: str | Callable[[], str] | None = None):
        parsed = urlsplit(origin)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
            raise ValueError("a bare HTTPS origin without credentials is required")
        self.origin = origin.rstrip("/")
        context = ssl.create_default_context(cafile=ca)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if bool(cert) != bool(key):
            raise ValueError("client certificate and key must be provided together")
        if cert:
            context.load_cert_chain(certfile=cert, keyfile=key)
        self._opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=context))
        self._authorization = authorization

    def with_authorization(self, authorization: str | Callable[[], str] | None) -> "JsonHTTPS":
        """Same verified origin and TLS context, different ``Authorization`` value."""

        import copy

        clone = copy.copy(self)
        clone._authorization = authorization
        return clone

    def request(self, method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("request path must be origin-relative")
        headers = {"Accept": "application/json"}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload, allow_nan=False).encode()
        # A callable is asked on every request, so a rotated credential file takes effect without a restart.
        authorization = self._authorization() if callable(self._authorization) else self._authorization
        if authorization:
            headers["Authorization"] = authorization
        request = Request(self.origin + path, data=data, method=method, headers=headers)
        try:
            with self._opener.open(request, timeout=15) as reply:
                body = reply.read(2 * 1024 * 1024 + 1)
                if len(body) > 2 * 1024 * 1024:
                    raise DeliveryError("RESPONSE_TOO_LARGE", retryable=False)
                # A bounded read can return early without raising IncompleteRead.
                # Check remaining Content-Length before treating truncated JSON
                # as a permanent schema error.
                if reply.length not in (None, 0):
                    raise DeliveryError("INCOMPLETE_HTTP_RESPONSE", retryable=True)
                decoded = json.loads(body)
                if not isinstance(decoded, dict):
                    raise DeliveryError("RESPONSE_NOT_OBJECT", retryable=False)
                return reply.status, decoded
        except HTTPError as exc:
            # Do not copy error bodies, URLs, or auth headers into audit/logs.
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
