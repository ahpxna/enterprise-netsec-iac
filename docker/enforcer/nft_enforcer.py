#!/usr/bin/env python3
"""Constrained nftables enforcement agent (stdlib only, mutual TLS).

Runs on a firewall node and exposes exactly three operations on one fixed pair of
sets (``soc_blocklist`` for IPv4, ``soc_blocklist6`` for IPv6) in one table:

    POST /v1/add       {"address": "...", "max_lifetime_seconds": N}
    POST /v1/remove    {"address": "..."}
    POST /v1/contains  {"address": "..."}

There is no rule, table, chain or shell surface.  Every element is added with an
nftables ``timeout`` so containment expires on its own if the orchestrator dies.
The orchestrator authenticates with a client certificate signed by the SOC CA.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import ssl
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Sequence

MAX_BODY = 4096
DEFAULT_LIFETIME = 3600
MAX_LIFETIME = 86400 + 600
Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


def _run(argv: Sequence[str]) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(list(argv), capture_output=True, text=True, timeout=5, check=False)


class Enforcer:
    def __init__(self, *, nft: str, family: str, table: str, set_name: str, run: Runner = _run) -> None:
        for value in (family, table, set_name):
            if not value.replace("_", "").isalnum():
                raise ValueError("family, table and set names must be alphanumeric/underscore")
        self._nft, self._family, self._table = nft, family, table
        self._sets = {4: set_name, 6: set_name + "6"}
        self._run = run

    @staticmethod
    def parse(address: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        if not isinstance(address, str):
            raise ValueError("address must be a string")
        ip = ipaddress.ip_address(address)
        if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local or ip.is_reserved:
            raise ValueError("special-use addresses are never blocked")
        return ip

    def _base(self, verb: str, ip) -> list[str]:
        return [self._nft, verb, "element", self._family, self._table, self._sets[ip.version]]

    def add(self, address: str, lifetime: int | None) -> None:
        ip = self.parse(address)
        seconds = DEFAULT_LIFETIME if lifetime is None else int(lifetime)
        if not 60 <= seconds <= MAX_LIFETIME:
            raise ValueError("max_lifetime_seconds is outside the permitted range")
        result = self._run(self._base("add", ip) + [f"{{ {ip} timeout {seconds}s }}"])
        if result.returncode != 0:
            raise RuntimeError("nft add failed")

    def remove(self, address: str) -> None:
        ip = self.parse(address)
        result = self._run(self._base("delete", ip) + [f"{{ {ip} }}"])
        if result.returncode != 0 and "No such file" not in result.stderr and "does not exist" not in result.stderr:
            raise RuntimeError("nft delete failed")

    def contains(self, address: str) -> bool:
        ip = self.parse(address)
        result = self._run([self._nft, "-j", "list", "set", self._family, self._table, self._sets[ip.version]])
        if result.returncode != 0:
            raise RuntimeError("nft list failed")
        for item in json.loads(result.stdout).get("nftables", []):
            for element in item.get("set", {}).get("elem", []):
                value = element.get("elem", {}).get("val") if isinstance(element, dict) else element
                try:
                    if value is not None and ipaddress.ip_address(value) == ip:
                        return True
                except ValueError:
                    continue
        return False


def make_handler(enforcer: Enforcer, allowed_clients: frozenset[str]):
    class Handler(BaseHTTPRequestHandler):
        server_version = "cxyz-enforcer"
        sys_version = ""

        def log_message(self, fmt, *args):  # no client data in logs
            sys.stderr.write("enforcer %s\n" % (fmt % args if args else fmt))

        def _reply(self, status: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _client_name(self) -> str | None:
            cert = self.connection.getpeercert()  # type: ignore[attr-defined]
            for rdn in cert.get("subject", ()):
                for key, value in rdn:
                    if key == "commonName":
                        return value
            return None

        def do_POST(self):  # noqa: N802
            if allowed_clients and self._client_name() not in allowed_clients:
                return self._reply(403, {"ok": False, "error": "client not permitted"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_BODY:
                    return self._reply(400, {"ok": False, "error": "bad length"})
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError("body must be an object")
                address = body.get("address")
                if self.path == "/v1/add":
                    enforcer.add(address, body.get("max_lifetime_seconds"))
                    return self._reply(200, {"ok": True})
                if self.path == "/v1/remove":
                    enforcer.remove(address)
                    return self._reply(200, {"ok": True})
                if self.path == "/v1/contains":
                    return self._reply(200, {"present": enforcer.contains(address)})
                return self._reply(404, {"ok": False, "error": "unknown operation"})
            except (ValueError, TypeError) as exc:
                return self._reply(400, {"ok": False, "error": str(exc)[:120]})
            except (RuntimeError, subprocess.TimeoutExpired, OSError):
                return self._reply(502, {"ok": False, "error": "enforcement backend error"})

        def do_GET(self):  # noqa: N802
            if self.path == "/healthz":
                return self._reply(200, {"ok": True})
            return self._reply(404, {"ok": False})

    return Handler


def serve(args: argparse.Namespace) -> None:
    enforcer = Enforcer(nft=args.nft, family=args.family, table=args.table, set_name=args.set)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    context.load_verify_locations(args.client_ca)
    context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingHTTPServer((args.listen, args.port), make_handler(enforcer, frozenset(args.allowed_client)))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", required=True)
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--client-ca", required=True)
    parser.add_argument("--allowed-client", action="append", default=[], help="permitted client CN (repeatable)")
    parser.add_argument("--nft", default="/usr/sbin/nft")
    parser.add_argument("--family", default="inet")
    parser.add_argument("--table", required=True)
    parser.add_argument("--set", default="soc_blocklist")
    serve(parser.parse_args())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
