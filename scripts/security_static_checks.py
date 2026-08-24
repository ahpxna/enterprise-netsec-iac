#!/usr/bin/env python3
"""Fail-closed repository invariants for previously audited security regressions."""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ERRORS: list[str] = []


def fail(message: str) -> None:
    ERRORS.append(message)


def text(path: str) -> str:
    return (ROOT / path).read_text()


compose = text("docker-compose.yml")
for token in ("8081:8080", "55000:55000", "1515:1515", "1514:1514", "6514:6514"):
    if token in compose:
        fail(f"docker-compose.yml publishes forbidden management/backend port {token}")
if "/var/run/docker.sock" in compose:
    fail("Traefik/application plane must not mount the Docker daemon socket")
if re.search(r"(?m)^\s*image:\s*\S+:latest\s*$", compose):
    fail("docker-compose.yml contains mutable :latest image")
if '127.0.0.1:5601:5601' not in compose:
    fail("Wazuh dashboard must remain loopback-only in the Docker path")

relay = text("docker/syslog-relay/rsyslog.conf")
if 'StreamDriver.AuthMode="x509/name"' not in relay or "PermittedPeer" not in relay:
    fail("syslog relay must authenticate client certificates with an allowlist")
if 'StreamDriver.AuthMode="anon"' in relay:
    fail("anonymous TLS syslog authentication is forbidden")

for path in (ROOT / "terraform/vyos-fabric/configs").glob("*.boot"):
    body = path.read_text()
    if "plaintext-password" in body:
        fail(f"{path.relative_to(ROOT)} contains plaintext-password")
    if "service {\n    ssh" not in body and "ssh {" not in body:
        fail(f"{path.relative_to(ROOT)} does not explicitly configure SSH")
    if "disable-password-authentication" not in body:
        fail(f"{path.relative_to(ROOT)} does not disable SSH password authentication")
for name in ("fw-core.boot", "fw-dmz.boot"):
    body = text(f"terraform/vyos-fabric/configs/{name}")
    if re.search(r"firewall\s*\{[\s\S]*?name\s+[A-Z0-9_-]+\s*\{", body):
        fail(f"{name} appears to contain legacy pre-1.4 named firewall syntax")
    if "ipv4 {" not in body or "forward {" not in body or "filter {" not in body:
        fail(f"{name} lacks the reviewed VyOS 1.4 IPv4 forward filter")

k8s_files = list((ROOT / "k8s").glob("*.yaml")) + list((ROOT / "k8s").glob("*.yml"))
for path in k8s_files:
    body = path.read_text()
    if re.search(r"(?m)^\s*image:\s*\S+:latest\s*$", body):
        fail(f"{path.relative_to(ROOT)} contains mutable :latest image")
    if re.search(r"privileged:\s*true", body):
        fail(f"{path.relative_to(ROOT)} uses privileged: true")
    if "SYS_MODULE" in body:
        fail(f"{path.relative_to(ROOT)} grants SYS_MODULE")

wazuh_k8s = text("k8s/10-wazuh.yaml")
for component in ("indexer", "manager", "dashboard"):
    if f"wazuh/wazuh-{component}:4.14.6" not in wazuh_k8s:
        fail(f"Kubernetes Wazuh {component} is not aligned to 4.14.6")

if (ROOT / "COMPLIANCE-REPORT.md").exists():
    fail("tracked root COMPLIANCE-REPORT.md is stale-prone; generated evidence report must be authoritative")

if ERRORS:
    print("security static checks FAILED:", file=sys.stderr)
    for error in ERRORS:
        print(f" - {error}", file=sys.stderr)
    raise SystemExit(1)
print("OK: audited security regression invariants hold")
