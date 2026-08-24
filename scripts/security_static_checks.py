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


# Path B Terraform state must never contain long-lived routing credentials.
tf_main = text("terraform/vyos-fabric/main.tf")
tf_vars = text("terraform/vyos-fabric/variables.tf")
if "var.routing_secrets" in tf_main or 'variable "routing_secrets"' in tf_vars:
    fail("Terraform Path B must not receive long-lived BGP/OSPF credentials")
for token in ("BOOTSTRAP_DISABLED_${node_name}_ospf", "BOOTSTRAP_DISABLED_${node_name}_bgp1", "BOOTSTRAP_DISABLED_${node_name}_bgp2"):
    if token not in tf_main:
        fail("Path B first boot must use per-node fail-closed routing authentication tokens")

vyos_role = text("ansible/roles/vyos_edge/tasks/main.yml")
if "backup: true" in vyos_role:
    fail("VyOS Day-2 reconciliation must not write secret-bearing configuration backups")
if "vyos_edge_result.commands" in vyos_role:
    fail("VyOS Day-2 must not print secret-bearing command lists")
if "no_log: true" not in vyos_role:
    fail("VyOS secret-bearing reconciliation is not log-redacted")

local_env = ROOT / ".env"
if local_env.exists() and (local_env.stat().st_mode & 0o077):
    fail(".env contains credentials and must be mode 0600")

wazuh_k8s = text("k8s/10-wazuh.yaml")
for component in ("indexer", "manager", "dashboard"):
    if f"wazuh/wazuh-{component}:4.14.6" not in wazuh_k8s:
        fail(f"Kubernetes Wazuh {component} is not aligned to 4.14.6")

root_report = ROOT / "COMPLIANCE-REPORT.md"
if root_report.exists():
    pointer = root_report.read_text()
    if "NOT COMPLIANCE EVIDENCE" not in pointer or "evidence/PATH-B-COMPLIANCE-REPORT.md" not in pointer:
        fail("tracked root COMPLIANCE-REPORT.md may only be a non-evidence pointer to generated reports")

if ERRORS:
    print("security static checks FAILED:", file=sys.stderr)
    for error in ERRORS:
        print(f" - {error}", file=sys.stderr)
    raise SystemExit(1)
print("OK: audited security regression invariants hold")
