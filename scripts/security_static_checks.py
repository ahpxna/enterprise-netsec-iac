#!/usr/bin/env python3
"""Fail-closed repository invariants for previously audited security regressions."""
from __future__ import annotations

import pathlib
import re
import sys

import yaml

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

compose_model = yaml.safe_load(compose)
services = compose_model.get("services", {})
relay_volumes = services.get("syslog-relay", {}).get("volumes", [])
relay_mounts = [item if isinstance(item, str) else str(item) for item in relay_volumes]
if any("docker/syslog-relay/certs:/run/certs" in item for item in relay_mounts):
    fail("syslog relay must not receive the entire PKI directory")
if any("ca.key" in item or "/clients" in item for item in relay_mounts):
    fail("syslog relay must never receive the CA signing key or client private-key directory")
for required in ("ca.crt:/run/certs/ca.crt:ro", "relay.crt:/run/certs/relay.crt:ro", "relay.key:/run/certs/relay.key:ro"):
    if not any(required in item for item in relay_mounts):
        fail(f"syslog relay is missing least-privilege certificate mount {required}")

def service_networks(name: str) -> set[str]:
    value = services.get(name, {}).get("networks", [])
    if isinstance(value, dict):
        return set(value)
    return set(value or [])

if service_networks("dmz-web") & service_networks("authentik-postgres"):
    fail("protected DMZ application must not share a Docker network with the identity database")
if service_networks("dmz-web") & service_networks("authentik-redis"):
    fail("protected DMZ application must not share a Docker network with the identity cache")
if service_networks("traefik").isdisjoint(service_networks("dmz-web")):
    fail("Traefik must retain a private network path to the protected DMZ application")
if service_networks("traefik").isdisjoint(service_networks("authentik-server")):
    fail("Traefik must retain a private network path to Authentik forward-auth")
identity_env = services.get("authentik-server", {}).get("environment", {})
for key in ("AUTHENTIK_POSTGRESQL__HOST", "AUTHENTIK_POSTGRESQL__USER", "AUTHENTIK_POSTGRESQL__NAME", "AUTHENTIK_REDIS__HOST"):
    if key not in identity_env:
        fail(f"Authentik server lacks explicit dependency setting {key}")
postgres_env = services.get("authentik-postgres", {}).get("environment", {})
if postgres_env.get("POSTGRES_USER") != "authentik":
    fail("Authentik PostgreSQL must create the same explicit database user Authentik uses")

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
k8s_documents: list[dict] = []
for path in k8s_files:
    body = path.read_text()
    if re.search(r"(?m)^\s*image:\s*\S+:latest\s*$", body):
        fail(f"{path.relative_to(ROOT)} contains mutable :latest image")
    if re.search(r"privileged:\s*true", body):
        fail(f"{path.relative_to(ROOT)} uses privileged: true")
    if "SYS_MODULE" in body:
        fail(f"{path.relative_to(ROOT)} grants SYS_MODULE")
    for document in yaml.safe_load_all(body):
        if isinstance(document, dict):
            k8s_documents.append(document)

kustomization = text("k8s/kustomization.yaml")
if "../" in kustomization:
    fail("Kustomize inputs must remain inside k8s/ so default LoadRestrictionsRootOnly works")
if "k8s/01-secrets.yaml" not in text(".gitignore").splitlines():
    fail("documented local Kubernetes Secret file k8s/01-secrets.yaml must be gitignored")

for document in k8s_documents:
    kind = document.get("kind")
    metadata = document.get("metadata", {})
    if kind == "Service" and metadata.get("name") == "traefik":
        spec = document.get("spec", {})
        if spec.get("type") == "NodePort":
            exposed_names = {port.get("name") for port in spec.get("ports", [])}
            if "dashboard" in exposed_names:
                fail("Traefik dashboard must not receive an automatically allocated Kubernetes NodePort")
    if kind == "IngressRoute" and metadata.get("name") == "authentik":
        if "tls" not in document.get("spec", {}):
            fail("Authentik websecure IngressRoute must explicitly enable TLS")

authentik_k8s = text("k8s/31-authentik.yaml")
for key in ("POSTGRES_USER", "AUTHENTIK_POSTGRESQL__USER", "AUTHENTIK_POSTGRESQL__NAME", "AUTHENTIK_REDIS__HOST"):
    if key not in authentik_k8s:
        fail(f"Kubernetes Authentik deployment lacks explicit dependency setting {key}")


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
