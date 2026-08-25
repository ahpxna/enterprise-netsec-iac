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
    name = metadata.get("name", "")

    if kind in {"Deployment", "StatefulSet", "DaemonSet"}:
        pod_spec = document.get("spec", {}).get("template", {}).get("spec", {})
        if pod_spec.get("hostPID") is True:
            fail(f"Kubernetes workload {name} must not use hostPID")
        if pod_spec.get("hostIPC") is True:
            fail(f"Kubernetes workload {name} must not use hostIPC")
        for volume in pod_spec.get("volumes", []) or []:
            if isinstance(volume, dict) and "hostPath" in volume:
                fail(f"Kubernetes workload {name} must not mount hostPath volumes")

        host_network_allowlist = {("DaemonSet", "suricata"), ("Deployment", "wireguard")}
        if pod_spec.get("hostNetwork") is True and (kind, name) not in host_network_allowlist:
            fail(f"Kubernetes workload {name} uses hostNetwork outside the reviewed allowlist")

        capability_allowlist = {
            ("DaemonSet", "suricata", "suricata"): {"NET_ADMIN", "NET_RAW", "SYS_NICE"},
            ("Deployment", "wireguard", "wireguard"): {"NET_ADMIN"},
        }
        pod_containers = list(pod_spec.get("containers", []) or []) + list(pod_spec.get("initContainers", []) or [])
        for container in pod_containers:
            if not isinstance(container, dict):
                continue
            container_name = container.get("name", "")
            security_context = container.get("securityContext", {}) or {}
            if security_context.get("privileged") is True:
                fail(f"Kubernetes container {name}/{container_name} must not be privileged")
            added = set((security_context.get("capabilities", {}) or {}).get("add", []) or [])
            allowed = capability_allowlist.get((kind, name, container_name), set())
            unexpected = added - allowed
            if unexpected:
                fail(
                    f"Kubernetes container {name}/{container_name} adds unreviewed capabilities: "
                    f"{', '.join(sorted(unexpected))}"
                )
            if name == "traefik":
                args = container.get("args", []) or []
                if any(str(arg).strip().lower() == "--api.insecure=true" for arg in args):
                    fail("Traefik Kubernetes dashboard must not enable api.insecure")

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

# Path C must retain namespace micro-segmentation and health semantics.
kustomization = yaml.safe_load(text("k8s/kustomization.yaml"))
if "40-network-policies.yaml" not in (kustomization.get("resources") or []):
    fail("Kubernetes NetworkPolicy manifest is not included by k8s/kustomization.yaml")
network_policies = [doc for doc in k8s_documents if doc.get("kind") == "NetworkPolicy"]
policy_names = {doc.get("metadata", {}).get("name") for doc in network_policies}
required_policies = {
    "default-deny", "allow-cluster-dns", "traefik-ingress-egress",
    "authentik-server", "authentik-worker", "authentik-postgres",
    "authentik-redis", "wazuh-indexer", "wazuh-manager",
    "wazuh-dashboard", "suricata-wazuh-agent", "wireguard-vpn",
}
missing_policies = required_policies - policy_names
if missing_policies:
    fail(f"Kubernetes NetworkPolicy set is incomplete: {', '.join(sorted(missing_policies))}")
default_deny = next((doc for doc in network_policies if doc.get("metadata", {}).get("name") == "default-deny"), {})
default_spec = default_deny.get("spec", {})
if default_spec.get("podSelector") != {} or set(default_spec.get("policyTypes", [])) != {"Ingress", "Egress"}:
    fail("Kubernetes default-deny must select every pod and deny both ingress and egress by default")

probe_requirements = {
    ("StatefulSet", "wazuh-indexer", "wazuh-indexer"),
    ("Deployment", "wazuh-manager", "wazuh-manager"),
    ("Deployment", "wazuh-dashboard", "wazuh-dashboard"),
    ("Deployment", "traefik", "traefik"),
    ("StatefulSet", "authentik-postgres", "postgres"),
    ("Deployment", "authentik-redis", "redis"),
    ("Deployment", "authentik-server", "authentik-server"),
    ("Deployment", "authentik-worker", "authentik-worker"),
    ("Deployment", "wireguard", "wireguard"),
}
for document in k8s_documents:
    kind = document.get("kind")
    name = document.get("metadata", {}).get("name", "")
    if kind not in {"Deployment", "StatefulSet", "DaemonSet"}:
        continue
    containers = document.get("spec", {}).get("template", {}).get("spec", {}).get("containers", []) or []
    for container in containers:
        key = (kind, name, container.get("name", ""))
        if key in probe_requirements:
            for probe in ("startupProbe", "readinessProbe", "livenessProbe"):
                if probe not in container:
                    fail(f"Kubernetes workload {name}/{container.get('name')} lacks {probe}")

suricata_k8s = text("k8s/20-suricata.yaml")
for token in (
    "dnsPolicy: ClusterFirstWithHostNet",
    "name: wazuh-agent",
    "wazuh/wazuh-agent:4.14.6",
    "WAZUH_MANAGER_SERVER",
    "WAZUH_REGISTRATION_SERVER",
    "WAZUH_AGENT_NAME",
    "<location>/var/log/suricata/eve.json</location>",
    "<protocol>tcp</protocol>",
):
    if token not in suricata_k8s:
        fail(f"Kubernetes Suricata-to-Wazuh agent delivery lost required wiring: {token}")
if "agent-events, port: 1514, protocol: TCP" not in text("k8s/10-wazuh.yaml"):
    fail("Kubernetes Wazuh secure agent event service must use TCP/1514")

# Collection resolution is exact so a future Galaxy release cannot silently
# change lint/runtime semantics for the same repository commit.
requirements = yaml.safe_load(text("ansible/requirements.yml"))["collections"]
expected_collections = {
    "community.docker": "5.2.2",
    "community.general": "13.3.0",
    "ansible.posix": "2.2.2",
    "vyos.vyos": "6.0.0",
}
resolved = {item.get("name"): str(item.get("version")) for item in requirements}
for collection, version in expected_collections.items():
    if resolved.get(collection) != version:
        fail(f"Ansible collection {collection} must remain pinned to {version}")


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
