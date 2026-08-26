#!/usr/bin/env python3
"""Fail-closed repository invariants for previously audited security regressions."""
from __future__ import annotations

import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMAGE_LOCK = yaml.safe_load((ROOT / "supply-chain/images.lock.yml").read_text())["images"]
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

if service_networks("ztna-demo-app") & service_networks("authentik-postgres"):
    fail("protected ZTNA demo application must not share a Docker network with the identity database")
if service_networks("ztna-demo-app") & service_networks("authentik-redis"):
    fail("protected ZTNA demo application must not share a Docker network with the identity cache")
if service_networks("traefik").isdisjoint(service_networks("ztna-demo-app")):
    fail("Traefik must retain a private network path to the protected ZTNA demo application")
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
    "wazuh-dashboard", "suricata-wazuh-agent", "wireguard-vpn", "ztna-demo-app",
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
    IMAGE_LOCK["wazuh-agent"]["pinned_ref"],
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
    expected = IMAGE_LOCK[f"wazuh-{component}"]["pinned_ref"]
    if expected not in wazuh_k8s:
        fail(f"Kubernetes Wazuh {component} is not aligned to the audited image-index pin")


# ---------------------------------------------------------------------------
# Assurance/lifecycle invariants added after the v11 audit.
# ---------------------------------------------------------------------------
if "dmz-web" in services:
    fail("Docker ZTNA demo must not reuse the canonical fabric asset name dmz-web")
if "ztna-demo-app" not in services:
    fail("Docker ZTNA demo application is missing")
if service_networks("ztna-demo-app") & service_networks("authentik-postgres"):
    fail("ZTNA demo application must not share a network with Authentik PostgreSQL")
if service_networks("ztna-demo-app") & service_networks("authentik-redis"):
    fail("ZTNA demo application must not share a network with Authentik Redis")

blueprint_path = ROOT / "docker/authentik/blueprints/cxyz-ztna.yaml"
if not blueprint_path.exists():
    fail("Authentik ZTNA bootstrap blueprint is missing")
else:
    blueprint = blueprint_path.read_text()
    for token in (
        "authentik_providers_proxy.proxyprovider",
        "authentik_core.application",
        "authentik_outposts.outpost",
        "forward_single",
        "CXYZ_AUTHENTIK_APP_URL",
        "CXYZ_AUTHENTIK_SSO_URL",
        "authentik Embedded Outpost",
    ):
        if token not in blueprint:
            fail(f"Authentik ZTNA blueprint lost declarative bootstrap token: {token}")
for service_name in ("authentik-server", "authentik-worker"):
    volumes = services.get(service_name, {}).get("volumes", []) or []
    if not any("cxyz-ztna.yaml:/blueprints/cxyz-ztna.yaml:ro" in str(v) for v in volumes):
        fail(f"{service_name} must mount the declarative Authentik ZTNA blueprint")

dynamic_ztna = text("docker/zero-trust-gateway/dynamic.yml")
for token in (
    "/outpost.goauthentik.io/",
    "ztna-demo-app:8080",
    "/run/ztna/tls.crt",
    "/run/ztna/tls.key",
):
    if token not in dynamic_ztna:
        fail(f"Traefik ZTNA config lost required declarative/TLS token: {token}")
hardening_test = text("tests/validation/test_hardening.py")
if "--insecure" in hardening_test:
    fail("ZTNA live validation must verify the lab CA instead of using curl --insecure")
for token in ("--cacert", "vpn_probe_admin_ssh_reachable", "vpn_probe_route_uses_wg0"):
    if token not in hardening_test:
        fail(f"live hardening assurance lost required proof: {token}")

wireguard_networks = service_networks("wireguard")
if "cxyz_dc" not in wireguard_networks or "cxyz_edge" not in wireguard_networks:
    fail("WireGuard must bridge the VPN ingress plane to the approved DC management target network")
probe = services.get("vpn-probe", {})
if not probe or probe.get("ports"):
    fail("vpn-probe must exist as an unexposed real peer fixture")
if "cxyz_edge" not in service_networks("vpn-probe"):
    fail("vpn-probe must reach the WireGuard endpoint only through the edge network")
wg_volumes = [str(v) for v in services.get("wireguard", {}).get("volumes", []) or []]
if not any("wireguard-dc-route.sh:/custom-cont-init.d/40-cxyz-dc-route.sh:ro" in v for v in wg_volumes):
    fail("WireGuard server must install the reviewed DC forwarding/NAT init hook")
wg_route_script = text("docker/zero-trust-gateway/wireguard-dc-route.sh")
for token in ("VPN_PEER_SUBNET", "VPN_ADMIN_SUBNET", "-i wg0", "MASQUERADE", "ESTABLISHED,RELATED"):
    if token not in wg_route_script:
        fail(f"WireGuard DC routing hook lost required routing/firewall token: {token}")

# TIME-01 must measure the host kernel clock that Docker workloads actually use.
if "chronyd" in text("docker/server1/supervisord.conf") or "chrony" in text("docker/server1/Dockerfile"):
    fail("Path A server1 container must not run an independent chronyd instance")
if "scripts/host_time_status.py" not in hardening_test:
    fail("TIME-01 Path A must verify host NTS/clock state via host_time_status.py")
if "-x" in text("docker/server1/supervisord.conf"):
    fail("chronyd -x tracking-only mode is forbidden as TIME-01 enforcement")

# Untrusted Path A endpoints retain Docker management only for bootstrap, then
# drop eth0 after their data-plane route exists. This avoids the previous
# network-mode:none provisioning regression while closing the alternate path.
intent = yaml.safe_load(text("intent/fabric.yaml"))
for endpoint in ("pc1", "dmz-web"):
    if intent.get("nodes", {}).get(endpoint, {}).get("disable_management_after_boot") is not True:
        fail(f"{endpoint} must disable its Docker management interface after bootstrap")
clab_model = yaml.safe_load(text("clab/companyxyz.clab.yml"))
for endpoint in ("pc1", "dmz-web"):
    commands = clab_model.get("topology", {}).get("nodes", {}).get(endpoint, {}).get("exec", []) or []
    if "sh -c 'ip link set eth0 down'" not in commands:
        fail(f"rendered Path A endpoint {endpoint} does not drop its bootstrap management interface")
segmentation_test = text("tests/validation/test_segmentation.py")
for token in ("pc1_management_interface_down", "dmz_management_interface_down", "10.1.1.50"):
    if token not in segmentation_test:
        fail(f"Path A segmentation test lost alternate-management-path proof: {token}")

# HRD controls use one canonical managed-node set and effective sshd settings.
node_sets = text("tests/validation/node_sets.py")
for endpoint in ("pc1", "pc4", "dmz-web"):
    if endpoint not in node_sets:
        fail(f"HRD managed-node set is missing {endpoint}")
if '"sshd", "-T"' not in hardening_test:
    fail("HRD-01 must validate effective sshd configuration with sshd -T")
if "clab-companyxyz-dmz-web" not in text("ansible/inventory/hosts.yml"):
    fail("canonical dmz-web endpoint is missing from Path A Ansible inventory")

# Path C: namespace-scoped Traefik RBAC and explicit micro-segmentation.
traefik_k8s = text("k8s/30-traefik.yaml")
for forbidden in ("kind: ClusterRole\n", "kind: ClusterRoleBinding\n", "--providers.kubernetesingress=true"):
    if forbidden in traefik_k8s:
        fail(f"Traefik Kubernetes scope widened unexpectedly: {forbidden.strip()}")
for required in (
    "kind: Role\n",
    "kind: RoleBinding\n",
    "--providers.kubernetescrd.namespaces=cxyz-security",
    "--providers.kubernetescrd.allowCrossNamespace=false",
    "--providers.kubernetescrd.disableClusterScopeResources=true",
):
    if required not in traefik_k8s:
        fail(f"Traefik Kubernetes namespace-scope invariant missing: {required.strip()}")

policy_by_name = {doc.get("metadata", {}).get("name"): doc for doc in network_policies}
dashboard_policy = policy_by_name.get("wazuh-dashboard", {})
if dashboard_policy.get("spec", {}).get("ingress") != []:
    fail("Wazuh dashboard NetworkPolicy must deny ordinary pod-network ingress")
for policy_name in ("traefik-ingress-egress", "authentik-server", "authentik-worker", "wazuh-manager"):
    policy = policy_by_name.get(policy_name, {})
    for rule in policy.get("spec", {}).get("egress", []) or []:
        if "to" not in rule and any(port.get("port") == 443 for port in rule.get("ports", []) or []):
            fail(f"{policy_name} must not have destination-unbounded HTTPS egress")

runtime_policy_renderer = text("scripts/render_k8s_runtime_policy.py")
for token in ("kubernetes", "jsonpath={.spec.clusterIP}", "ipBlock", "cidr: {api_ip}/32", "port: 443"):
    if token not in runtime_policy_renderer:
        fail(f"Path C runtime API policy renderer lost exact-destination token: {token}")
makefile_text = text("Makefile")
for token in ("k8s-runtime-policy", "k8s/runtime-networkpolicy.yaml", "k8s-smoke"):
    if token not in makefile_text:
        fail(f"Path C deployment lifecycle lost required target/artifact: {token}")
if "k8s/runtime-networkpolicy.yaml" not in text(".gitignore").splitlines():
    fail("cluster-specific Kubernetes API NetworkPolicy must remain ignored")

# Privileged networking workloads must start from an empty capability set and
# use the default seccomp profile; other reviewed workloads must at least
# refuse privilege escalation.
for document in k8s_documents:
    kind = document.get("kind")
    name = document.get("metadata", {}).get("name", "")
    if kind not in {"Deployment", "StatefulSet", "DaemonSet"}:
        continue
    pod_spec = document.get("spec", {}).get("template", {}).get("spec", {}) or {}
    for container in pod_spec.get("containers", []) or []:
        c_name = container.get("name", "")
        sc = container.get("securityContext", {}) or {}
        if sc.get("allowPrivilegeEscalation") is not False:
            fail(f"Kubernetes container {name}/{c_name} must explicitly disable privilege escalation")
        if (kind, name, c_name) in capability_allowlist:
            caps = sc.get("capabilities", {}) or {}
            if set(caps.get("drop", []) or []) != {"ALL"}:
                fail(f"privileged networking container {name}/{c_name} must drop ALL before adding reviewed capabilities")
        if (sc.get("seccompProfile", {}) or {}).get("type") != "RuntimeDefault":
            fail(f"Kubernetes container {name}/{c_name} must use seccompProfile RuntimeDefault")

# Path C Wazuh trust graph is source-defined even though live cluster parity
# remains a separate runtime checkpoint.
wazuh_k8s = text("k8s/10-wazuh.yaml")
if "https://wazuh.indexer:9200" in text("k8s/generated/ossec.conf"):
    fail("generated Kubernetes Wazuh manager config still uses Compose DNS wazuh.indexer")
if "https://wazuh-indexer:9200" not in text("k8s/generated/ossec.conf"):
    fail("generated Kubernetes Wazuh manager config must target Service DNS wazuh-indexer")

for token in (
    "cxyz-wazuh-tls",
    "root-ca.pem",
    "admin.pem",
    "admin-key.pem",
    "FILEBEAT_SSL_VERIFICATION_MODE",
    "SSL_CERTIFICATE_AUTHORITIES",
    "WAZUH_API_URL",
    "cxyz-wazuh-security-config",
):
    if token not in wazuh_k8s:
        fail(f"Kubernetes Wazuh trust/config parity lost token: {token}")

# Image inventory must be completely immutable at merge time.
for component, entry in IMAGE_LOCK.items():
    if entry.get("status") == "deferred" or not entry.get("pinned_ref"):
        fail(f"image-lock component {component} remains mutable/deferred")

# Certificate lifecycle: leaves renew before expiry; CA requires an explicit
# overlap/rotation operation instead of silently expiring in place.
secret_script = text("scripts/gen-secrets.sh")
for token in ("openssl x509 -checkend", 'cert_has_days "$relay_certs/relay.crt" 30', 'cert_has_days "$relay_certs/ca.crt" 90', "zero-trust-gateway/certs"):
    if token not in secret_script:
        fail(f"certificate lifecycle guard missing token: {token}")
if "docker/zero-trust-gateway/certs/" not in text(".gitignore"):
    fail("local ZTNA CA/private key directory must be gitignored")

# Deterministic local image builds use an immutable base plus a fixed Debian
# archive snapshot; CI must actually build both images.
for dockerfile in ("docker/server1/Dockerfile", "docker/syslog-relay/Dockerfile"):
    body = text(dockerfile)
    if "snapshot.debian.org/archive/debian/" not in body or "DEBIAN_SNAPSHOT=" not in body:
        fail(f"{dockerfile} does not pin the Debian package repository snapshot")

libvirt_versions = text("terraform/libvirt/versions.tf")
if 'version = "0.8.1"' not in libvirt_versions or 'version = "~> 0.8.1"' in libvirt_versions:
    fail("legacy libvirt provider must remain exact-pinned to 0.8.1 until its verified lockfile is generated")
if "providers lock -platform=linux_amd64" not in makefile_text or "-platform=darwin_arm64" not in makefile_text:
    fail("Makefile must retain the cross-platform terraform-lock helper")

for required_path in ("scripts/check_yaml_syntax.py", "scripts/k8s_smoke.sh", "docs/AUTHENTIK-UPGRADE.md", "docs/PKI-ROTATION.md", "supply-chain/lifecycle.yml"):
    if not (ROOT / required_path).exists():
        fail(f"required assurance/lifecycle artifact is missing: {required_path}")
lifecycle_path = ROOT / "supply-chain/lifecycle.yml"
if lifecycle_path.exists():
    lifecycle = yaml.safe_load(lifecycle_path.read_text()) or {}
    authentik_lifecycle = (lifecycle.get("components") or {}).get("authentik", {})
    if authentik_lifecycle.get("state") != "migration-required":
        fail("unsupported Authentik 2024.8 debt must remain explicitly marked migration-required until the runbook is completed")
    if authentik_lifecycle.get("runbook") != "docs/AUTHENTIK-UPGRADE.md":
        fail("Authentik lifecycle debt must reference the controlled sequential-upgrade runbook")

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
