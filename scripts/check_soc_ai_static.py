#!/usr/bin/env python3
"""Fail-closed static invariants for the SOC AI and response planes.

These checks encode the trust boundaries of docs/SOC-AI-ARCHITECTURE.md as machine
rules so a later edit cannot quietly move a credential, widen a network, or give a
model a path to a firewall.  They never start a service.
"""
from __future__ import annotations

import ast
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


compose = yaml.safe_load(text("docker-compose.yml"))
services = compose["services"]
AI_SERVICES = {
    "soc-ai-api": "soc_run_ai_api",
    "soc-feature-worker": "soc_run_feature",
    "soc-enrichment-worker": "soc_run_enrichment",
    "soc-decision": "soc_run_decision",
    "soc-response": "soc_run_response",
}

for name, own_volume in AI_SERVICES.items():
    service = services.get(name)
    if service is None:
        fail(f"missing SOC AI service {name}")
        continue
    if service.get("profiles") != ["soc-ai"]:
        fail(f"{name} must be profile-scoped to soc-ai")
    if service.get("ports"):
        fail(f"{name} must not publish a host port")
    if service.get("read_only") is not True or service.get("cap_drop") != ["ALL"]:
        fail(f"{name} must run with a read-only root filesystem and no capabilities")
    if "no-new-privileges:true" not in (service.get("security_opt") or []):
        fail(f"{name} must set no-new-privileges")
    if str(service.get("user")) != "10001:10001":
        fail(f"{name} must run as the unprivileged service user")
    volumes = [str(item) for item in service.get("volumes", [])]
    own = [item for item in volumes if item.startswith(f"{own_volume}:")]
    others = [
        item for item in volumes
        if re.match(r"soc_run_\w+:", item) and not item.startswith(f"{own_volume}:")
    ]
    if len(own) != 1 or not own[0].endswith(":ro"):
        fail(f"{name} must mount its own credential volume {own_volume} read-only")
    if others:
        fail(f"{name} must not mount another service's credential volume: {others}")
    for item in volumes:
        if "docker.sock" in item or ".key:" in item or "soc/certs" in item:
            fail(f"{name} must not bind-mount host key material directly: {item}")
    networks = service.get("networks")
    names = set(networks if isinstance(networks, (list, dict)) else [])
    allowed = {"cxyz_soc_backend"}
    if name == "soc-response":
        allowed = {"cxyz_soc_backend", "cxyz_response_egress", "cxyz_dc"}
    if names != allowed:
        fail(f"{name} networks must be exactly {sorted(allowed)}, found {sorted(names)}")
    probe = " ".join((service.get("healthcheck") or {}).get("test", []))
    if len(names) > 1 and "gethostname()" in probe:
        fail(f"{name} is multi-homed: its healthcheck must probe the address it binds, not whatever its hostname resolves to")

# Only the orchestrator may reach firewalls/Wazuh; the AI plane is backend-only.
for name in ("soc-ai-api", "soc-feature-worker", "soc-enrichment-worker", "soc-decision"):
    if set(services[name].get("networks", [])) != {"cxyz_soc_backend"}:
        fail(f"{name} must stay on the private SOC backend network only")
if compose["networks"]["cxyz_soc_backend"].get("internal") is not True:
    fail("the SOC backend network must remain internal")

init = services.get("soc-service-init", {})
init_text = yaml.safe_dump(init)
for forbidden in ("ca.key", "decision-ca.key", "ai-client-ca.key", "/source/ca.key"):
    if forbidden in init_text:
        fail(f"soc-service-init must never receive CA signing material ({forbidden})")
provision = text("soc/elasticsearch/provision-service-credentials.sh")
for line in provision.splitlines():
    if "signing.key" in line and "/out/decision" not in line:
        fail("the decision signing key may only be written to the decision volume")
if "/out/response" in provision and re.search(r"decision-key-1\.key.*?/out/response", provision):
    fail("the response orchestrator must receive verification keys only, never the signing key")
# Compose re-runs soc-service-init on every `up` of a dependent service. Rotating the API keys each time
# invalidated the key every running worker held (HTTP 401 until restarted; observed live).
for token, why in (("key_is_current", "keep an API key that still authenticates with an unchanged role"),
                   ("! -name es.key", "not wipe the kept API key with the rest of the credential directory"),
                   ('mv -f "$dest/.es.key.new" "$dest/es.key"', "replace a rotated key atomically")):
    if token not in provision:
        fail(f"provision-service-credentials.sh must {why}")
for path, call in (("soc/workers/common.py", "authorization=FileAuthorization(key_file)"),
                   ("response/service/__main__.py", 'authorization=FileAuthorization(cfg["api_key_file"])')):
    if call not in text(path):
        fail(f"{path}: Elasticsearch clients must re-read a rotated credential file (FileAuthorization)")
if "keys/decision-key-1.pub" not in provision:
    fail("the orchestrator must be provisioned with the decision public key")

# Dockerfile: locked base, hash-locked dependencies, unprivileged user.
dockerfile = text("docker/soc-python/Dockerfile")
lock_text = text("supply-chain/images.lock.yml")
base = re.search(r"^FROM\s+(\S+)", dockerfile, re.M).group(1)
if base not in lock_text:
    fail("the SOC image base is not an audited image in supply-chain/images.lock.yml")
if "--require-hashes" not in dockerfile:
    fail("the SOC image must install dependencies with --require-hashes")
if not re.search(r"^USER\s+soc\s*$", dockerfile, re.M):
    fail("the SOC image must drop to the unprivileged soc user")
lock = text("requirements-soc-service.lock")
blocks = re.split(r"\n(?=\S)", lock.strip())
for block in blocks:
    if "==" in block.split("\n")[0] and "--hash=sha256:" not in block:
        fail(f"locked requirement without a hash: {block.splitlines()[0]}")
for requirement in re.findall(r"^([A-Za-z0-9_.-]+)==", text("requirements-soc-service.in"), re.M):
    if not re.search(rf"^{re.escape(requirement)}==", lock, re.M | re.I):
        fail(f"requirements-soc-service.lock lacks {requirement}")

# Python import boundaries.
def imports(path: pathlib.Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module.split(".")[0])
    return found


for path in (ROOT / "ai").rglob("*.py"):
    bad = imports(path) & {"response", "soc", "requests", "urllib3", "httpx", "paramiko"}
    if bad:
        fail(f"{path.relative_to(ROOT)}: the AI plane must not import {sorted(bad)}")
for path in (ROOT / "response").rglob("*.py"):
    if imports(path) & {"ai", "sklearn", "torch", "joblib"}:
        fail(f"{path.relative_to(ROOT)}: the response plane must not import model code")
for path in list((ROOT / "response/adapters").glob("*.py")):
    if imports(path) & {"subprocess", "socket", "urllib", "http", "requests"}:
        fail(f"{path.relative_to(ROOT)}: adapters must have no network or process surface")

# No shell escape hatch anywhere in privileged code.
for pattern in ("shell=True", "os.system(", "os.popen(", "eval(", "exec("):
    for path in [*(ROOT / "response").rglob("*.py"), ROOT / "docker/enforcer/nft_enforcer.py",
                 ROOT / "docker/wazuh/active-response/cxyz_endpoint_isolation.py"]:
        body = path.read_text()
        if re.search(rf"(?<![\w.]){re.escape(pattern)}", body):
            fail(f"{path.relative_to(ROOT)} uses {pattern}")
for path in [*(ROOT / "response").rglob("*.py"), *(ROOT / "soc/workers").glob("*.py")]:
    body = path.read_text()
    if re.search(r"verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False|--insecure|curl -k", body):
        fail(f"{path.relative_to(ROOT)} disables TLS verification")

# Deployment defaults: nothing enforces automatically out of the box.
for kind in ("response", "decision"):
    for deployment in sorted((ROOT / "response/deployments").glob(f"*/{kind}.yaml")):
        if yaml.safe_load(deployment.read_text()).get("mode") != "observe":
            fail(f"{deployment.relative_to(ROOT)} must default to observe mode")
for secret_word in ("password:", "secret:", "api_key:"):
    for deployment in (ROOT / "response/deployments").rglob("*.yaml"):
        if secret_word in deployment.read_text().lower():
            fail(f"{deployment.relative_to(ROOT)} must name credential files, never contain secrets")

# Firewall containment: sets with timeouts, drops before established-accept, agent mgmt-only.
for node in ("fw-core", "fw-dmz"):
    nft = text(f"clab/configs/{node}.nft")
    if "set soc_blocklist  { type ipv4_addr; flags timeout; }" not in nft:
        fail(f"{node}.nft lost the timeout-bearing soc_blocklist set")
    forward = nft.split("chain forward", 1)[1]
    first_block = forward.find("@soc_blocklist")
    established = forward.find("ct state established,related accept")
    if first_block < 0 or first_block > established:
        fail(f"{node}.nft must drop SOC_BLOCKLIST traffic before accepting established flows")
    if 'iifname "eth0" ip saddr 10.1.1.0/24 tcp dport 9443 accept' not in nft:
        fail(f"{node}.nft must expose the enforcement agent on the management network only")
for node in ("fw-core", "fw-dmz"):
    boot = text(f"terraform/vyos-fabric/configs/{node}.boot")
    for token in ("address-group SOC_BLOCKLIST", "prerouting {", "raw {", "SOC containment: blocked source"):
        if token not in boot:
            fail(f"{node}.boot lost SOC containment token: {token}")
    if "service https" in boot or "https {" in boot:
        fail(f"{node}.boot must not embed the HTTPS API (needs PKI/keys applied by Ansible)")

# Enforcement agent: fixed operations only.
agent = text("docker/enforcer/nft_enforcer.py")
for route in ('"/v1/add"', '"/v1/remove"', '"/v1/contains"'):
    if route not in agent:
        fail(f"nft enforcer lost route {route}")
if agent.count('self.path == "/v1/') != 3:
    fail("nft enforcer must expose exactly three POST routes")
if "ssl.CERT_REQUIRED" not in agent:
    fail("nft enforcer must require client certificates")

# Policies and Elasticsearch roles.
for policy in sorted((ROOT / "response/policies").glob("*.yaml")):
    body = yaml.safe_load(policy.read_text())
    protections = body["defaults"]["protections"]
    if "172.16.50.1" not in protections["protected_ips"] or "10.1.1.0/24" not in protections["protected_networks"]:
        fail(f"{policy.name} dropped a protected infrastructure target")
    if "10.255.0.0/16" not in protections["protected_networks"]:
        fail(f"{policy.name} must protect the routed transit 10.255.0.0/16 (campus traffic is NATed onto it)")
    honeypot = [r for p in body["policies"] if p["action"] == "block_ip" for r in p["when"]["require_any"] if r["type"] == "honeypot"]
    if any(r.get("min_severity", 0) < 5 for r in honeypot):
        fail(f"{policy.name}: a honeypot signal needs min_severity >= 5 (a bare connection must not corroborate)")
roles = {n: yaml.safe_load(text(f"soc/elasticsearch/{n}-role.json")) for n in
         ("feature-engine", "ai-event-writer", "decision-engine", "response-orchestrator")}
for name, role in roles.items():
    for grant in role["indices"]:
        if "soc-raw-*" in grant["names"] and name != "feature-engine" and "read" in grant["privileges"]:
            fail(f"{name} role must not read raw payloads")
        if {"index", "write", "update", "delete", "all", "create"} & set(grant["privileges"]):
            fail(f"{name} role grants a mutating privilege beyond create_doc")

for path in ("scripts/provision_wazuh_response_user.py",):
    body = text(path)
    if "CERT_NONE" in body or "check_hostname" in body:
        fail(f"{path} must verify TLS")
if '"actions": ["active-response:command", "agent:read", "syscheck:read"]' not in text("scripts/provision_wazuh_response_user.py"):
    fail("the Wazuh response identity must keep exactly its three least-privilege actions")

# Kubernetes (Path C): same trust boundaries as the Compose services.
K8S_SERVICES = {
    "soc-ai-api": "cxyz-soc-ai-api",
    "soc-feature-worker": "cxyz-soc-feature",
    "soc-enrichment-worker": "cxyz-soc-enrichment",
    "soc-decision": "cxyz-soc-decision",
    "soc-response": "cxyz-soc-response",
}
k8s_documents = [
    document
    for name in ("k8s/52-soc-ai.yaml", "k8s/40-network-policies.yaml")
    for document in yaml.safe_load_all(text(name))
    if document
]
k8s_workloads = {d["metadata"]["name"]: d for d in k8s_documents if d["kind"] == "Deployment"}
k8s_policies = {d["metadata"]["name"]: d for d in k8s_documents if d["kind"] == "NetworkPolicy"}
for name, secret in K8S_SERVICES.items():
    workload = k8s_workloads.get(name)
    if workload is None:
        fail(f"k8s/52-soc-ai.yaml lacks Deployment {name}")
        continue
    pod = workload["spec"]["template"]["spec"]
    if pod.get("automountServiceAccountToken") is not False:
        fail(f"{name} must not automount a ServiceAccount token")
    if any(pod.get(key) for key in ("hostNetwork", "hostPID", "hostIPC")):
        fail(f"{name} must not use the host namespaces")
    for container in pod["containers"]:
        context = container.get("securityContext", {})
        if (context.get("readOnlyRootFilesystem") is not True or context.get("runAsNonRoot") is not True
                or context.get("runAsUser") != 10001 or context.get("allowPrivilegeEscalation") is not False
                or context.get("capabilities", {}).get("drop") != ["ALL"]):
            fail(f"{name} must run read-only, non-root (10001), without privilege escalation or capabilities")
        if container.get("image") != "cxyz/soc-python:local" or any(p.get("hostPort") for p in container.get("ports", [])):
            fail(f"{name} must use the locked SOC image and publish no host port")
    secrets = {v["secret"]["secretName"] for v in pod.get("volumes", []) if "secret" in v}
    if secrets != {secret}:
        fail(f"{name} must mount only its own credential Secret {secret}, found {sorted(secrets)}")
    if name not in k8s_policies or k8s_policies[name]["spec"]["podSelector"]["matchLabels"] != {"app": name}:
        fail(f"{name} needs its own NetworkPolicy")
    if workload["spec"].get("replicas") != 1 or workload["spec"].get("strategy", {}).get("type") != "Recreate":
        if name != "soc-ai-api":
            fail(f"{name} owns SQLite state: exactly one Recreate replica")
for name, policy in k8s_policies.items():
    if name in K8S_SERVICES and name != "soc-response":
        if any("ipBlock" in peer for rule in policy["spec"].get("egress", []) for peer in rule.get("to", [])):
            fail(f"{name} must not have egress outside the cluster; only soc-response reaches firewalls")
model_volumes = [v for v in k8s_workloads["soc-ai-api"]["spec"]["template"]["spec"]["volumes"] if "persistentVolumeClaim" in v]
if not any(v["persistentVolumeClaim"].get("readOnly") is True and v["persistentVolumeClaim"]["claimName"] == "soc-model-registry"
           for v in model_volumes):
    fail("the inference API must mount the model registry read-only")
if "loaders" in text("k8s/kustomization.yaml"):
    fail("the model loader Pod must not be part of the standing kustomization")
loader = yaml.safe_load(text("k8s/loaders/soc-model-loader.yaml"))
loader_pod = loader["spec"]
loader_context = loader_pod["containers"][0]["securityContext"]
if (loader["kind"] != "Pod" or loader_pod.get("automountServiceAccountToken") is not False
        or loader_context.get("readOnlyRootFilesystem") is not True or loader_context.get("runAsUser") != 10001
        or loader_context.get("capabilities", {}).get("drop") != ["ALL"]
        or loader_context.get("allowPrivilegeEscalation") is not False):
    fail("the model loader Pod must be read-only, non-root, capability-free and without a ServiceAccount token")
if {v["persistentVolumeClaim"]["claimName"] for v in loader_pod["volumes"] if "persistentVolumeClaim" in v} != {"soc-model-registry"}:
    fail("the model loader Pod may mount only the model registry volume")
if any("secret" in v or "hostPath" in v for v in loader_pod["volumes"]) or loader_pod.get("hostNetwork"):
    fail("the model loader Pod must mount no Secret or host path and use no host network")
secret_renderer = text("scripts/render_k8s_runtime_secrets.py")
response_block = secret_renderer.split('secret("cxyz-soc-response"', 1)[1].split("]", 1)[0]
if "signing.key" in response_block or "decision-key-1.key" in response_block:
    fail("the k8s response Secret must contain verification keys only, never the signing key")
if secret_renderer.count("decision/decision-key-1.key") != 1:
    fail("the decision signing key must be written to exactly one Secret")

if ERRORS:
    print("SOC AI static checks FAILED:", file=sys.stderr)
    for error in ERRORS:
        print(f" - {error}", file=sys.stderr)
    raise SystemExit(1)
print("OK: SOC AI/response plane retains isolation, least privilege, locked supply chain and fail-closed defaults")
