# k8s/ — Kubernetes path for the security plane

Experimental Kubernetes alternative for the SIEM/IDS/ZTNA layer. It shares
reviewed images and canonical IDS/SIEM configuration with the Compose path.
Source-level trust, NetworkPolicy, probes, and generated assets are now wired,
but **live-cluster parity is not claimed until `make k8s-smoke` passes**.
The routed network fabric remains Path A or Path B.

## Recommended cluster for testing

k3s is a practical single-node test target. Disable its bundled Traefik because
this repository deploys its own immutable Traefik release:

```bash
curl -sfL https://get.k3s.io | sh -s - --disable=traefik
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
```

Budget roughly 4 vCPU / 8 GiB free; Wazuh Indexer is the heaviest pod.

## One-time prerequisites

1. Install the CRDs matching the repository's Traefik 3.7.11 intent:

   ```bash
   kubectl apply -f https://raw.githubusercontent.com/traefik/traefik/v3.7.11/docs/content/reference/dynamic-configuration/kubernetes-crd-definition-v1.yml
   ```

2. Generate local credentials/PKI and Kubernetes runtime material:

   ```bash
   make secrets
   make wazuh-config
   make k8s-runtime-secrets
   ```

   `k8s/runtime-secrets.yaml` is generated from the same local trust material
   as Compose and is gitignored. Do not replace this with a committed plaintext
   Secret.

3. Generated Kustomize-local assets are derived from the canonical Docker-side
   Wazuh/Suricata/Authentik source:

   ```bash
   python scripts/render_k8s_assets.py
   python scripts/render_k8s_assets.py --check
   ```

   The renderer adapts Compose DNS names such as `wazuh.indexer` to Kubernetes
   Service DNS such as `wazuh-indexer`; CI rejects drift.

## Deploy

Use the Make target rather than raw `kubectl apply -k`. Traefik needs to watch
Kubernetes CRDs, but a static `egress: TCP/443 anywhere` exception is forbidden.
`k8s-runtime-policy` resolves the actual `kubernetes.default` ClusterIP and
creates an ignored `/32` NetworkPolicy first.

```bash
make k8s-up
kubectl -n cxyz-security get pods -w
```

Then run the live checkpoint:

```bash
make k8s-smoke
```

The smoke gate waits for every core rollout, verifies the required static and
runtime NetworkPolicies, checks Suricata EVE creation and the Wazuh sidecar, and
requires the manager to see the Suricata agent. It is intentionally not part of
PR CI because it needs a real cluster.

## Access

```bash
kubectl -n cxyz-security get svc
# traefik NodePort 30080/30443
# Wazuh dashboard is ClusterIP-only; ordinary pod ingress is denied.
kubectl -n cxyz-security port-forward svc/wazuh-dashboard 5601:5601
```

## Security model and validation boundary

- Namespace ingress/egress defaults to deny. Application flows are explicit.
- Traefik uses namespace Role/RoleBinding and a namespace-scoped CRD provider;
  its Kubernetes API egress is a runtime-rendered exact `/32`, not arbitrary
  HTTPS egress.
- Wazuh manager/indexer/dashboard are wired to the same local CA/certificate
  trust material used by Compose. The generated manager/dashboard config uses
  Kubernetes Service DNS.
- Suricata writes EVE to a shared pod `emptyDir`; a same-pod Wazuh agent reads
  the file and uses the secure agent channel TCP/1514 to the manager.
- Authentik provider/application/embedded-outpost state is declared by
  `docker/authentik/blueprints/cxyz-ztna.yaml` and mirrored into the K8s
  ConfigMap. No manual first-run UI state is part of the intended deployment.
- Suricata and WireGuard remain reviewed `hostNetwork` capability exceptions.
  They drop all capabilities first, add only their required networking caps,
  disable privilege escalation, and use `RuntimeDefault` seccomp. NetworkPolicy
  behavior for host-network pods remains CNI-dependent and must be observed on
  the chosen cluster.
- Other vendor containers explicitly disable privilege escalation and use
  `RuntimeDefault`. `runAsNonRoot`, read-only root filesystems, and dropping all
  capabilities are not blanket-forced where upstream images have not been
  runtime-proven with those constraints.

A successful static render is **not** Path C runtime evidence. Treat Path C as
source-validated until `make k8s-smoke` and the relevant live security controls
pass on the target cluster.
