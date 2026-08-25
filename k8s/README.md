# k8s/ — Kubernetes path for the security plane

Experimental Kubernetes alternative for the SIEM/IDS/ZTNA layer. It shares
reviewed images plus selected IDS/SIEM rules with the Compose path, but it is
**not yet security-control-equivalent to Docker Compose**. StatefulSets,
DaemonSets, and Traefik's native Kubernetes CRD provider are used where
appropriate. The network fabric (containerlab or `terraform/vyos-fabric`) is
unaffected either way.

## Recommended cluster for testing

**k3s** (single binary, low overhead, ships Traefik by default — disable
the bundled Traefik with `--disable=traefik` because this repository deploys a
pinned version here). A single VM/laptop with 4 vCPU / 8GB RAM free
(on top of whatever the network fabric is using) is enough for this
manifest set at rest; Wazuh's indexer is the heaviest single pod
(request 1.5Gi / limit 2Gi).

```bash
curl -sfL https://get.k3s.io | sh -s - --disable=traefik
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
```

## One-time prerequisites

1. **Traefik CRDs** (IngressRoute/Middleware) — required before
   `30-traefik.yaml` / `31-authentik.yaml` will apply cleanly:
   ```bash
   kubectl apply -f https://raw.githubusercontent.com/traefik/traefik/v3.1/docs/content/reference/dynamic-configuration/kubernetes-crd-definition-v1.yml
   ```
2. **Secrets** — copy the template and fill real values (never commit
   the real file):
   ```bash
   cp 01-secrets.yaml.example 01-secrets.yaml
   $EDITOR 01-secrets.yaml   # or generate with kubectl create secret --from-literal
   kubectl apply -f 01-secrets.yaml
   ```
3. **Generated Kustomize-local assets** — Kustomize's default root-only
   loader intentionally rejects `../docker/...` references. Keep the Docker
   IDS/SIEM files canonical and refresh their checked-in Kubernetes mirrors:
   ```bash
   python scripts/render_k8s_assets.py
   ```
   `make k8s-up` performs this refresh automatically and CI runs `--check`
   before rendering the manifests with the default load restrictions.

## Deploy

```bash
kubectl apply -k k8s/
kubectl -n cxyz-security get pods -w
```

## Access

```bash
kubectl -n cxyz-security get svc
# traefik NodePort 30080/30443
# Wazuh dashboard is ClusterIP-only; use kubectl port-forward when needed.
```

## Current validation status and known gaps

- **Live-cluster validation is still pending.** Static rendering now covers
  default-deny NetworkPolicy, core workload startup/readiness/liveness probes,
  and Suricata EVE forwarding through a same-pod Wazuh agent, but first-cluster
  deployment is still required before Path C can claim runtime parity.
- **Wazuh parity is incomplete.** The Kubernetes manifests still need the
  full certificate/API/config wiring used by the Compose deployment before
  this path can claim the same authenticated manager/indexer/dashboard trust.
- **Suricata-to-Wazuh delivery is now wired but not yet live-proven.** A
  Wazuh-agent sidecar shares Suricata's EVE `emptyDir`, enrolls with the manager,
  and sends events over the Wazuh secure agent channel on TCP/1514. The manager
  must still gain the full certificate/API parity described above before Path C
  can make the same end-to-end trust claim as Compose.
- **NetworkPolicy now defaults the namespace to deny ingress/egress** and opens
  the reviewed Traefik/Auth/PostgreSQL/Redis/Wazuh flows plus DNS. Suricata and
  WireGuard are `hostNetwork` exceptions; enforcement of NetworkPolicy for
  host-network pods is CNI-dependent and must be checked on the chosen cluster.
- Core Wazuh, Authentik, Traefik, PostgreSQL, Redis, and WireGuard workloads now
  have startup/readiness/liveness probes. `PriorityClass` and
  `PodDisruptionBudget` remain future availability work.
- WireGuard runs with `hostNetwork: true` and `NET_ADMIN`, but not
  `privileged: true`. Treat that capability as a documented exception and
  keep the rest of the namespace under a stricter Pod Security policy.
- Authentik server/worker explicitly share the same PostgreSQL user/database
  and Redis service names; a full working outpost
  (the `/outpost.goauthentik.io/auth/traefik` forward-auth endpoint used
  by `31-authentik.yaml`'s Middleware) needs a one-time setup flow inside
  the Authentik UI (create the embedded outpost, an application, and a
  provider) — that's an Authentik product step, not something Terraform/
  Ansible/kubectl can pre-bake without the Authentik API bootstrap flow,
  which isn't wired up yet. Document this as a manual first-run step.
