# k8s/ — Kubernetes path for the security plane

Alternative to `docker-compose.yml` for the SIEM/IDS/ZTNA layer, same
images and config as the compose file, restructured into real k8s
primitives (StatefulSets for stateful stores, DaemonSet for the IDS
sensor, Traefik's native Kubernetes CRD provider instead of its Docker
provider). Use this if you specifically want the security plane running
on Kubernetes rather than plain Docker Compose — the network fabric
(containerlab or `terraform/vyos-fabric`) is unaffected either way.

## Recommended cluster for testing

**k3s** (single binary, low overhead, ships Traefik by default — disable
the bundled Traefik with `--disable=traefik` since we deploy our own
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
3. **ConfigMaps from existing docker/ files** — `kustomization.yaml`'s
   `configMapGenerator` does this automatically on `kubectl apply -k .`,
   so the Wazuh rules/decoders and Suricata rules stay a single source
   of truth shared with the docker-compose path.

## Deploy

```bash
kubectl apply -k k8s/
kubectl -n cxyz-security get pods -w
```

## Access

```bash
kubectl -n cxyz-security get svc
# wazuh-dashboard NodePort 30561  -> https://<node-ip>:30561
# traefik         NodePort 30080/30443
```

## Known gaps / not yet tested

- **Never applied to a real cluster in this session** (no k8s available
  in the sandbox that built this) — manifests are schema-valid YAML
  (checked) but not proven against the actual Wazuh/Authentik/Traefik
  container entrypoints on k8s. Expect at least one iteration on
  resource limits / readiness probes once you run it.
- No `PriorityClass`, `NetworkPolicy`, or `PodDisruptionBudget` yet —
  fine for a lab, not for anything you'd call production.
- WireGuard runs `privileged: true` + `hostNetwork: true`, which is
  normal for a VPN concentrator but means the cluster's PodSecurity
  admission must allow `privileged` in this namespace (k3s default does).
- `authentik-server` alone is enough to boot, but a full working outpost
  (the `/outpost.goauthentik.io/auth/traefik` forward-auth endpoint used
  by `31-authentik.yaml`'s Middleware) needs a one-time setup flow inside
  the Authentik UI (create the embedded outpost, an application, and a
  provider) — that's an Authentik product step, not something Terraform/
  Ansible/kubectl can pre-bake without the Authentik API bootstrap flow,
  which isn't wired up yet. Document this as a manual first-run step.
