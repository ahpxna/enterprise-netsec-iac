# k8s/ — Kubernetes path for the security plane

Experimental Kubernetes alternative for the SIEM/IDS/ZTNA layer. It shares
reviewed images and canonical IDS/SIEM configuration with the Compose path.
Source-level trust, NetworkPolicy, probes, generated assets, authenticated Wazuh
enrollment, and a least-privilege Traefik file-provider path are wired, but
**live-cluster parity is not claimed until `make k8s-smoke` passes**. The routed
network fabric remains Path A or Path B.

## Recommended cluster for testing

k3s is a practical single-node test target. Disable its bundled Traefik because
this repository deploys its own immutable Traefik release:

```bash
curl -sfL https://get.k3s.io | sh -s - --disable=traefik
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
```

Budget roughly 4 vCPU / 8 GiB free; Wazuh Indexer is the heaviest pod.

## Prerequisites and generated runtime state

Path C does **not** require Traefik CRDs. The public Traefik process uses only a
file provider and has no service-account token or Kubernetes Secret read
permission. This deliberately avoids turning a reverse-proxy compromise into
namespace-wide credential access.

Generate local credentials/PKI and Kubernetes runtime material:

```bash
make secrets
make wazuh-config
make k8s-runtime-secrets
make k8s-runtime-config
```

- `k8s/runtime-secrets.yaml` contains the ignored local credentials, Wazuh PKI,
  and ZTNA TLS keypair used by the cluster.
- `k8s/runtime-config.yaml` contains only non-secret operator settings derived
  from `.env` (`ORG_DOMAIN`, WireGuard port/endpoint/peer count), the Traefik
  file-provider routing configuration, and the matching WireGuard policy.
- Both files are gitignored. Do not replace them with committed plaintext
  Secrets or hard-coded environment-specific manifests.

Generated Kustomize-local assets remain derived from the canonical Docker-side
Wazuh/Suricata/Authentik source:

```bash
python scripts/render_k8s_assets.py
python scripts/render_k8s_assets.py --check
```

Compose and Kubernetes now use the same hostname-verified Wazuh indexer
identity (`wazuh-indexer`). `make wazuh-config` fails closed if an older local
certificate set does not contain the reviewed SAN/chain; follow
`docs/PKI-ROTATION.md` rather than disabling TLS hostname verification.

## Deploy

Use the Make target rather than raw `kubectl apply -k` so ignored runtime state
is rendered first:

```bash
make k8s-up
kubectl -n cxyz-security get pods -w
```

Then run the live checkpoint:

```bash
make k8s-smoke
```

The smoke gate waits for every core rollout, verifies the required static and
runtime NetworkPolicies, and proves Traefik loaded its protected file-provider
route by making a CA-verified HTTPS request that must receive an Authentik
redirect. It then iterates **every** Suricata DaemonSet pod, requires the stable
node-bound Wazuh agent identity to be enrolled, injects a unique synthetic EVE
marker, and requires each marker to reach Wazuh manager alerts. It is
intentionally not part of PR CI because it needs a real cluster/CNI.

## Access

```bash
kubectl -n cxyz-security get svc
# traefik NodePort 30080/30443
# Wazuh dashboard is ClusterIP-only; ordinary pod ingress is denied.
kubectl -n cxyz-security port-forward svc/wazuh-dashboard 5601:5601
```

WireGuard uses `hostNetwork`; its actual UDP listener, endpoint and peer count
come from the same `.env` contract as Compose. NetworkPolicy semantics for
host-network pods remain CNI-dependent and must be observed on the chosen
cluster.

## Security model and validation boundary

- Namespace ingress/egress defaults to deny. Application flows are explicit.
- Public Traefik has `automountServiceAccountToken: false`, uses no Kubernetes
  provider/RBAC, and gets only its file-provider ConfigMap plus the dedicated
  ZTNA TLS Secret mounted by kubelet. It cannot enumerate Authentik/Postgres/
  Wazuh Secrets through the Kubernetes API.
- Wazuh manager/indexer/dashboard use the same local CA/certificate trust
  material as Compose and verify the canonical `wazuh-indexer` server identity.
- Wazuh agent enrollment requires a generated registration password; the
  manager receives `authd.pass` from an ignored Secret instead of relying only
  on network location.
- Suricata writes EVE to a shared pod `emptyDir`; a same-pod Wazuh agent uses a
  stable `suricata-<nodeName>` identity and sends the secure agent channel over
  TCP/1514.
- Authentik provider/application/embedded-outpost state is declared by
  `docker/authentik/blueprints/cxyz-ztna.yaml`; domain-specific URLs are supplied
  from the runtime ConfigMap, not hard-coded in checked-in Kubernetes YAML.
- Suricata and WireGuard remain reviewed `hostNetwork` capability exceptions.
  They drop all capabilities first, add only required networking caps, disable
  privilege escalation, and use `RuntimeDefault` seccomp.
- Other vendor containers explicitly disable privilege escalation and use
  `RuntimeDefault`. `runAsNonRoot`, read-only root filesystems, and dropping all
  capabilities are not blanket-forced where upstream images have not been
  runtime-proven with those constraints.
- Wazuh vulnerability-feed egress is intentionally not widened to arbitrary
  Internet HTTPS. Path C does not claim fresh vulnerability-feed parity until a
  reviewed egress/offline-feed design is live-proven.

A successful static render is **not** Path C runtime evidence. Treat Path C as
source-validated until `make k8s-smoke` and the relevant live security controls
pass on the target cluster.
