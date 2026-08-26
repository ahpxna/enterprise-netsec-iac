#!/usr/bin/env bash
# Live Path C checkpoint. Not part of static PR CI: it requires a real cluster.
set -euo pipefail
ns="${CXYZ_K8S_NAMESPACE:-cxyz-security}"
timeout="${CXYZ_K8S_ROLLOUT_TIMEOUT:-240s}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 2; }; }
need kubectl

rollout() {
  local resource="$1"
  echo "==> rollout $resource"
  kubectl -n "$ns" rollout status "$resource" --timeout="$timeout"
}

for workload in \
  statefulset/wazuh-indexer deployment/wazuh-manager deployment/wazuh-dashboard \
  deployment/authentik-postgres deployment/authentik-redis deployment/authentik-server \
  deployment/authentik-worker deployment/traefik deployment/wireguard daemonset/suricata; do
  rollout "$workload"
done

echo "==> required NetworkPolicies"
for policy in default-deny allow-cluster-dns traefik-ingress-egress traefik-kubernetes-api \
  authentik-server authentik-worker authentik-postgres authentik-redis \
  wazuh-indexer wazuh-manager wazuh-dashboard suricata-wazuh-agent wireguard-vpn ztna-demo-app; do
  kubectl -n "$ns" get networkpolicy "$policy" >/dev/null
done

suricata_pod="$(kubectl -n "$ns" get pods -l app=suricata -o jsonpath='{.items[0].metadata.name}')"
[[ -n "$suricata_pod" ]] || { echo "no Suricata pod found" >&2; exit 1; }

echo "==> Suricata EVE + Wazuh sidecar"
kubectl -n "$ns" exec "$suricata_pod" -c suricata -- sh -c 'test -e /var/log/suricata/eve.json'
kubectl -n "$ns" exec "$suricata_pod" -c wazuh-agent -- sh -c 'test -x /var/ossec/bin/wazuh-control && /var/ossec/bin/wazuh-control status'

echo "==> Suricata agent enrollment visibility"
seen=0
for _ in $(seq 1 12); do
  if kubectl -n "$ns" exec deployment/wazuh-manager -- /var/ossec/bin/agent_control -lc 2>/dev/null | grep -qi 'suricata'; then
    seen=1
    break
  fi
  sleep 5
done
[[ "$seen" -eq 1 ]] || { echo "Wazuh manager does not report the Suricata agent after retries" >&2; exit 1; }

echo "OK: Path C live smoke checkpoint passed"
