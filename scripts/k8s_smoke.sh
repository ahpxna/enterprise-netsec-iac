#!/usr/bin/env bash
# Live Path C checkpoint. Not part of static PR CI: it requires a real cluster.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
ns="${CXYZ_K8S_NAMESPACE:-cxyz-security}"
timeout="${CXYZ_K8S_ROLLOUT_TIMEOUT:-240s}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 2; }; }
need kubectl
need python3
need curl

# Re-check the cluster-specific API policy against the live Service and API
# endpoints before trusting Traefik readiness. This catches CNI/DNAT drift.
python3 scripts/render_k8s_runtime_policy.py --check

rollout() {
  local resource="$1"
  echo "==> rollout $resource"
  kubectl -n "$ns" rollout status "$resource" --timeout="$timeout"
}

for workload in \
  statefulset/wazuh-indexer deployment/wazuh-manager deployment/wazuh-dashboard \
  statefulset/authentik-postgres deployment/authentik-server \
  deployment/authentik-worker deployment/traefik deployment/wireguard daemonset/suricata; do
  rollout "$workload"
done

echo "==> required NetworkPolicies"
for policy in default-deny allow-cluster-dns traefik-ingress-egress traefik-kubernetes-api \
  authentik-server authentik-worker authentik-postgres \
  wazuh-indexer wazuh-manager wazuh-dashboard suricata-wazuh-agent wireguard-vpn ztna-demo-app; do
  kubectl -n "$ns" get networkpolicy "$policy" >/dev/null
done

# Process health is not enough: prove the KubernetesCRD provider has watched the
# namespace and loaded the protected IngressRoute. Port-forward avoids relying
# on a particular NodePort routing implementation while still traversing the
# deployed Traefik pod, TLS secret, Middleware, Authentik outpost and route.
echo "==> Traefik CRD/ZTNA route over trusted TLS"
domain="companyxyz.lab"
if [[ -f .env ]]; then
  candidate="$(python3 scripts/env_exec.py --env-file .env --print-var ORG_DOMAIN 2>/dev/null || true)"
  [[ -z "$candidate" ]] || domain="$candidate"
fi
host="app.${domain}"
ca_file="docker/zero-trust-gateway/certs/ca.crt"
[[ -s "$ca_file" ]] || { echo "missing ZTNA CA: $ca_file" >&2; exit 1; }
pf_log="$(mktemp)"
headers="$(mktemp)"
kubectl -n "$ns" port-forward service/traefik 18443:443 >"$pf_log" 2>&1 &
pf_pid=$!
cleanup() {
  kill "$pf_pid" 2>/dev/null || true
  rm -f "$pf_log" "$headers"
}
trap cleanup EXIT
route_ready=0
for _ in $(seq 1 20); do
  if ! kill -0 "$pf_pid" 2>/dev/null; then
    cat "$pf_log" >&2
    echo "Traefik port-forward exited early" >&2
    exit 1
  fi
  : >"$headers"
  if curl --silent --show-error --max-time 3 \
      --cacert "$ca_file" \
      --resolve "${host}:18443:127.0.0.1" \
      --output /dev/null --dump-header "$headers" \
      "https://${host}:18443/" 2>/dev/null; then
    if grep -Eq '^HTTP/[^ ]+ (301|302|303|307|308)( |$)' "$headers" \
        && grep -Eqi '^location: .*(sso\.|/if/flow/)' "$headers"; then
      route_ready=1
      break
    fi
  fi
  sleep 1
done
[[ "$route_ready" -eq 1 ]] || {
  echo "Traefik is healthy but the protected ZTNA IngressRoute did not return an authentication redirect" >&2
  cat "$headers" >&2 || true
  exit 1
}
kill "$pf_pid" 2>/dev/null || true
wait "$pf_pid" 2>/dev/null || true
trap - EXIT
rm -f "$pf_log" "$headers"

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

# Inject one valid synthetic EVE JSON line into the same shared file Suricata
# writes. This is intentionally a pipeline checkpoint, not a fake IDS packet:
# it proves EVE -> Wazuh-agent -> manager -> project rule/alert transport.
marker="CXYZ-K8S-SURICATA-MARKER-$(date +%s)"
echo "==> Suricata EVE -> Wazuh manager alert pipeline"
kubectl -n "$ns" exec "$suricata_pod" -c suricata -- sh -c \
  "printf '%s\\n' '{\"event_type\":\"alert\",\"src_ip\":\"192.0.2.10\",\"dest_ip\":\"198.51.100.10\",\"alert\":{\"signature_id\":999999,\"signature\":\"${marker}\",\"category\":\"CompanyXYZ smoke\",\"severity\":1}}' >> /var/log/suricata/eve.json"
alert_seen=0
for _ in $(seq 1 20); do
  if kubectl -n "$ns" exec deployment/wazuh-manager -- sh -c \
      "grep -Fq '${marker}' /var/ossec/logs/alerts/alerts.json 2>/dev/null"; then
    alert_seen=1
    break
  fi
  sleep 3
done
[[ "$alert_seen" -eq 1 ]] || { echo "synthetic Suricata EVE marker did not reach Wazuh manager alerts" >&2; exit 1; }

echo "OK: Path C live smoke checkpoint passed"
