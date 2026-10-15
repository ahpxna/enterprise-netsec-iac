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

# Re-check operator-configurable Path C settings before trusting the deployed routes.
python3 scripts/render_k8s_runtime_config.py --check

rollout() {
  local resource="$1"
  echo "==> rollout $resource"
  kubectl -n "$ns" rollout status "$resource" --timeout="$timeout"
}

for workload in \
  statefulset/wazuh-indexer deployment/wazuh-manager deployment/wazuh-dashboard \
  statefulset/authentik-postgres deployment/authentik-server \
  deployment/authentik-worker deployment/traefik deployment/wireguard daemonset/suricata \
  statefulset/elasticsearch deployment/kibana deployment/soc-ai-api deployment/soc-feature-worker \
  deployment/soc-enrichment-worker deployment/soc-decision deployment/soc-response; do
  rollout "$workload"
done

echo "==> SOC bootstrap/setup Jobs completed"
for job in soc-elastic-bootstrap soc-kibana-setup; do
  kubectl -n "$ns" wait --for=condition=complete "job/$job" --timeout="$timeout"
done

echo "==> required NetworkPolicies"
for policy in default-deny allow-cluster-dns traefik-ingress-egress wireguard-vpn \
  authentik-server authentik-worker authentik-postgres \
  wazuh-indexer wazuh-manager wazuh-dashboard suricata-wazuh-agent ztna-demo-app \
  elasticsearch kibana soc-elastic-bootstrap soc-kibana-setup soc-ai-api soc-feature-worker \
  soc-enrichment-worker soc-decision soc-response; do
  kubectl -n "$ns" get networkpolicy "$policy" >/dev/null
done

# Process health is not enough: prove the least-privilege file provider loaded
# the protected route. Port-forward avoids relying on a particular NodePort
# implementation while still traversing Traefik, trusted TLS and Authentik.
echo "==> Traefik file-provider/ZTNA route over trusted TLS"
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
  echo "Traefik is healthy but the protected ZTNA route did not return an authentication redirect" >&2
  cat "$headers" >&2 || true
  exit 1
}
kill "$pf_pid" 2>/dev/null || true
wait "$pf_pid" 2>/dev/null || true
trap - EXIT
rm -f "$pf_log" "$headers"

# Automatic response must stay in observe mode unless an operator deliberately changed it.
echo "==> SOC response plane defaults to observe mode"
for config in response.yaml decision.yaml; do
  kubectl -n "$ns" get configmap cxyz-soc-response-config -o "jsonpath={.data.${config//./\\.}}" \
    | grep -Eq '^mode: observe$' \
    || echo "WARNING: ${config} is not in observe mode (enforcement is enabled)" >&2
done

echo "==> SOC AI approved-model digest is configured"
digest="$(kubectl -n "$ns" get configmap cxyz-soc-ai-settings -o jsonpath='{.data.SOC_AI_METADATA_SHA256}')"
[[ "$digest" =~ ^[a-f0-9]{64}$ ]] || { echo "SOC_AI_METADATA_SHA256 is not set in cxyz-soc-ai-settings (make k8s-soc-model, then re-render)" >&2; exit 1; }

echo "==> Elasticsearch refuses anonymous requests over TLS"
kubectl -n "$ns" exec elasticsearch-0 -- sh -c \
  'curl -sS --cacert /usr/share/elasticsearch/config/certs/ca.crt -o /dev/null -w "%{http_code}" https://localhost:9200' \
  | grep -Eq '^401$' || { echo "Elasticsearch did not require authentication" >&2; exit 1; }

mapfile -t suricata_pods < <(
  kubectl -n "$ns" get pods -l app=suricata \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
)
[[ "${#suricata_pods[@]}" -gt 0 ]] || { echo "no Suricata pods found" >&2; exit 1; }

# DaemonSet readiness is not enough: every sensor must have a stable node-bound
# Wazuh identity and prove its own EVE -> agent -> manager alert pipeline.
for suricata_pod in "${suricata_pods[@]}"; do
  node_name="$(kubectl -n "$ns" get pod "$suricata_pod" -o jsonpath='{.spec.nodeName}')"
  [[ -n "$node_name" ]] || { echo "$suricata_pod has no assigned node" >&2; exit 1; }
  agent_name="suricata-${node_name}"

  echo "==> Suricata EVE + Wazuh sidecar: $suricata_pod ($agent_name)"
  kubectl -n "$ns" exec "$suricata_pod" -c suricata -- sh -c 'test -e /var/log/suricata/eve.json'
  kubectl -n "$ns" exec "$suricata_pod" -c wazuh-agent -- sh -c \
    'test -x /var/ossec/bin/wazuh-control && /var/ossec/bin/wazuh-control status'

  echo "==> Suricata agent enrollment visibility: $agent_name"
  seen=0
  for _ in $(seq 1 12); do
    if kubectl -n "$ns" exec deployment/wazuh-manager -- /var/ossec/bin/agent_control -lc 2>/dev/null \
        | grep -Fqi "$agent_name"; then
      seen=1
      break
    fi
    sleep 5
  done
  [[ "$seen" -eq 1 ]] || { echo "Wazuh manager does not report $agent_name after retries" >&2; exit 1; }

  marker_node="$(printf '%s' "$node_name" | tr -c 'A-Za-z0-9_.-' '_')"
  marker="CXYZ-K8S-SURICATA-MARKER-${marker_node}-$(date +%s)-${RANDOM}"
  echo "==> Suricata EVE -> Wazuh manager alert pipeline: $agent_name"
  kubectl -n "$ns" exec "$suricata_pod" -c suricata -- sh -c \
    "printf '%s\n' '{\"event_type\":\"alert\",\"src_ip\":\"192.0.2.10\",\"dest_ip\":\"198.51.100.10\",\"alert\":{\"signature_id\":999999,\"signature\":\"${marker}\",\"category\":\"CompanyXYZ smoke\",\"severity\":1}}' >> /var/log/suricata/eve.json"
  alert_seen=0
  for _ in $(seq 1 20); do
    if kubectl -n "$ns" exec deployment/wazuh-manager -- sh -c \
        "grep -Fq '${marker}' /var/ossec/logs/alerts/alerts.json 2>/dev/null"; then
      alert_seen=1
      break
    fi
    sleep 3
  done
  [[ "$alert_seen" -eq 1 ]] || { echo "synthetic EVE marker from $agent_name did not reach Wazuh alerts" >&2; exit 1; }
done

echo "OK: Path C live smoke checkpoint passed"
