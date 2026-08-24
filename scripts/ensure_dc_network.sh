#!/usr/bin/env bash
# Create the one DC broadcast domain shared by Docker and the selected fabric.
# Host forwarding/routes are stateful and can be restored by cleanup_dc_network.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
network_name="cxyz_dc"
bridge_name="br-cxyz-dc"
subnet="172.16.50.0/24"
gateway="172.16.50.253"
firewall_gateway="172.16.50.254"
state_dir="$ROOT/.cxyz-state"
state_file="$state_dir/dc-network.env"
mkdir -p "$state_dir"

if (( EUID == 0 )); then SUDO=(); else SUDO=(sudo); fi

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

capture_state_once() {
  [[ -f "$state_file" ]] && return
  local ipf route1 route2
  ipf="$(sysctl -n net.ipv4.ip_forward)"
  route1="$(ip route show 10.255.0.0/16 || true)"
  route2="$(ip route show 192.168.0.0/16 || true)"
  umask 077
  {
    printf 'IP_FORWARD_BEFORE=%q\n' "$ipf"
    printf 'ROUTE_INFRA_BEFORE_B64=%q\n' "$(b64 "$route1")"
    printf 'ROUTE_CAMPUS_BEFORE_B64=%q\n' "$(b64 "$route2")"
  } > "$state_file"
}

ensure_return_routes() {
  capture_state_once
  "${SUDO[@]}" sysctl -w net.ipv4.ip_forward=1 >/dev/null
  "${SUDO[@]}" ip route replace 10.255.0.0/16 via "$firewall_gateway" dev "$bridge_name"
  "${SUDO[@]}" ip route replace 192.168.0.0/16 via "$firewall_gateway" dev "$bridge_name"
}

if docker network inspect "$network_name" >/dev/null 2>&1; then
  actual_bridge="$(docker network inspect -f '{{ index .Options "com.docker.network.bridge.name" }}' "$network_name")"
  actual_subnet="$(docker network inspect -f '{{ (index .IPAM.Config 0).Subnet }}' "$network_name")"
  if [[ "$actual_bridge" != "$bridge_name" || "$actual_subnet" != "$subnet" ]]; then
    echo "existing $network_name does not match canonical DC network" >&2
    echo "expected bridge=$bridge_name subnet=$subnet" >&2
    echo "actual   bridge=$actual_bridge subnet=$actual_subnet" >&2
    exit 1
  fi
  echo "$network_name already matches canonical DC network"
  ensure_return_routes
  exit 0
fi

docker network create \
  --driver bridge \
  --subnet "$subnet" \
  --gateway "$gateway" \
  --opt "com.docker.network.bridge.name=$bridge_name" \
  --opt "com.docker.network.bridge.enable_ip_masquerade=false" \
  "$network_name" >/dev/null

echo "created $network_name on $bridge_name ($subnet)"
ensure_return_routes
