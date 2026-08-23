#!/usr/bin/env bash
# Create the one DC broadcast domain shared by Docker and containerlab.
set -euo pipefail

network_name="cxyz_dc"
bridge_name="br-cxyz-dc"
subnet="172.16.50.0/24"
gateway="172.16.50.253"

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
