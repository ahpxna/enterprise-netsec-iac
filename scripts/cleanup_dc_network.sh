#!/usr/bin/env bash
# Restore only host networking state changed by ensure_dc_network.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
state_file="$ROOT/.cxyz-state/dc-network.env"
bridge_name="br-cxyz-dc"
firewall_gateway="172.16.50.254"
[[ -f "$state_file" ]] || exit 0
# shellcheck disable=SC1090 -- file is generated locally by ensure_dc_network.sh with %q
source "$state_file"
if (( EUID == 0 )); then SUDO=(); else SUDO=(sudo); fi

decode() { [[ -n "$1" ]] && printf '%s' "$1" | base64 -d || true; }
restore_route() {
  local prefix="$1" encoded="$2" previous current
  previous="$(decode "$encoded")"
  current="$(ip route show "$prefix" || true)"
  if [[ "$current" == *"via $firewall_gateway dev $bridge_name"* ]]; then
    if [[ -n "$previous" ]]; then
      read -r -a words <<< "$previous"
      "${SUDO[@]}" ip route replace "${words[@]}"
    else
      "${SUDO[@]}" ip route del "$prefix" via "$firewall_gateway" dev "$bridge_name" 2>/dev/null || true
    fi
  fi
}
restore_route 10.255.0.0/16 "${ROUTE_INFRA_BEFORE_B64:-}"
restore_route 192.168.0.0/16 "${ROUTE_CAMPUS_BEFORE_B64:-}"
"${SUDO[@]}" sysctl -w "net.ipv4.ip_forward=${IP_FORWARD_BEFORE:-0}" >/dev/null
rm -f "$state_file"
rmdir "$ROOT/.cxyz-state" 2>/dev/null || true
