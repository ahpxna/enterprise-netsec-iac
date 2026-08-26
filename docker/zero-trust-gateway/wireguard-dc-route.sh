#!/usr/bin/env bash
# LinuxServer custom-init hook: make the reviewed VPN peer subnet reach only
# the approved DC CIDR through this multi-homed WireGuard container.
set -euo pipefail
peer_cidr="${VPN_PEER_SUBNET:-10.13.13.0/24}"
admin_cidr="${VPN_ADMIN_SUBNET:-172.16.50.0/24}"
probe_ip="${VPN_ADMIN_PROBE_IP:-172.16.50.1}"

dc_iface="$(ip route get "$probe_ip" | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
[[ -n "$dc_iface" ]] || { echo "cannot resolve DC interface for $probe_ip" >&2; exit 1; }

iptables -C FORWARD -i wg0 -o "$dc_iface" -s "$peer_cidr" -d "$admin_cidr" -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i wg0 -o "$dc_iface" -s "$peer_cidr" -d "$admin_cidr" -j ACCEPT
iptables -C FORWARD -i "$dc_iface" -o wg0 -s "$admin_cidr" -d "$peer_cidr" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "$dc_iface" -o wg0 -s "$admin_cidr" -d "$peer_cidr" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -C POSTROUTING -s "$peer_cidr" -d "$admin_cidr" -o "$dc_iface" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s "$peer_cidr" -d "$admin_cidr" -o "$dc_iface" -j MASQUERADE

echo "CXYZ WireGuard DC route: $peer_cidr -> $admin_cidr via $dc_iface"
