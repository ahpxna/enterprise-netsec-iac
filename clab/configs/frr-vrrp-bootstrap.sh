#!/usr/bin/env bash
# FRR's VRRP daemon does not create its Linux macvlan devices.  Build the
# shared virtual-MAC interfaces before docker-start launches vrrpd.
set -euo pipefail

ensure_vrrp_interface() {
    local parent="$1" vrid="$2" mac="$3" vip="$4"
    local parent_ifindex device
    parent_ifindex="$(cat "/sys/class/net/${parent}/ifindex")"
    # FRR discovers externally-created macvlans by this canonical name:
    # vrrp4-<parent-ifindex>-<vrid>.
    device="vrrp4-${parent_ifindex}-${vrid}"

    if ! ip link show dev "$device" >/dev/null 2>&1; then
        ip link add "$device" link "$parent" addrgenmode random type macvlan mode bridge
    fi
    ip link set dev "$device" address "$mac"
    ip address replace "$vip" dev "$device"
    ip link set dev "$device" up
    sysctl -w "net.ipv4.conf.${parent}.ignore_routes_with_linkdown=1" >/dev/null
}

ensure_vrrp_interface eth2 10 00:00:5e:00:01:0a 192.168.10.254/24
ensure_vrrp_interface eth3 40 00:00:5e:00:01:28 192.168.40.254/24

exec /usr/lib/frr/docker-start
