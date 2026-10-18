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
        # addrgenmode is set after creation: newer kernels (6.16) reject it inside
        # `ip link add` with "Address family not supported by protocol".
        ip link add "$device" link "$parent" type macvlan mode bridge
        ip link set dev "$device" addrgenmode random
    fi
    ip link set dev "$device" address "$mac"
    ip address replace "$vip" dev "$device"
    ip link set dev "$device" up
    sysctl -w "net.ipv4.conf.${parent}.ignore_routes_with_linkdown=1" >/dev/null
    # vrrpd protodowns the macvlan on the backup router; the kernel only skips that
    # linkdown connected route when the macvlan itself carries this flag.
    sysctl -w "net.ipv4.conf.${device}.ignore_routes_with_linkdown=1" >/dev/null
    # The VIP is a local address on both routers. Without these, the parent answers
    # ARP for it with its own MAC (backup included), so hosts bypass the VRRP MAC.
    sysctl -w "net.ipv4.conf.${parent}.arp_ignore=1" >/dev/null
    sysctl -w "net.ipv4.conf.${parent}.arp_announce=2" >/dev/null
}

# containerlab starts the container before it wires the veth links, so wait for
# them instead of exiting (which makes the deploy fail with "namespace path not available").
wait_for_links() {
    local tries=0 dev
    for dev in "$@"; do
        until [[ -e "/sys/class/net/${dev}" ]]; do
            (( ++tries > 600 )) && { echo "cxyz-frr-start: ${dev} never appeared" >&2; exit 1; }
            sleep 0.2
        done
    done
}

wait_for_links eth2 eth3
ensure_vrrp_interface eth2 10 00:00:5e:00:01:0a 192.168.10.254/24
ensure_vrrp_interface eth3 40 00:00:5e:00:01:28 192.168.40.254/24

exec /usr/lib/frr/docker-start
