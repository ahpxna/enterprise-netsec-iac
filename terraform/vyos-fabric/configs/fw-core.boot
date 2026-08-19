/* fw-core — VyOS translation of ASAv-I (perimeter firewall).
 * Classic (1.3) rule-set syntax; see edge.boot header for the 1.4/1.5
 * zone-based firewall note. Intent is byte-identical to
 * clab/configs/fw-core.nft: default-deny, mgmt-VLAN full access to DC,
 * user-VLANs DNS/NTP-only to DC, log every drop.
 */
interfaces {
    ethernet eth0 { address 10.255.0.2/30; description "to-edge" }
    ethernet eth1 { address 10.255.0.9/30;  description "to-core" }
    ethernet eth2 {
        address dhcp
        description "management"
        dhcp-options { no-default-route }
    }
}
firewall {
    group {
        network-group MGMT_VLAN  { network 192.168.40.0/24 }
        network-group USER_VLANS { network 192.168.10.0/24; network 192.168.20.0/24; network 192.168.30.0/24 }
        network-group DC_HOSTS   { network 172.16.50.1/32 }
    }
    name FWCORE-IN {
        default-action drop
        enable-default-log
        rule 10 { action accept; state { established enable; related enable } }
        rule 20 { action accept; source { group { network-group MGMT_VLAN } }; destination { port 22 }; protocol tcp }
        rule 30 { action accept; protocol icmp }
    }
    name FWCORE-FWD {
        default-action drop
        enable-default-log
        rule 10 { action accept; state { established enable; related enable } }
        /* mgmt VLAN -> DC: ssh, radius, syslog, ntp, dns */
        rule 20 {
            action accept
            source      { group { network-group MGMT_VLAN } }
            destination { group { network-group DC_HOSTS }; port 22,53,123,514,1812,1813 }
            protocol tcp_udp
        }
        /* user VLANs -> DC: dns + ntp ONLY (no ssh, no radius) — SEG-01 */
        rule 30 {
            action accept
            source      { group { network-group USER_VLANS } }
            destination { group { network-group DC_HOSTS }; port 53,123 }
            protocol udp
        }
        /* egress to Internet */
        rule 40 { action accept; source { group { network-group USER_VLANS } }; outbound-interface eth0 }
        /* everything else: CYB-240 prohibited scan lands here, logged (DET-01) */
    }
    interface eth0 { in { name FWCORE-IN } }
}
system { host-name fw-core }
