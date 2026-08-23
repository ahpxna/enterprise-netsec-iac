/* Two-arm DMZ boundary. eth0=edge, eth1=DMZ, eth2=management. */
interfaces {
    ethernet eth0 { address 10.255.0.10/30; description "outside-to-edge" }
    ethernet eth1 { address 195.1.1.166/29; description "dmz" }
    ethernet eth2 { address dhcp; description "management"; dhcp-options { no-default-route } }
}
protocols {
    static {
        route 0.0.0.0/0 { next-hop 10.255.0.9 }
        route 172.16.0.0/16 { next-hop 10.255.0.9 }
        route 192.168.0.0/16 { next-hop 10.255.0.9 }
    }
}
firewall {
    group {
        network-group WEB_HOST { network 195.1.1.161/32 }
        network-group INTERNAL_NETS { network 172.16.0.0/16; network 192.168.0.0/16 }
    }
    name OUTSIDE-IN {
        default-action drop
        enable-default-log
        rule 10 { action accept; state { established enable; related enable } }
        rule 20 { action accept; destination { group { network-group WEB_HOST }; port 80,443 }; protocol tcp }
    }
    name DMZ-IN {
        default-action drop
        enable-default-log
        rule 10 { action accept; state { established enable; related enable } }
        rule 20 { action drop; log enable; source { group { network-group WEB_HOST } }; destination { group { network-group INTERNAL_NETS } } }
        rule 100 { action accept; source { group { network-group WEB_HOST } }; outbound-interface eth0 }
    }
    interface eth0 { in { name OUTSIDE-IN } }
    interface eth1 { in { name DMZ-IN } }
}
system { host-name fw-dmz }
service { ssh { port 22 } }
