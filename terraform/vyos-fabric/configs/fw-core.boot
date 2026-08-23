/* Three-arm security boundary: eth0=edge, eth1=core, eth2=DC, eth3=management. */
interfaces {
    ethernet eth0 { address 10.255.0.2/30; description "outside-to-edge" }
    ethernet eth1 { address 10.255.0.5/30; description "campus-to-core" }
    ethernet eth2 { address 172.16.50.254/24; description "dc" }
    ethernet eth3 { address dhcp; description "management"; dhcp-options { no-default-route } }
}
protocols {
    static {
        route 0.0.0.0/0 { next-hop 10.255.0.1 }
        route 192.168.0.0/16 { next-hop 10.255.0.6 }
    }
}
firewall {
    group {
        network-group MGMT_VLAN { network 192.168.40.0/24 }
        network-group USER_VLANS { network 192.168.10.0/24; network 192.168.20.0/24; network 192.168.30.0/24 }
        network-group CLIENT_VLANS { network 192.168.0.0/16 }
        network-group DC_NET { network 172.16.50.0/24 }
        network-group INFRA_NET { network 10.255.0.0/16 }
    }
    name OUTSIDE-IN {
        default-action drop
        enable-default-log
        rule 10 { action accept; state { established enable; related enable } }
    }
    name CAMPUS-IN {
        default-action drop
        enable-default-log
        rule 10 { action accept; state { established enable; related enable } }
        rule 20 { action accept; source { group { network-group MGMT_VLAN } }; destination { group { network-group DC_NET }; port 22,6514 }; protocol tcp }
        rule 21 { action accept; source { group { network-group MGMT_VLAN } }; destination { group { network-group DC_NET }; port 53,123,1812,1813 }; protocol udp }
        rule 30 { action accept; source { group { network-group USER_VLANS } }; destination { group { network-group DC_NET }; port 53,123 }; protocol udp }
        rule 40 { action accept; source { group { network-group INFRA_NET } }; destination { address 172.16.50.11; port 6514 }; protocol tcp }
        rule 50 { action drop; log enable; source { group { network-group CLIENT_VLANS } }; destination { group { network-group DC_NET } } }
        rule 100 { action accept; source { group { network-group CLIENT_VLANS } } }
    }
    name DC-IN {
        default-action drop
        enable-default-log
        rule 10 { action accept; state { established enable; related enable } }
        rule 20 { action accept; source { group { network-group DC_NET } }; outbound-interface eth0 }
    }
    interface eth0 { in { name OUTSIDE-IN } }
    interface eth1 { in { name CAMPUS-IN } }
    interface eth2 { in { name DC-IN } }
}
system { host-name fw-core }
service { ssh { port 22 } }
