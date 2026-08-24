/* VyOS 1.4.x three-arm security boundary.
 * eth0=edge, eth1=core/campus, eth2=DC, eth3=management.
 * Uses the 1.4 nftables firewall model (`firewall ipv4 forward/input filter`).
 */
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
    global-options {
        state-policy {
            established { action accept }
            related { action accept }
            invalid { action drop }
        }
        syn-cookies enable
    }
    group {
        network-group MGMT_VLAN { network 192.168.40.0/24 }
        network-group USER_VLANS {
            network 192.168.10.0/24
            network 192.168.20.0/24
            network 192.168.30.0/24
        }
        network-group CLIENT_VLANS { network 192.168.0.0/16 }
        network-group DC_NET { network 172.16.50.0/24 }
        network-group INFRA_NET { network 10.255.0.0/16 }
    }
    ipv4 {
        forward {
            filter {
                default-action drop
                default-log
                rule 20 {
                    action accept
                    description "SEG-01 management SSH and TLS logging to DC"
                    inbound-interface { name eth1 }
                    source { group { network-group MGMT_VLAN } }
                    destination { group { network-group DC_NET }; port 22,6514 }
                    protocol tcp
                }
                rule 21 {
                    action accept
                    description "SEG-01 management infrastructure UDP services"
                    inbound-interface { name eth1 }
                    source { group { network-group MGMT_VLAN } }
                    destination { group { network-group DC_NET }; port 53,123,1812,1813 }
                    protocol udp
                }
                rule 30 {
                    action accept
                    description "SEG-01 user DNS and NTP only"
                    inbound-interface { name eth1 }
                    source { group { network-group USER_VLANS } }
                    destination { group { network-group DC_NET }; port 53,123 }
                    protocol udp
                }
                rule 40 {
                    action accept
                    description "DET-02 campus infrastructure TLS logging"
                    inbound-interface { name eth1 }
                    source { group { network-group INFRA_NET } }
                    destination { address 172.16.50.11; port 6514 }
                    protocol tcp
                }
                rule 41 {
                    action accept
                    description "DET-02 edge and DMZ firewall TLS logging"
                    inbound-interface { name eth0 }
                    source { address 10.255.0.1/32; address 10.255.0.10/32 }
                    destination { address 172.16.50.11; port 6514 }
                    protocol tcp
                }
                rule 50 {
                    action drop
                    description "SEG-01 deny client access to remaining DC services"
                    inbound-interface { name eth1 }
                    source { group { network-group CLIENT_VLANS } }
                    destination { group { network-group DC_NET } }
                    log
                }
                rule 60 {
                    action accept
                    description "Campus egress outside DC"
                    inbound-interface { name eth1 }
                    source { group { network-group CLIENT_VLANS } }
                }
                rule 70 {
                    action accept
                    description "DC egress to edge only"
                    inbound-interface { name eth2 }
                    outbound-interface { name eth0 }
                    source { group { network-group DC_NET } }
                }
            }
        }
        input {
            filter {
                default-action drop
                default-log
                rule 10 {
                    action accept
                    description "Management-plane SSH only"
                    inbound-interface { name eth3 }
                    destination { port 22 }
                    protocol tcp
                }
                rule 20 {
                    action accept
                    description "Management DHCP lease replies"
                    inbound-interface { name eth3 }
                    destination { port 68 }
                    source { port 67 }
                    protocol udp
                }
                rule 30 {
                    action accept
                    description "Management ICMP diagnostics"
                    inbound-interface { name eth3 }
                    protocol icmp
                }
            }
        }
    }
}
nat {
    source {
        rule 100 {
            description "Campus and DC egress SNAT"
            outbound-interface { name eth0 }
            source { address 192.168.0.0/16 }
            translation { address masquerade }
        }
        rule 110 {
            description "DC egress SNAT"
            outbound-interface { name eth0 }
            source { address 172.16.50.0/24 }
            translation { address masquerade }
        }
    }
}

system {
    host-name fw-core
    login {
        timeout 300
        user vyos {
            authentication {
                public-keys terraform-bootstrap {
                    type "SSH_KEY_TYPE"
                    key "SSH_KEY_DATA"
                }
            }
        }
    }
}
service {
    ssh {
        port 22
        listen-address "MANAGEMENT_IP"
        disable-password-authentication
        client-keepalive-interval 300
    }
}
