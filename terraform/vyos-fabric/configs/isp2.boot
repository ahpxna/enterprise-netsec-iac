/* isp2 — VyOS upstream router for edge BGP peer AS65020. */
interfaces {
    ethernet eth0 {
        address 197.10.10.1/30
        description "to-edge"
    }
    ethernet eth1 {
        address dhcp
        description "management"
        dhcp-options { no-default-route }
    }
}
protocols {
    static { route 10.255.0.0/16 { next-hop 197.10.10.2 } }
    bgp 65020 {
        parameters { router-id 197.10.10.1 }
        neighbor 197.10.10.2 {
            remote-as 65001
            password "CHANGE_ME_bgp_isp2"
            ttl-security { hops 1 }
        }
        address-family { ipv4-unicast { neighbor 197.10.10.2 { default-originate } } }
    }
}
firewall {
    ipv4 {
        input {
            filter {
                default-action accept
                rule 10 {
                    action accept
                    description "OOB SSH from trusted libvirt host only"
                    inbound-interface { name eth1 }
                    source { address 10.1.1.1/32 }
                    destination { port 22 }
                    protocol tcp
                }
                rule 20 {
                    action drop
                    description "Deny routed OOB SSH bypass"
                    destination { port 22 }
                    protocol tcp
                }
            }
        }
        forward {
            filter {
                default-action accept
                rule 5 {
                    action drop
                    description "OOB management subnet is never a transit destination"
                    destination { address 10.1.1.0/24 }
                }
            }
        }
    }
}
system {
    host-name isp2
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
