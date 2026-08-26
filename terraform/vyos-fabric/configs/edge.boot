/* edge — VyOS Path B dual-ISP BGP edge.
 * Target baseline: the exact image pinned in terraform.tfvars (the example
 * uses 1.4.2). This config must pass `load /config/config.boot && commit` on
 * that image before a full fabric apply; Terraform cannot validate VyOS CLI.
 */
interfaces {
    ethernet eth0 {
        address 198.10.10.2/30      /* to isp1 */
        description "to-isp1"
    }
    ethernet eth1 {
        address 197.10.10.2/30      /* to isp2 */
        description "to-isp2"
    }
    ethernet eth2 {
        address 10.255.0.1/30       /* to fw-core */
        description "to-fw-core"
    }
    ethernet eth3 {
        address 10.255.0.9/30       /* to fw-dmz */
        description "to-fw-dmz"
    }
    ethernet eth4 {
        address dhcp
        description "management"
        dhcp-options { no-default-route }
    }
}
protocols {
    static {
        route 172.16.50.0/24 { next-hop 10.255.0.2 }
        route 192.168.0.0/16 { next-hop 10.255.0.2 }
        route 195.1.1.160/29 { next-hop 10.255.0.10 }
        route 195.1.1.0/24 { blackhole }
    }
    bgp 65001 {
        parameters {
            router-id 195.1.1.2
        }
        neighbor 198.10.10.1 {
            remote-as 65010
            password "CHANGE_ME_bgp_isp1"
            ttl-security { hops 1 }
        }
        neighbor 197.10.10.1 {
            remote-as 65020
            password "CHANGE_ME_bgp_isp2"
            ttl-security { hops 1 }
        }
        address-family {
            ipv4-unicast {
                network 195.1.1.0/24 { }
                /* outbound filter: advertise only the approved enterprise prefixes */
                route-map { export ONLY-OURS }
            }
        }
    }
}
policy {
    prefix-list OURS {
        rule 5 {
            prefix 195.1.1.0/24
            action permit
        }
    }
    route-map ONLY-OURS {
        rule 10 {
            action permit
            match { ip { address { prefix-list OURS } } }
        }
        rule 20 { action deny }
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
                    inbound-interface { name eth4 }
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
    host-name edge
    config-management { commit-revisions 20 }
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
