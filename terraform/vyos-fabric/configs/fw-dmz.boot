/* VyOS 1.4.x two-arm DMZ boundary. eth0=edge, eth1=DMZ, eth2=management. */
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
    global-options {
        state-policy {
            established { action accept }
            related { action accept }
            invalid { action drop }
        }
        syn-cookies enable
    }
    group {
        network-group WEB_HOST { network 195.1.1.161/32 }
        network-group INTERNAL_NETS {
            network 172.16.0.0/16
            network 192.168.0.0/16
        }
    }
    ipv4 {
        forward {
            filter {
                default-action drop
                default-log
                rule 5 {
                    action drop
                    description "OOB management subnet is never a transit destination"
                    destination { address 10.1.1.0/24 }
                }
                rule 20 {
                    action accept
                    description "Public HTTP and HTTPS to DMZ web host"
                    inbound-interface { name eth0 }
                    destination { group { network-group WEB_HOST }; port 80,443 }
                    protocol tcp
                }
                rule 30 {
                    action drop
                    description "SEG-02 block DMZ pivot to internal networks"
                    inbound-interface { name eth1 }
                    source { group { network-group WEB_HOST } }
                    destination { group { network-group INTERNAL_NETS } }
                    log
                }
                rule 40 {
                    action accept
                    description "DMZ web egress to outside only"
                    inbound-interface { name eth1 }
                    outbound-interface { name eth0 }
                    source { group { network-group WEB_HOST } }
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
                    inbound-interface { name eth2 }
                    destination { port 22 }
                    protocol tcp
                }
                rule 20 {
                    action accept
                    description "Management DHCP lease replies"
                    inbound-interface { name eth2 }
                    destination { port 68 }
                    source { port 67 }
                    protocol udp
                }
                rule 30 {
                    action accept
                    description "Management ICMP diagnostics"
                    inbound-interface { name eth2 }
                    protocol icmp
                }
            }
        }
    }
}
system {
    host-name fw-dmz
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
