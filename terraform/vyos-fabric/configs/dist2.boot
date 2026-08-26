/* DIST2 backs up both shared client LAN gateways.
 * eth0=core, eth1=VLAN10, eth2=VLAN40, eth3=management.
 */
interfaces {
    ethernet eth0 { address 10.255.1.3/31; description "to-core" }
    ethernet eth1 {
        address 192.168.10.253/24
        description "vlan10"
        vrrp { vrrp-group 10 { virtual-address 192.168.10.254/24; priority 100; advertise-interval 1 } }
    }
    ethernet eth2 {
        address 192.168.40.253/24
        description "vlan40"
        vrrp { vrrp-group 40 { virtual-address 192.168.40.254/24; priority 100; advertise-interval 1 } }
    }
    ethernet eth3 { address dhcp; description "management"; dhcp-options { no-default-route } }
}
protocols {
    ospf {
        parameters { router-id 10.1.1.3 }
        area 0 { network 10.255.1.2/31; network 192.168.10.0/24; network 192.168.40.0/24 }
        interface eth0 { authentication { md5 { key-id 1 { md5-key "CHANGE_ME_ospf_key" } } } }
        interface eth1 { passive }
        interface eth2 { passive }
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
                    inbound-interface { name eth3 }
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
    host-name dist2
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
