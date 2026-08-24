/* Generated architecture contract: intent/fabric.yaml.
 * eth0=fw-core, eth1=dist1, eth2=dist2, eth3=management.
 */
interfaces {
    ethernet eth0 { address 10.255.0.6/30; description "to-fw-core" }
    ethernet eth1 { address 10.255.1.0/31; description "to-dist1" }
    ethernet eth2 { address 10.255.1.2/31; description "to-dist2" }
    ethernet eth3 { address dhcp; description "management"; dhcp-options { no-default-route } }
}
protocols {
    static {
        route 0.0.0.0/0 { next-hop 10.255.0.5 }
        route 172.16.50.0/24 { next-hop 10.255.0.5 }
    }
    ospf {
        parameters { router-id 10.1.1.11 }
        default-information { originate { } }
        area 0 { network 10.255.1.0/31; network 10.255.1.2/31 }
        interface eth1 { authentication { md5 { key-id 1 { md5-key "CHANGE_ME_ospf_key" } } } }
        interface eth2 { authentication { md5 { key-id 1 { md5-key "CHANGE_ME_ospf_key" } } } }
    }
}
system {
    host-name core
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
