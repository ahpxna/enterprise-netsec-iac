/* core — VyOS translation of vIOS-Core-I. OSPF backbone, MD5 auth,
 * user VLANs passive (mirrors clab/configs/core.frr.conf).
 */
interfaces {
    ethernet eth0 { address 10.255.0.10/30; description "to-fw-core" }
    ethernet eth1 { address 192.168.10.253/24; description "to-dist1" }
    ethernet eth2 { address 192.168.40.253/24; description "to-dist2" }
    ethernet eth3 { address 172.16.50.254/24;  description "to-dc" }
    ethernet eth4 {
        address dhcp
        description "management"
        dhcp-options { no-default-route }
    }
}
protocols {
    ospf {
        parameters { router-id 10.1.1.11 }
        area 0 {
            network 10.255.0.8/30
            network 172.16.50.0/24
        }
        interface eth0 { authentication { md5 { key-id 1 { md5-key "CHANGE_ME_ospf_key" } } } }
        /* user-facing interfaces stay passive: no hellos leak to users */
        interface eth1 { passive }
        interface eth2 { passive }
    }
}
system { host-name core }
