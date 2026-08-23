/* DIST1 is the preferred gateway for both shared client LANs.
 * eth0=core, eth1=VLAN10, eth2=VLAN40, eth3=management.
 */
interfaces {
    ethernet eth0 { address 10.255.1.1/31; description "to-core" }
    ethernet eth1 {
        address 192.168.10.252/24
        description "vlan10"
        vrrp { vrrp-group 10 { virtual-address 192.168.10.254/24; priority 150; advertise-interval 1 } }
    }
    ethernet eth2 {
        address 192.168.40.252/24
        description "vlan40"
        vrrp { vrrp-group 40 { virtual-address 192.168.40.254/24; priority 150; advertise-interval 1 } }
    }
    ethernet eth3 { address dhcp; description "management"; dhcp-options { no-default-route } }
}
protocols {
    ospf {
        parameters { router-id 10.1.1.2 }
        area 0 { network 10.255.1.0/31; network 192.168.10.0/24; network 192.168.40.0/24 }
        interface eth0 { authentication { md5 { key-id 1 { md5-key "CHANGE_ME_ospf_key" } } } }
        interface eth1 { passive }
        interface eth2 { passive }
    }
}
system { host-name dist1 }
service { ssh { port 22 } }
