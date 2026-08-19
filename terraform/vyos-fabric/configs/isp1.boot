/* isp1 — VyOS upstream router for edge BGP peer AS65010. */
interfaces {
    ethernet eth0 {
        address 198.10.10.1/30
        description "to-edge"
    }
    ethernet eth1 {
        address dhcp
        description "management"
        dhcp-options { no-default-route }
    }
}
protocols {
    bgp 65010 {
        parameters { router-id 198.10.10.1 }
        neighbor 198.10.10.2 {
            remote-as 65001
            password "CHANGE_ME_bgp_isp1"
            ttl-security { hops 1 }
        }
    }
}
system { host-name isp1 }
