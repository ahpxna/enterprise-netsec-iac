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
    static { route 10.255.0.0/16 { next-hop 198.10.10.2 } }
    bgp 65010 {
        parameters { router-id 198.10.10.1 }
        neighbor 198.10.10.2 {
            remote-as 65001
            password "CHANGE_ME_bgp_isp1"
            ttl-security { hops 1 }
        }
        address-family { ipv4-unicast { neighbor 198.10.10.2 { default-originate } } }
    }
}
system { host-name isp1 }
