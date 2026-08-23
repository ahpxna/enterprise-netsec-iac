/* edge — VyOS translation of vIOS-EDGE-I (dual-ISP BGP edge).
 * SYNTAX NOTE: written against VyOS 1.3 (equuleus) classic CLI syntax.
 * VyOS 1.4/1.5 (rolling) rewired `firewall` to a zone-based model. For a
 * rolling build, port the firewall{} stanza per:
 * https://docs.vyos.io/en/latest/configuration/firewall/index.html
 * Everything else (interfaces/protocols bgp) is stable across versions.
 * VALIDATE with `configure && load /config/config.boot && commit` and
 * resolve any parser errors for the target build. This file has not yet been
 * boot-validated against a real VyOS image (see TESTING-GUIDE.md).
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
system {
    host-name edge
    login {
        user vyos {
            authentication { plaintext-password "CHANGE_ME_ON_FIRST_BOOT" }
        }
    }
    config-management { commit-revisions 20 }
}
