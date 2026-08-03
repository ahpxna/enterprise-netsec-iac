/* edge — VyOS translation of vIOS-EDGE-I (dual-ISP BGP edge).
 * SYNTAX NOTE: written against VyOS 1.3 (equuleus) classic CLI syntax.
 * VyOS 1.4/1.5 (rolling) rewired `firewall` to a zone-based model — if
 * you're on rolling, port the firewall{} stanza per:
 * https://docs.vyos.io/en/latest/configuration/firewall/index.html
 * Everything else (interfaces/protocols bgp) is stable across versions.
 * VALIDATE with `configure && load /config/config.boot && commit` and
 * fix anything the parser rejects for your exact build — this file has
 * NOT been booted against a real VyOS image yet (see TESTING-GUIDE.md).
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
        address 10.255.0.5/30       /* to fw-dmz */
        description "to-fw-dmz"
    }
}
protocols {
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
                /* outbound filter: never leak internal routes beyond ours */
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
