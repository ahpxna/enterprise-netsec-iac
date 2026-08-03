/* fw-dmz — VyOS translation of ASAv-DMZ-I. Mirrors clab/configs/fw-dmz.nft:
 * only 80/443 in to the web host, DMZ cannot pivot to 172.16/192.168 (SEG-02).
 */
interfaces {
    ethernet eth0 { address 10.255.0.6/30;   description "to-edge" }
    ethernet eth1 { address 195.1.1.161/29;  description "to-dmz-web" }
}
firewall {
    group {
        network-group WEB_HOST    { network 195.1.1.161/32 }
        network-group INTERNAL_NETS { network 172.16.0.0/16; network 192.168.0.0/16 }
    }
    name FWDMZ-FWD {
        default-action drop
        enable-default-log
        rule 10 { action accept; state { established enable; related enable } }
        rule 20 { action accept; destination { group { network-group WEB_HOST }; port 80,443 }; protocol tcp }
        rule 30 { action accept; destination { group { network-group WEB_HOST }; port 53 }; protocol udp }
        rule 40 { action accept; source { group { network-group WEB_HOST } }; outbound-interface eth0 }
        /* explicit deny+log: web host trying to pivot inward */
        rule 50 { action drop; log enable; source { group { network-group WEB_HOST } }; destination { group { network-group INTERNAL_NETS } } }
    }
    interface eth1 { in { name FWDMZ-FWD } }
}
system { host-name fw-dmz }
