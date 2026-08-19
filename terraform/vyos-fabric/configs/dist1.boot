/* dist1 — vEOS-Dis-I equivalent. VRRP master (priority 150), user gateway .254 */
interfaces {
    ethernet eth0 {
        address 192.168.10.252/24
        vrrp {
            vrrp-group 10 {
                virtual-address 192.168.10.254/24
                priority 150
                advertise-interval 1
            }
        }
    }
    ethernet eth1 {
        address dhcp
        description "management"
        dhcp-options { no-default-route }
    }
}
system { host-name dist1 }
