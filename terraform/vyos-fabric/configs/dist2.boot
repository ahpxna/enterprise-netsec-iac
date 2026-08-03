/* dist2 — vEOS-Dis-II equivalent. VRRP backup (priority 100) */
interfaces {
    ethernet eth0 {
        address 192.168.40.252/24
        vrrp {
            vrrp-group 10 {
                virtual-address 192.168.40.254/24
                priority 100
                advertise-interval 1
            }
        }
    }
}
system { host-name dist2 }
