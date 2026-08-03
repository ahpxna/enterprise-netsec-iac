# =====================================================================
# Point-to-point libvirt networks — one per link in the topology, no
# switch/bridge sharing, so this is a routed fabric exactly like the
# containerlab version (each link = its own /30 or /24 broadcast domain).
# IPs match Brezula's original plan / clab/companyxyz.clab.yml.
# =====================================================================

resource "libvirt_network" "mgmt" {
  name      = var.management_network
  mode      = "nat"
  addresses = ["10.1.1.0/24"]
  dhcp { enabled = true }
  dns { enabled = true }
}

resource "libvirt_network" "isp1_link" {
  name      = "cxyz-isp1"
  mode      = "none" # isolated P2P segment, addressing done in VyOS config.boot
  addresses = ["198.10.10.0/30"]
}

resource "libvirt_network" "isp2_link" {
  name      = "cxyz-isp2"
  mode      = "none"
  addresses = ["197.10.10.0/30"]
}

resource "libvirt_network" "edge_fwcore" {
  name      = "cxyz-edge-fwcore"
  mode      = "none"
  addresses = ["10.255.0.0/30"]
}

resource "libvirt_network" "edge_fwdmz" {
  name      = "cxyz-edge-fwdmz"
  mode      = "none"
  addresses = ["10.255.0.4/30"]
}

resource "libvirt_network" "fwcore_core" {
  name      = "cxyz-fwcore-core"
  mode      = "none"
  addresses = ["10.255.0.8/30"]
}

resource "libvirt_network" "fwdmz_dmzweb" {
  name      = "cxyz-fwdmz-dmzweb"
  mode      = "none"
  addresses = ["195.1.1.160/29"] # matches Part 7 DMZ /29 for VLAN10-equivalent segment
}

resource "libvirt_network" "core_dist1" {
  name      = "cxyz-core-dist1"
  mode      = "none"
  addresses = ["192.168.10.0/24"]
}

resource "libvirt_network" "core_dist2" {
  name      = "cxyz-core-dist2"
  mode      = "none"
  addresses = ["192.168.40.0/24"]
}

resource "libvirt_network" "core_dc" {
  name      = "cxyz-core-dc"
  mode      = "none"
  addresses = ["172.16.50.0/24"]
}
