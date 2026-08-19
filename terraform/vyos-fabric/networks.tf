# =====================================================================
# Data-plane libvirt networks — one isolated Layer-2 segment per link in the
# topology. The CIDRs remain declared Terraform data in local.link_plan,
# while addressing is applied only inside the VyOS guests.
#
# Do not pass these CIDRs through libvirt_network.addresses. The legacy
# dmacvicar/libvirt 0.8 provider reserves a network, broadcast, and host-bridge
# address before it evaluates dhcp.enabled; a /30 therefore fails validation
# and would also make the host bridge consume one of the two router addresses.
# =====================================================================

locals {
  link_plan = {
    isp1_link = {
      name = "cxyz-isp1"
      cidr = "198.10.10.0/30"
    }
    isp2_link = {
      name = "cxyz-isp2"
      cidr = "197.10.10.0/30"
    }
    edge_fwcore = {
      name = "cxyz-edge-fwcore"
      cidr = "10.255.0.0/30"
    }
    edge_fwdmz = {
      name = "cxyz-edge-fwdmz"
      cidr = "10.255.0.4/30"
    }
    fwcore_core = {
      name = "cxyz-fwcore-core"
      cidr = "10.255.0.8/30"
    }
    fwdmz_dmzweb = {
      name = "cxyz-fwdmz-dmzweb"
      cidr = "195.1.1.160/29"
    }
    core_dist1 = {
      name = "cxyz-core-dist1"
      cidr = "192.168.10.0/24"
    }
    core_dist2 = {
      name = "cxyz-core-dist2"
      cidr = "192.168.40.0/24"
    }
    core_dc = {
      name = "cxyz-core-dc"
      cidr = "172.16.50.0/24"
    }
  }
}

resource "libvirt_network" "mgmt" {
  name      = var.management_network
  mode      = "nat"
  addresses = ["10.1.1.0/24"]
  dhcp { enabled = true }
  dns { enabled = true }
}

resource "libvirt_network" "isp1_link" {
  name = local.link_plan.isp1_link.name
  mode = "none" # isolated L2 segment; addressing is owned by VyOS
}

resource "libvirt_network" "isp2_link" {
  name = local.link_plan.isp2_link.name
  mode = "none"
}

resource "libvirt_network" "edge_fwcore" {
  name = local.link_plan.edge_fwcore.name
  mode = "none"
}

resource "libvirt_network" "edge_fwdmz" {
  name = local.link_plan.edge_fwdmz.name
  mode = "none"
}

resource "libvirt_network" "fwcore_core" {
  name = local.link_plan.fwcore_core.name
  mode = "none"
}

resource "libvirt_network" "fwdmz_dmzweb" {
  name = local.link_plan.fwdmz_dmzweb.name
  mode = "none"
}

resource "libvirt_network" "core_dist1" {
  name = local.link_plan.core_dist1.name
  mode = "none"
}

resource "libvirt_network" "core_dist2" {
  name = local.link_plan.core_dist2.name
  mode = "none"
}

resource "libvirt_network" "core_dc" {
  name = local.link_plan.core_dc.name
  mode = "none"
}

output "data_plane_link_plan" {
  description = "Declared data-plane libvirt network names and guest-owned CIDRs"
  value       = local.link_plan
}
