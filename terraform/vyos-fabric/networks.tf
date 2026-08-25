# Canonical topology is shared with Path A. Libvirt owns only isolated L2
# segments; guest addressing comes from intent/fabric.yaml and never from
# libvirt_network.addresses (which avoids the legacy provider /30 bug).

locals {
  fabric_intent = yamldecode(file("${path.module}/../../intent/fabric.yaml"))
  link_plan = {
    for link_name, link in local.fabric_intent.links : link_name => {
      name = link.network_name
      cidr = link.cidr
      kind = link.kind
    }
  }
}

resource "libvirt_network" "mgmt" {
  name      = var.management_network
  mode      = "nat"
  addresses = [local.fabric_intent.management.subnet]
  dhcp { enabled = true }
  dns { enabled = true }
}

resource "libvirt_network" "data" {
  # DC uses the existing br-cxyz-dc bridge shared with Docker. Do not recreate
  # it as a separate libvirt network using the same CIDR.
  for_each = {
    for link_name, link in local.link_plan : link_name => link
    if link.kind != "external_bridge"
  }

  name = each.value.name
  mode = "none"
}

output "data_plane_link_plan" {
  description = "Canonical link names, guest-owned CIDRs, and L2 segment kinds"
  value       = local.link_plan
}
