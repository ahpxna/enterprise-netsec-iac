# =====================================================================
# Real VM fabric: one libvirt domain per node, base VyOS qcow2 backed by
# a per-node COW overlay disk, initial config injected via a second
# cloud-init-style config-drive that drops /config/config.boot before
# first boot (VyOS reads this at startup — see cloud-init/ templates).
# =====================================================================

resource "libvirt_pool" "cxyz" {
  name = "cxyz-vyos-fabric"
  type = "dir"
  target {
    path = "/var/lib/libvirt/images/cxyz-vyos-fabric"
  }
}

# VyOS base image shared as a backing file for network nodes.
resource "libvirt_volume" "base" {
  name   = "vyos-base.qcow2"
  pool   = libvirt_pool.cxyz.name
  source = var.vyos_image_path
  format = "qcow2"
}

# Linux cloud image shared by endpoint nodes.
resource "libvirt_volume" "linux_base" {
  name   = "linux-base.qcow2"
  pool   = libvirt_pool.cxyz.name
  source = var.linux_image_path
  format = "qcow2"
}

# Optional per-node images retain support for separately licensed or customized
# qcow2 images without duplicating the default base volumes.
resource "libvirt_volume" "node_override_base" {
  for_each = var.node_image_overrides

  name   = "${each.key}-base.qcow2"
  pool   = libvirt_pool.cxyz.name
  source = each.value
  format = "qcow2"
}

resource "libvirt_volume" "node_disk" {
  for_each = var.nodes
  name     = "${each.key}-disk.qcow2"
  pool     = libvirt_pool.cxyz.name
  base_volume_id = contains(keys(var.node_image_overrides), each.key) ? (
    libvirt_volume.node_override_base[each.key].id
    ) : each.value.platform == "vyos" ? (
    libvirt_volume.base.id
    ) : (
    libvirt_volume.linux_base.id
  )
  format = "qcow2"
}

# Cloud-init ISO per node. VyOS nodes receive config.boot; Linux endpoints
# receive a normal cloud-config plus MAC-matched network-config v2 data.
resource "libvirt_cloudinit_disk" "node_ci" {
  for_each = var.nodes
  name     = "${each.key}-cloudinit.iso"
  pool     = libvirt_pool.cxyz.name
  user_data = each.value.platform == "vyos" ? templatefile(
    "${path.module}/cloud-init/user-data.tftpl",
    {
      hostname    = each.key
      ssh_key     = var.ssh_public_key
      boot_config = file("${path.module}/${each.value.boot_config}")
    }
    ) : templatefile(
    "${path.module}/cloud-init/linux-user-data.tftpl",
    {
      hostname = each.key
      ssh_key  = var.ssh_public_key
    }
  )
  meta_data = templatefile("${path.module}/cloud-init/meta-data.tftpl", {
    hostname = each.key
  })

  network_config = each.value.platform == "linux" ? yamlencode({
    version = 2
    ethernets = merge(
      {
        for nic in local.interface_plan[each.key] : nic.device => merge(
          {
            match = {
              macaddress = lower(nic.mac)
            }
            "set-name" = nic.device
            addresses  = [nic.address]
          },
          nic.gateway == null ? {} : {
            routes = [{
              to  = "0.0.0.0/0"
              via = nic.gateway
            }]
          }
        )
      },
      {
        (local.management_plan[each.key].device) = {
          match = {
            macaddress = lower(local.management_plan[each.key].mac)
          }
          "set-name" = local.management_plan[each.key].device
          dhcp4      = true
          "dhcp4-overrides" = {
            "use-routes" = false
          }
        }
      }
    )
  }) : null
}

resource "libvirt_domain" "node" {
  for_each = var.nodes
  name     = "cxyz-${each.key}"
  memory   = each.value.memory_mb
  vcpu     = each.value.vcpu

  cloudinit = libvirt_cloudinit_disk.node_ci[each.key].id

  disk {
    volume_id = libvirt_volume.node_disk[each.key].id
  }

  # NIC 0..n-1: data-plane first. This ordering matches every config.boot and
  # is reinforced with deterministic MAC addresses.
  dynamic "network_interface" {
    for_each = local.interface_plan[each.key]
    content {
      network_name   = network_interface.value.network_name
      mac            = network_interface.value.mac
      wait_for_lease = false
    }
  }

  # Final NIC: out-of-band management. The management network reserves the
  # requested address for this stable MAC; VyOS and Linux both request DHCP
  # without accepting a management-plane default route.
  network_interface {
    network_name   = libvirt_network.mgmt.name
    mac            = local.management_plan[each.key].mac
    hostname       = each.key
    addresses      = [each.value.mgmt_ip]
    wait_for_lease = false
  }

  console {
    type        = "pty"
    target_port = "0"
    target_type = "serial"
  }

  graphics {
    type        = "vnc"
    listen_type = "address"
  }
}

# Mirrors the `links:` section of clab/companyxyz.clab.yml. List order is the
# guest ethX order; management is appended after the final entry.
locals {
  data_links = {
    edge = [
      { network_name = libvirt_network.isp1_link.name, address = "198.10.10.2/30", gateway = null },
      { network_name = libvirt_network.isp2_link.name, address = "197.10.10.2/30", gateway = null },
      { network_name = libvirt_network.edge_fwcore.name, address = "10.255.0.1/30", gateway = null },
      { network_name = libvirt_network.edge_fwdmz.name, address = "10.255.0.5/30", gateway = null },
    ]
    fw-core = [
      { network_name = libvirt_network.edge_fwcore.name, address = "10.255.0.2/30", gateway = null },
      { network_name = libvirt_network.fwcore_core.name, address = "10.255.0.9/30", gateway = null },
    ]
    fw-dmz = [
      { network_name = libvirt_network.edge_fwdmz.name, address = "10.255.0.6/30", gateway = null },
      { network_name = libvirt_network.fwdmz_dmzweb.name, address = "195.1.1.162/29", gateway = null },
    ]
    core = [
      { network_name = libvirt_network.fwcore_core.name, address = "10.255.0.10/30", gateway = null },
      { network_name = libvirt_network.core_dist1.name, address = "192.168.10.253/24", gateway = null },
      { network_name = libvirt_network.core_dist2.name, address = "192.168.40.253/24", gateway = null },
      { network_name = libvirt_network.core_dc.name, address = "172.16.50.254/24", gateway = null },
    ]
    dist1 = [
      { network_name = libvirt_network.core_dist1.name, address = "192.168.10.252/24", gateway = null },
    ]
    dist2 = [
      { network_name = libvirt_network.core_dist2.name, address = "192.168.40.252/24", gateway = null },
    ]
    isp1 = [
      { network_name = libvirt_network.isp1_link.name, address = "198.10.10.1/30", gateway = null },
    ]
    isp2 = [
      { network_name = libvirt_network.isp2_link.name, address = "197.10.10.1/30", gateway = null },
    ]
    pc1 = [
      { network_name = libvirt_network.core_dist1.name, address = "192.168.10.1/24", gateway = "192.168.10.254" },
    ]
    pc4 = [
      { network_name = libvirt_network.core_dist2.name, address = "192.168.40.1/24", gateway = "192.168.40.254" },
    ]
    server1 = [
      { network_name = libvirt_network.core_dc.name, address = "172.16.50.1/24", gateway = "172.16.50.254" },
    ]
    dmz-web = [
      { network_name = libvirt_network.fwdmz_dmzweb.name, address = "195.1.1.161/29", gateway = "195.1.1.162" },
    ]
  }

  interface_plan = {
    for node_name, links in local.data_links : node_name => [
      for index, link in links : merge(link, {
        device = "eth${index}"
        mac    = format("52:54:00:%02x:00:%02x", var.nodes[node_name].node_id, index + 1)
      })
    ]
  }

  management_plan = {
    for node_name, node in var.nodes : node_name => {
      device       = "eth${length(local.data_links[node_name])}"
      mac          = format("52:54:00:%02x:00:ff", node.node_id)
      network_name = var.management_network
      address      = node.mgmt_ip
    }
  }
}

check "complete_topology" {
  assert {
    condition     = toset(keys(var.nodes)) == toset(keys(local.data_links))
    error_message = "Every Path B node must have an explicit ordered data-plane interface plan."
  }
}

check "known_image_override_nodes" {
  assert {
    condition     = length(setsubtract(toset(keys(var.node_image_overrides)), toset(keys(var.nodes)))) == 0
    error_message = "node_image_overrides contains a node that is not present in var.nodes."
  }
}

output "node_mgmt_ips" {
  value = { for k, v in var.nodes : k => v.mgmt_ip }
}

output "node_interface_plan" {
  description = "Stable guest device, MAC, network, and address mapping; management is always last"
  value = {
    for node_name in keys(var.nodes) : node_name => {
      data       = local.interface_plan[node_name]
      management = local.management_plan[node_name]
    }
  }
}
