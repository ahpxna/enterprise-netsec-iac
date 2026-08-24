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
  source = each.value.path
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
      boot_config = local.vyos_boot_configs[each.key]
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
      bridge         = network_interface.value.bridge
      mac            = network_interface.value.mac
      wait_for_lease = false
    }
  }

  # Final NIC: out-of-band management. The management network reserves the
  # requested address for this stable MAC; VyOS and Linux both request DHCP
  # without accepting a management-plane default route.
  network_interface {
    network_name   = libvirt_network.mgmt.name
    mac          = local.management_plan[each.key].mac
    hostname     = each.key
    # IP ownership belongs only to intent/fabric.yaml. Libvirt uses this
    # address to create a deterministic DHCP reservation for the stable MAC.
    addresses      = [local.management_plan[each.key].address]
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

# Directly consumes intent/fabric.yaml. Attachment list order is the guest
# ethX order; management is appended after the final data-plane entry.
locals {
  data_links = {
    for node_name, node in local.fabric_intent.nodes : node_name => [
      for attachment in node.attachments : {
        network_name = try(libvirt_network.data[attachment.link].name, null)
        bridge = try(
          local.fabric_intent.links[attachment.link].kind == "external_bridge"
          ? local.fabric_intent.links[attachment.link].bridge
          : null,
          null,
        )
        address = attachment.address
        gateway = try([
          for route in node.routes : route.via if route.to == "0.0.0.0/0"
        ][0], null)
      }
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
    for node_name, node in local.fabric_intent.nodes : node_name => {
      device       = "eth${length(local.data_links[node_name])}"
      mac          = format("52:54:00:%02x:00:ff", var.nodes[node_name].node_id)
      network_name = var.management_network
      address      = node.mgmt_ip
    }
  }

  # Source configs are reviewed without secret material. Terraform injects
  # routing credentials, the intent-owned management address, and the SSH
  # bootstrap key only into the cloud-init payload.
  ssh_public_key_parts = split(" ", trimspace(var.ssh_public_key))
  ssh_public_key_type  = local.ssh_public_key_parts[0]
  ssh_public_key_data  = local.ssh_public_key_parts[1]

  vyos_boot_configs = {
    for node_name, node in var.nodes : node_name => node.platform == "vyos" ? replace(
      replace(
        replace(
          replace(
            replace(
              replace(file("${path.module}/${node.boot_config}"), "CHANGE_ME_ospf_key", var.routing_secrets.ospf_md5),
              "CHANGE_ME_bgp_isp1", var.routing_secrets.bgp_isp1),
            "CHANGE_ME_bgp_isp2", var.routing_secrets.bgp_isp2),
          "MANAGEMENT_IP", local.fabric_intent.nodes[node_name].mgmt_ip),
        "SSH_KEY_TYPE", local.ssh_public_key_type),
      "SSH_KEY_DATA", local.ssh_public_key_data) : null
  }

}

check "complete_topology" {
  assert {
    condition     = toset(keys(var.nodes)) == toset(keys(local.data_links))
    error_message = "Every Path B node must have an explicit ordered data-plane interface plan."
  }
}

check "intent_management_complete" {
  assert {
    condition     = toset(keys(var.nodes)) == toset(keys(local.fabric_intent.nodes))
    error_message = "Path B sizing entries and intent/fabric.yaml nodes must be identical."
  }
}

check "known_image_override_nodes" {
  assert {
    condition     = length(setsubtract(toset(keys(var.node_image_overrides)), toset(keys(var.nodes)))) == 0
    error_message = "node_image_overrides contains a node that is not present in var.nodes."
  }
}

check "pinned_vyos_image" {
  assert {
    condition     = lower(filesha256(var.vyos_image_path)) == lower(var.vyos_image_sha256)
    error_message = "vyos_image_path does not match vyos_image_sha256; use the exact reviewed VyOS image."
  }
}

check "pinned_linux_image" {
  assert {
    condition     = lower(filesha256(var.linux_image_path)) == lower(var.linux_image_sha256)
    error_message = "linux_image_path does not match linux_image_sha256; use the exact reviewed Linux image."
  }
}

check "pinned_override_images" {
  assert {
    condition = alltrue([
      for image in values(var.node_image_overrides) : lower(filesha256(image.path)) == lower(image.sha256)
    ])
    error_message = "A node_image_overrides path does not match its reviewed SHA-256 digest."
  }
}

output "node_mgmt_ips" {
  value = { for k, v in local.management_plan : k => v.address }
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
