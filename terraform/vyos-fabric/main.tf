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

# One base-image volume shared as a backing file (fast COW clones per node)
resource "libvirt_volume" "base" {
  name   = "vyos-base.qcow2"
  pool   = libvirt_pool.cxyz.name
  source = var.vyos_image_path
  format = "qcow2"
}

resource "libvirt_volume" "node_disk" {
  for_each       = var.nodes
  name           = "${each.key}-disk.qcow2"
  pool           = libvirt_pool.cxyz.name
  base_volume_id = libvirt_volume.base.id
  format         = "qcow2"
}

# cloud-init ISO per node: injects hostname, SSH key, and a first-boot
# script that writes the real VyOS config.boot for that node and reboots.
resource "libvirt_cloudinit_disk" "node_ci" {
  for_each  = var.nodes
  name      = "${each.key}-cloudinit.iso"
  pool      = libvirt_pool.cxyz.name
  user_data = templatefile("${path.module}/cloud-init/user-data.tftpl", {
    hostname    = each.key
    ssh_key     = var.ssh_public_key
    boot_config = file("${path.module}/${each.value.boot_config}")
  })
  meta_data = templatefile("${path.module}/cloud-init/meta-data.tftpl", {
    hostname = each.key
  })
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

  # NIC 0: management, fixed IP via libvirt network DHCP host entry
  network_interface {
    network_name   = var.management_network
    hostname       = each.key
    addresses      = [each.value.mgmt_ip]
    wait_for_lease = false
  }

  # NIC 1..n: data-plane links — wire these to the per-segment libvirt
  # networks defined in networks.tf, matching clab's link map 1:1.
  dynamic "network_interface" {
    for_each = lookup(local.data_links, each.key, [])
    content {
      network_name   = network_interface.value
      wait_for_lease = false
    }
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

# Mirrors the `links:` section of clab/companyxyz.clab.yml so the VM
# fabric is topologically identical to the container fabric.
locals {
  data_links = {
    edge    = [libvirt_network.isp1_link.name, libvirt_network.isp2_link.name, libvirt_network.edge_fwcore.name, libvirt_network.edge_fwdmz.name]
    fw-core = [libvirt_network.edge_fwcore.name, libvirt_network.fwcore_core.name]
    fw-dmz  = [libvirt_network.edge_fwdmz.name, libvirt_network.fwdmz_dmzweb.name]
    core    = [libvirt_network.fwcore_core.name, libvirt_network.core_dist1.name, libvirt_network.core_dist2.name, libvirt_network.core_dc.name]
    dist1   = [libvirt_network.core_dist1.name]
    dist2   = [libvirt_network.core_dist2.name]
  }
}

output "node_mgmt_ips" {
  value = { for k, v in var.nodes : k => v.mgmt_ip }
}
