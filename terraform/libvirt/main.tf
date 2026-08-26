# =====================================================================
# Optional heavyweight path: a real KVM VM for the SIEM/DC-services host,
# for deployments that outgrow containers or move to a home Proxmox server.
# The containerlab + docker path (make up) needs NONE of this — this is
# here to preserve a clean separation between Terraform provisioning and
# Ansible configuration.
# =====================================================================

resource "libvirt_pool" "cxyz" {
  name = "cxyz"
  type = "dir"
  target { path = "/var/lib/libvirt/images/cxyz" }
}

resource "libvirt_volume" "dc_base" {
  name   = "dc-base.qcow2"
  pool   = libvirt_pool.cxyz.name
  source = var.base_image_path
  format = "qcow2"
}

resource "libvirt_volume" "dc_disk" {
  name           = "dc-services.qcow2"
  pool           = libvirt_pool.cxyz.name
  base_volume_id = libvirt_volume.dc_base.id
  size           = 21474836480 # 20 GiB
}

resource "libvirt_cloudinit_disk" "dc" {
  name      = "dc-cloudinit.iso"
  pool      = libvirt_pool.cxyz.name
  user_data = file("${path.module}/cloud-init/user-data.yml")
}

check "pinned_dc_base_image" {
  assert {
    condition     = lower(filesha256(var.base_image_path)) == lower(var.base_image_sha256)
    error_message = "base_image_path does not match base_image_sha256; use the reviewed immutable cloud image."
  }
}

resource "libvirt_domain" "dc_services" {
  name   = "cxyz-dc-services"
  memory = var.siem_ram_mb
  vcpu   = var.siem_vcpu

  cloudinit = libvirt_cloudinit_disk.dc.id

  network_interface {
    network_name   = "default"
    wait_for_lease = true
  }

  disk { volume_id = libvirt_volume.dc_disk.id }

  console {
    type        = "pty"
    target_type = "serial"
    target_port = "0"
  }
}

output "dc_services_ip" {
  description = "Feed this into ansible/inventory for the VM-based path"
  value       = try(libvirt_domain.dc_services.network_interface[0].addresses[0], "pending")
}
