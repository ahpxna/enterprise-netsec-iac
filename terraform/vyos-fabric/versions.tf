# =====================================================================
# terraform/vyos-fabric — REAL VM path (libvirt/KVM), replaces the
# containerlab FRR/nftables devices with actual VyOS routers/firewalls.
#
# This module provisions VyOS, an open-source network operating system.
# Cisco IOS/IOS-XE and ASA/ASAv images are proprietary and are therefore not
# downloaded or bundled. Appropriately licensed qcow2/vmdk images can be
# supplied through the per-node image setting; network, disk, and cloud-init
# wiring remain generic. See README.md.
# =====================================================================

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.8"
    }
  }
}

provider "libvirt" {
  uri = var.libvirt_uri
}
