# =====================================================================
# terraform/vyos-fabric — REAL VM path (libvirt/KVM), replaces the
# containerlab FRR/nftables devices with actual VyOS routers/firewalls.
#
# HONESTY NOTE: this module provisions VyOS (open source, BSD-2-Clause,
# freely downloadable). It does NOT and cannot provision genuine Cisco
# IOS/IOS-XE (vIOS) or ASA/ASAv images — those are proprietary Cisco
# software distributed under license (CML / VIRL / dCloud / CCO login).
# I have no legal way to fetch or bundle them for you. If you already
# hold a Cisco license and have your own vIOS/ASAv qcow2/vmdk exports,
# this module's `node_image` variable is generic enough to point at
# them instead of the VyOS image — the wiring (networks, disks,
# cloud-init) works the same either way. See README.md.
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
