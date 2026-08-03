terraform {
  required_version = ">= 1.6.0"
  required_providers {
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "~> 0.8.1"
    }
  }
}

# Local KVM/libvirt so this runs on a laptop with no cloud spend.
# For a Proxmox home-server later, swap this provider for telmate/proxmox
# (see terraform/proxmox/) — the module interface stays the same.
provider "libvirt" {
  uri = var.libvirt_uri
}
