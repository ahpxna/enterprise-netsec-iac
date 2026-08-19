variable "libvirt_uri" {
  description = "libvirt connection URI"
  type        = string
  default     = "qemu:///system"
}

variable "vyos_image_path" {
  description = <<-DESC
    Absolute path to a VyOS qcow2 image on the libvirt host (rolling or LTS,
    cloud-init enabled). Download instructions in README.md. Used as the
    default base image for every node unless overridden per-node in
    var.nodes[*].image.
  DESC
  type = string
}

variable "management_network" {
  description = "libvirt network name for the 10.1.1.0/24 management plane"
  type        = string
  default     = "cxyz-mgmt"
}

variable "ssh_public_key" {
  description = "Public key injected via cloud-init for the vyos user"
  type        = string
}

# ---------------------------------------------------------------------
# One entry per fabric device. `image` may be overridden per node with
# an appropriately licensed Cisco image path (for example, a vIOS edge image).
# `boot_config` points at the VyOS config.boot this module injects.
# ---------------------------------------------------------------------
variable "nodes" {
  description = "VM fabric nodes: name, mgmt IP, vCPU/RAM sizing, boot config file"
  type = map(object({
    mgmt_ip     = string
    vcpu        = number
    memory_mb   = number
    boot_config = string
    image       = optional(string) # per-node override, defaults to var.vyos_image_path
  }))
  default = {
    edge = {
      mgmt_ip     = "10.1.1.10"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/edge.boot"
    }
    fw-core = {
      mgmt_ip     = "10.1.1.20"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/fw-core.boot"
    }
    fw-dmz = {
      mgmt_ip     = "10.1.1.30"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/fw-dmz.boot"
    }
    core = {
      mgmt_ip     = "10.1.1.1"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/core.boot"
    }
    dist1 = {
      mgmt_ip     = "10.1.1.2"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/dist1.boot"
    }
    dist2 = {
      mgmt_ip     = "10.1.1.3"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/dist2.boot"
    }
  }
}
