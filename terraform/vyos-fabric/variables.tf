variable "libvirt_uri" {
  description = "libvirt connection URI"
  type        = string
  default     = "qemu:///system"
}

variable "vyos_image_path" {
  description = <<-DESC
    Absolute path to a VyOS qcow2 image on the libvirt host (rolling or LTS,
    cloud-init enabled). Download instructions are in README.md. Used as the
    default base image for VyOS nodes unless overridden in
    var.node_image_overrides.
  DESC
  type        = string
}

variable "linux_image_path" {
  description = <<-DESC
    Absolute path to a cloud-init-enabled Linux qcow2 image on the libvirt
    host. Ubuntu 24.04 cloud images are supported. This image is used for the
    pc1, pc4, server1, and dmz-web endpoint VMs.
  DESC
  type        = string
}

variable "management_network" {
  description = "libvirt network name for the 10.1.1.0/24 management plane"
  type        = string
  default     = "cxyz-mgmt"
}

variable "ssh_public_key" {
  description = "Public key injected through cloud-init for VyOS and Linux management access"
  type        = string
}

variable "node_image_overrides" {
  description = "Optional node-name to qcow2 path overrides; unspecified nodes use their platform base image"
  type        = map(string)
  default     = {}
}

# ---------------------------------------------------------------------
# One entry per topology node. `boot_config` is required for VyOS nodes;
# Linux endpoint addressing is generated from local.interface_plan.
# ---------------------------------------------------------------------
variable "nodes" {
  description = "Complete Path B topology: VyOS network nodes and Linux endpoints"
  type = map(object({
    node_id     = number
    platform    = string
    mgmt_ip     = string
    vcpu        = number
    memory_mb   = number
    boot_config = optional(string)
  }))

  validation {
    condition = alltrue([
      for node in values(var.nodes) : contains(["vyos", "linux"], node.platform)
    ])
    error_message = "Each node platform must be either 'vyos' or 'linux'."
  }

  validation {
    condition = alltrue([
      for node in values(var.nodes) : node.node_id >= 1 && node.node_id <= 254
    ])
    error_message = "Each node_id must be unique and between 1 and 254."
  }

  validation {
    condition     = length(distinct([for node in values(var.nodes) : node.node_id])) == length(var.nodes)
    error_message = "Each node_id must be unique because it is used to derive stable MAC addresses."
  }

  validation {
    condition = alltrue([
      for node in values(var.nodes) : node.platform != "vyos" || node.boot_config != null
    ])
    error_message = "Every VyOS node must define boot_config."
  }

  default = {
    edge = {
      node_id     = 10
      platform    = "vyos"
      mgmt_ip     = "10.1.1.10"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/edge.boot"
    }
    fw-core = {
      node_id     = 20
      platform    = "vyos"
      mgmt_ip     = "10.1.1.20"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/fw-core.boot"
    }
    fw-dmz = {
      node_id     = 30
      platform    = "vyos"
      mgmt_ip     = "10.1.1.30"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/fw-dmz.boot"
    }
    core = {
      node_id     = 11
      platform    = "vyos"
      mgmt_ip     = "10.1.1.11"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/core.boot"
    }
    dist1 = {
      node_id     = 12
      platform    = "vyos"
      mgmt_ip     = "10.1.1.2"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/dist1.boot"
    }
    dist2 = {
      node_id     = 13
      platform    = "vyos"
      mgmt_ip     = "10.1.1.3"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/dist2.boot"
    }
    isp1 = {
      node_id     = 201
      platform    = "vyos"
      mgmt_ip     = "10.1.1.201"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/isp1.boot"
    }
    isp2 = {
      node_id     = 202
      platform    = "vyos"
      mgmt_ip     = "10.1.1.202"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/isp2.boot"
    }
    pc1 = {
      node_id   = 111
      platform  = "linux"
      mgmt_ip   = "10.1.1.111"
      vcpu      = 1
      memory_mb = 512
    }
    pc4 = {
      node_id   = 144
      platform  = "linux"
      mgmt_ip   = "10.1.1.144"
      vcpu      = 1
      memory_mb = 512
    }
    server1 = {
      node_id   = 50
      platform  = "linux"
      mgmt_ip   = "10.1.1.50"
      vcpu      = 1
      memory_mb = 1024
    }
    dmz-web = {
      node_id   = 61
      platform  = "linux"
      mgmt_ip   = "10.1.1.61"
      vcpu      = 1
      memory_mb = 512
    }
  }
}
