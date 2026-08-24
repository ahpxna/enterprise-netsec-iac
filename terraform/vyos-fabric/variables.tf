variable "libvirt_uri" {
  description = "libvirt connection URI"
  type        = string
  default     = "qemu:///system"
}

variable "vyos_image_path" {
  description = <<-DESC
    Absolute path to the pinned, cloud-init-enabled VyOS qcow2 image on the
    libvirt host. The exact version and digest are mandatory for a
    reproducible deployment. Used as the default base image unless overridden in
    var.node_image_overrides.
  DESC
  type        = string
}

variable "vyos_image_sha256" {
  description = "SHA-256 digest of the exact VyOS qcow2 selected for this deployment"
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{64}$", var.vyos_image_sha256))
    error_message = "vyos_image_sha256 must be a 64-character SHA-256 hexadecimal digest."
  }
}

variable "linux_image_path" {
  description = <<-DESC
    Absolute path to a cloud-init-enabled Linux qcow2 image on the libvirt
    host. Ubuntu 24.04 cloud images are supported. This image is used for the
    pc1, pc4, server1, and dmz-web endpoint VMs.
  DESC
  type        = string
}

variable "linux_image_sha256" {
  description = "SHA-256 digest of the exact Linux cloud image selected for Path B"
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{64}$", var.linux_image_sha256))
    error_message = "linux_image_sha256 must be a 64-character SHA-256 hexadecimal digest."
  }
}

variable "management_network" {
  description = "libvirt network name for the 10.1.1.0/24 management plane"
  type        = string
  default     = "cxyz-mgmt"
}

variable "ssh_public_key" {
  description = "Public key injected through cloud-init for VyOS and Linux management access; generated into auto tfvars by make path-b-vars"
  type        = string

  validation {
    condition     = can(regex("^(ssh-|ecdsa-|sk-)[^ ]+ [A-Za-z0-9+/=]+", trimspace(var.ssh_public_key)))
    error_message = "ssh_public_key must contain a supported OpenSSH public key."
  }
}

variable "routing_secrets" {
  description = "Per-protocol routing authentication material, supplied from ignored terraform.tfvars or a secret backend"
  type = object({
    ospf_md5 = string
    bgp_isp1 = string
    bgp_isp2 = string
  })
  sensitive = true

  validation {
    condition = alltrue([
      for secret in values(var.routing_secrets) : length(secret) >= 24 && !startswith(secret, "CHANGE_ME")
    ]) && length(distinct(values(var.routing_secrets))) == length(values(var.routing_secrets))
    error_message = "All routing secrets must be unique non-placeholder values of at least 24 characters."
  }
}

variable "node_image_overrides" {
  description = "Optional reviewed node image overrides with mandatory SHA-256; unspecified nodes use their platform base image"
  type = map(object({
    path   = string
    sha256 = string
  }))
  default = {}

  validation {
    condition = alltrue([
      for image in values(var.node_image_overrides) : can(regex("^[0-9a-fA-F]{64}$", image.sha256))
    ])
    error_message = "Every node image override requires a 64-character SHA-256 digest."
  }
}

# ---------------------------------------------------------------------
# One entry per topology node containing only infrastructure-specific sizing
# and image information. Node role, management IP, attachment order, guest
# addresses, and routes are canonical in intent/fabric.yaml.
# ---------------------------------------------------------------------
variable "nodes" {
  description = "Complete Path B topology: VyOS network nodes and Linux endpoints"
  type = map(object({
    node_id     = number
    platform    = string
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
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/edge.boot"
    }
    fw-core = {
      node_id     = 20
      platform    = "vyos"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/fw-core.boot"
    }
    fw-dmz = {
      node_id     = 30
      platform    = "vyos"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/fw-dmz.boot"
    }
    core = {
      node_id     = 11
      platform    = "vyos"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/core.boot"
    }
    dist1 = {
      node_id     = 12
      platform    = "vyos"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/dist1.boot"
    }
    dist2 = {
      node_id     = 13
      platform    = "vyos"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/dist2.boot"
    }
    isp1 = {
      node_id     = 201
      platform    = "vyos"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/isp1.boot"
    }
    isp2 = {
      node_id     = 202
      platform    = "vyos"
      vcpu        = 1
      memory_mb   = 1024
      boot_config = "configs/isp2.boot"
    }
    pc1 = {
      node_id   = 111
      platform  = "linux"
      vcpu      = 1
      memory_mb = 512
    }
    pc4 = {
      node_id   = 144
      platform  = "linux"
      vcpu      = 1
      memory_mb = 512
    }
    server1 = {
      node_id   = 50
      platform  = "linux"
      vcpu      = 1
      memory_mb = 1024
    }
    dmz-web = {
      node_id   = 61
      platform  = "linux"
      vcpu      = 1
      memory_mb = 512
    }
  }
}
