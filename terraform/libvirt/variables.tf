variable "libvirt_uri" {
  description = "libvirt connection URI"
  type        = string
  default     = "qemu:///system"
}

variable "siem_vcpu" {
  type    = number
  default = 2
}

variable "siem_ram_mb" {
  type    = number
  default = 4096
}

variable "base_image_path" {
  description = "Absolute path to the reviewed Ubuntu cloud image used for the DC services VM"
  type        = string
}

variable "base_image_sha256" {
  description = "SHA-256 of base_image_path; required so Terraform never consumes a mutable current cloud-image URL"
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{64}$", var.base_image_sha256))
    error_message = "base_image_sha256 must be a 64-character SHA-256 hexadecimal digest."
  }
}

variable "ssh_public_key" {
  description = "Reviewed SSH public key installed for the ansible bootstrap user"
  type        = string

  validation {
    condition     = can(regex("^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]+( .*)?$", trimspace(var.ssh_public_key)))
    error_message = "ssh_public_key must be a complete OpenSSH public key, not a placeholder."
  }
}
