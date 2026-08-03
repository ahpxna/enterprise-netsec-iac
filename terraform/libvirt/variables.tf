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

variable "base_image_url" {
  description = "Ubuntu cloud image used for the DC services VM"
  type        = string
  default     = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
}
