# Proxmox path (home server)

For a physical home-cloud (Raspberry Pi, mini-PC, or NAS), point Terraform at
Proxmox instead of local libvirt:

- provider: `telmate/proxmox`
- clone a hardened Ubuntu/Debian template
- attach the same cloud-init and hand the resulting IP to Ansible

The Ansible roles and the whole `compliance/` + `tests/` layer are reused
unchanged — that portability is the point.
