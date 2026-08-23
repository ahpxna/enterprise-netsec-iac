# terraform/vyos-fabric — real VM path (Terraform + libvirt/KVM + VyOS)

This recreates the complete 12-node Path A topology as VMs: eight routed nodes
run [VyOS](https://vyos.io), while `pc1`, `pc4`, `server1`, and `dmz-web` run a
cloud-init-enabled Linux image. This path validates the design against real
router/firewall software and retains endpoint hosts for end-to-end testing.

## Supported image paths

- ✅ **VyOS**: used by edge, core, distribution, firewall, and ISP nodes.
- ✅ **Linux cloud image**: used by client, server, and DMZ endpoint nodes.
- ⚠️ **Cisco IOS/IOS-XE (vIOS), ASA/ASAv**: proprietary Cisco software. It is
  distributed only through licensed channels (Cisco CML/VIRL, dCloud, or a
  support contract with CCO login), so these images are not downloaded or
  bundled. Appropriately licensed vIOS/ASAv qcow2 exports are supported by
  setting `node_image_overrides.<name>` to the local file path (see
  `terraform.tfvars.example`); the disk/network/cloud-init wiring is generic.
  Using Cisco images also requires translating `configs/<name>.boot` into
  IOS/ASA config syntax. The addressing, ACL, BGP, OSPF, and VRRP intent remains
  unchanged.

## Getting a VyOS image

1. Rolling release (free, no login) — follow the current curl command in the
   official docs, the exact build filename changes often:
   https://docs.vyos.io/en/latest/installation/virtual/libvirt.html
2. LTS release (more stable, requires a free/paid support.vyos.io account):
   https://support.vyos.io/
3. Pick a cloud-init-enabled VyOS qcow2 and set `vyos_image_path`.
4. Supply a cloud-init-enabled Ubuntu 24.04 (or compatible) image through
   `linux_image_path` for the four endpoint VMs.

## Sizing

The default topology creates 12 VMs: eight 1GB VyOS nodes, three 512MB Linux
endpoints, and one 1GB Linux server. Budget approximately 11GB RAM plus host
overhead for Path B alone. Running the fabric with the security stack or
Kubernetes realistically requires 32GB or more.

## Stable interface model

Data-plane NICs are attached first and map to `eth0..ethN`; the management NIC
is attached last. Every interface also receives a deterministic MAC address.
Linux cloud-init matches and renames interfaces by MAC, while each VyOS
`config.boot` declares its final management interface as DHCP with no imported
default route. The plan displays the proposed `node_interface_plan`; after
apply, inspect the same mapping with:

```bash
terraform output node_interface_plan
```

## Usage

```bash
cd terraform/vyos-fabric
cp terraform.tfvars.example terraform.tfvars   # fill in real paths/keys
terraform init
terraform plan
terraform apply
terraform output node_mgmt_ips
```

Before any Ansible connection, verify each VM SSH host key from its console or
trusted hypervisor inventory and store it in `ansible/inventory/known_hosts`.
The file is intentionally local-only; the automation refuses to disable host
verification. Then run the complete Path-B lifecycle:

```bash
cd ../..
make vm-configure
make vm-health
```

## Current validation status and known gaps

- **The expanded 12-node topology has not yet passed a live first-boot
  checkpoint.** `terraform validate` cannot validate VyOS grammar. Pin one
  exact VyOS qcow2 version and checksum in `terraform.tfvars`, boot one node,
  then run `configure && load /config/config.boot && commit` before deploying
  the full fabric.
- The first live apply exposed the legacy dmacvicar/libvirt 0.8 `/30`
  validation limit. Data-plane CIDRs now live in `local.link_plan`, while
  `mode = "none"` creates addressless isolated Layer-2 networks. This avoids
  DHCP validation and prevents the host bridge from consuming either VyOS
  endpoint address. Inspect the plan via `terraform output data_plane_link_plan`.
- No HA/failover test has been run against real VRRP on VyOS yet — the
  `dist1`/`dist2` priorities are set, but `make audit`'s `HA-01` control
  still needs a live failover test against these VMs specifically (the
  existing `attack_chain.sh::step5_vrrp_failover` currently targets the
  container fabric).
