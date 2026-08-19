# terraform/vyos-fabric — real VM path (Terraform + libvirt/KVM + VyOS)

This replaces the containerlab FRR/nftables devices with **actual routed VMs**
running [VyOS](https://vyos.io) — a real, open-source network OS (Debian-based,
Linux kernel routing/firewalling, BGP/OSPF/VRRP, CLI closely modeled on
Cisco/Juniper). This path validates the design against real router/firewall
software rather than the lightweight container implementation.

## Supported image paths

- ✅ **VyOS**: fully real, free, downloadable, works. This module provisions it.
- ⚠️ **Cisco IOS/IOS-XE (vIOS), ASA/ASAv**: proprietary Cisco software. It is
  distributed only through licensed channels (Cisco CML/VIRL, dCloud, or a
  support contract with CCO login), so these images are not downloaded or
  bundled. Appropriately licensed vIOS/ASAv qcow2 exports are supported by
  setting `nodes.<name>.image` to the local file path (see
  `terraform.tfvars.example`); the disk/network/cloud-init wiring is generic.
  Using Cisco images also requires translating `configs/<name>.boot` into
  IOS/ASA config syntax
  (the intent — same IPs, same ACLs, same BGP/OSPF/VRRP — carries over 1:1,
  see `docs/ARCHITECTURE.md`).

## Getting a VyOS image

1. Rolling release (free, no login) — follow the current curl command in the
   official docs, the exact build filename changes often:
   https://docs.vyos.io/en/latest/installation/virtual/libvirt.html
2. LTS release (more stable, requires a free/paid support.vyos.io account):
   https://support.vyos.io/
3. Either image works — pick cloud-init-enabled qcow2, put the path in
   `terraform.tfvars` as `vyos_image_path`.

## Sizing

6 VMs × 1 vCPU / 1GB RAM = minimum ~6 vCPU / 6GB RAM just for the fabric,
in addition to the resources allocated to SIEM/IDS/Kubernetes. A laptop with 16GB RAM can run
the fabric alone comfortably; running fabric + docker-compose security stack
+ Kubernetes simultaneously realistically needs 32GB+. See
`docs/TESTING-GUIDE.md` for the recommended phased test order.

## Usage

```bash
cd terraform/vyos-fabric
cp terraform.tfvars.example terraform.tfvars   # fill in real paths/keys
terraform init
terraform plan
terraform apply
terraform output node_mgmt_ips
```

Then configure via Ansible (network_cli, not SSH-into-Linux like the
container path):

```bash
cd ../../ansible
ansible-playbook -i inventory/vm-fabric.yml playbooks/30-vyos-fabric.yml
```

## Current validation status and known gaps

- **A live apply is in progress on an external KVM host, but the six VyOS VMs
  have not yet reached the first-boot checkpoint.** Config.boot syntax is written
  from VyOS 1.3 documentation and may need small fixes for the target
  version — especially `firewall{}`, which was rewritten to a zone-based
  model in 1.4/1.5. Boot one node, run `configure && load config.boot && commit`,
  and fix whatever the parser rejects before scripting the rest.
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
