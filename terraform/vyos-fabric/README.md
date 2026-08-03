# terraform/vyos-fabric — real VM path (Terraform + libvirt/KVM + VyOS)

This replaces the containerlab FRR/nftables devices with **actual routed VMs**
running [VyOS](https://vyos.io) — a real, open-source network OS (Debian-based,
Linux kernel routing/firewalling, BGP/OSPF/VRRP, CLI closely modeled on
Cisco/Juniper). This is the path to use if you specifically want "real
router/firewall software", not containers pretending to be one.

## What this can and cannot give you

- ✅ **VyOS**: fully real, free, downloadable, works. This module provisions it.
- ⚠️ **Cisco IOS/IOS-XE (vIOS), ASA/ASAv**: proprietary Cisco software. It is
  distributed only through licensed channels (Cisco CML/VIRL, dCloud, or a
  support contract with CCO login) — I have no legal way to download, bundle,
  or generate these images for you, and won't attempt to source them from
  unofficial mirrors. **If you already hold a Cisco license** and have your
  own vIOS/ASAv qcow2 exports, this module is built to accept them: set
  `nodes.<name>.image` to your file path (see `terraform.tfvars.example`) —
  the disk/network/cloud-init wiring is generic. You'll need to translate
  `configs/<name>.boot` into IOS/ASA config syntax yourself in that case
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
on top of whatever you run for SIEM/IDS/k8s. A laptop with 16GB RAM can run
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

## Known gaps / what I have NOT verified

- **Never booted against a real VyOS image in this session** (no libvirt/KVM
  available in the sandbox that built this). Config.boot syntax is written
  from VyOS 1.3 documentation and may need small fixes for your exact
  version — especially `firewall{}`, which was rewritten to a zone-based
  model in 1.4/1.5. Boot one node, `configure && load config.boot && commit`,
  and fix whatever the parser rejects before scripting the rest.
- `libvirt_network` resources using `mode = "none"` for point-to-point links
  are a reasonable modeling choice but less common than bridged setups —
  verify your libvirt/dmacvicar provider version supports it, or switch
  those to `mode = "route"` with static routes on the host if not.
- No HA/failover test has been run against real VRRP on VyOS yet — the
  `dist1`/`dist2` priorities are set, but `make audit`'s `HA-01` control
  still needs a live failover test against these VMs specifically (the
  existing `attack_chain.sh::step5_vrrp_failover` currently targets the
  container fabric).
