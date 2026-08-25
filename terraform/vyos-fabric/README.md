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

1. Select one **exact VyOS 1.4.x** cloud-init-enabled qcow2 build. The checked
   `config.boot` grammar and live audit target VyOS 1.4.x; do not point this
   deployment at a moving `rolling/current` artifact.
2. Record the local qcow2 SHA-256 in `vyos_image_sha256`. Terraform refuses an
   image whose digest differs from the reviewed value.
3. Select one exact cloud-init-enabled Ubuntu 24.04 (or compatible) qcow2 for
   the four endpoint VMs and record its SHA-256 in `linux_image_sha256`.
4. Before expanding to all nodes, boot one disposable VyOS VM and verify that
   the exact selected image can load, commit, and save the repository config.

## Sizing

The default topology creates 12 VMs: eight 1GB VyOS nodes, three 512MB Linux
endpoints, and one 1GB Linux server. Budget approximately 11GB RAM plus host
overhead for Path B alone. Running the fabric with the security stack or
Kubernetes realistically requires 32GB or more.

## Stable interface model

Data-plane NICs are attached first and map to `eth0..ethN`; the management NIC
is attached last. Infrastructure and the trusted admin workstation use the
`10.1.1.0/24` OOB network. Untrusted `pc1` and `dmz-web` use the separate
`10.1.2.0/24` isolated endpoint-harness network, which has no libvirt forwarding;
this preserves host-side SSH for Ansible/evidence without giving those endpoints
a Layer-2 path around the routed firewalls. Every interface also receives a
deterministic MAC address. Linux cloud-init matches and renames interfaces by
MAC, while each VyOS `config.boot` declares its final management interface as
DHCP with no imported default route. The plan displays the proposed
`node_interface_plan`; after apply, inspect the same mapping with:

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

Terraform first boot intentionally keeps BGP/OSPF adjacencies down by using
per-node non-secret bootstrap authentication tokens. Long-lived routing secrets
never enter Terraform state; Ansible injects them only after the management SSH
trust boundary has been established.

Before any Ansible connection, verify each VM SSH host key from its console or
trusted hypervisor inventory and store it in `ansible/inventory/known_hosts`.
The file is intentionally local-only; the automation refuses to disable host
verification. Then run the complete Path-B lifecycle:

```bash
cd ../..
make vm-configure
make vm-health
make vm-idempotency
# Establish at least one WireGuard peer handshake within 10 minutes before
# vm-audit so VPN-01 has a real remote-access positive control.
make vm-audit
```

## Current validation status and known gaps

- **The expanded 12-node topology has not yet passed a live first-boot
  checkpoint in this repository revision.** `scripts/check_vyos_boot.py`
  catches repository invariants, but only the exact qcow2 can prove parser and
  runtime compatibility. Pin one VyOS 1.4.x image and checksum, boot one node,
  and load/commit/save its config before deploying the full fabric.
- The first live apply exposed the legacy dmacvicar/libvirt 0.8 `/30`
  validation limit. Data-plane CIDRs now live in `local.link_plan`, while
  `mode = "none"` creates addressless isolated Layer-2 networks. This avoids
  DHCP validation and prevents the host bridge from consuming either VyOS
  endpoint address. Inspect the plan via `terraform output data_plane_link_plan`.
- `make vm-audit` now contains a Path-B-specific 13-control live audit,
  including a real libvirt suspend/resume VRRP failover measurement. It does
  **not** reuse the Containerlab `docker exec` validation backend. These checks
  remain UNVERIFIED until they pass on the actual KVM/libvirt host.
