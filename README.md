# CompanyXYZ-NG — Enterprise Network Security as Code

CompanyXYZ-NG is a reproducible enterprise network-security lab built from
open-source infrastructure components. The repository combines a three-tier
routed fabric, DMZ isolation, dual-ISP edge routing, centralized logging,
intrusion detection, zero-trust access, infrastructure provisioning,
configuration management, and evidence-backed compliance checks.

The default fabric uses containerlab, FRRouting, and nftables. The security
plane uses Wazuh, Suricata, Traefik, Authentik, and WireGuard. Terraform and
Ansible provide optional VM-based deployment and day-2 configuration paths.

## Validation status

| Path | Scope | Status |
|---|---|---|
| A | containerlab fabric + Docker Compose security plane | Complete on an external Linux lab host |
| B | Terraform/libvirt + VyOS VM fabric | In progress |
| C | Kubernetes security plane | Manifests implemented; live deployment unverified |

The Path A validation run completed on 2026-08-18. Ansible reported
`failed=0`, the live validation suite passed 10/10 checks, and the compliance
report generated on the lab host showed 10/10 PASS. The corresponding evidence
bundle remains on that host. Generated reports remain local evidence artifacts
and are excluded from Git.

Path B reached libvirt network creation during a live apply. The legacy
provider rejected `/30` CIDRs in `libvirt_network.addresses`; the module now
creates addressless isolated Layer-2 networks and assigns point-to-point
addresses inside VyOS. VyOS first-boot validation remains pending.

Path C has schema-valid manifests but has not completed live-cluster
validation. Resource sizing, readiness probes, and security-policy behavior
remain open validation items.

## Quick start

Prerequisites for the default path are Docker, Docker Compose, containerlab,
Ansible Core, Terraform, and Python 3.11 or newer.

```bash
git clone <repository-url>
cd enterprise-netsec-iac
make preflight
make secrets
make up
make configure
make audit
```

The lifecycle is:

1. `make preflight` checks required tooling.
2. `make secrets` creates local credentials and keys excluded from Git.
3. `make up` starts the routed fabric and security services.
4. `make configure` applies CIS-aligned Ansible roles.
5. `make audit` runs policy tests, live validation, attack replay, and report generation.

The generated compliance report is written to
`evidence/COMPLIANCE-REPORT.md`. The Wazuh dashboard is served at
`https://localhost:5601` when the SIEM profile is running.

## Deployment paths

The fabric and security-plane targets are independent.

| Path | Fabric | Security plane |
|---|---|---|
| A — default | containerlab + FRR/nftables | Docker Compose |
| B — real NOS | Terraform + libvirt + VyOS VMs | Docker Compose |
| C — Kubernetes | Path A or Path B fabric | Kubernetes |

Path B is documented in
[terraform/vyos-fabric/README.md](terraform/vyos-fabric/README.md). Path C is
documented in [k8s/README.md](k8s/README.md).

Cisco IOS and ASA images are proprietary and are not downloaded or distributed
by this repository. Licensed images may be supplied through the optional
per-node image override in the VyOS fabric module, with corresponding
configuration translation.

## Architecture

The logical design contains:

- dual external routing through ISP1 and ISP2;
- an edge BGP router;
- a core OSPF routing layer;
- redundant distribution gateways with VRRP;
- a default-deny core firewall;
- an isolated DMZ firewall and web segment;
- centralized Wazuh logging and alerting;
- Suricata network detection;
- Traefik and Authentik application access control;
- WireGuard remote-access transport.

The full topology and data flows are documented in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Evidence model

Compliance state is derived from machine-readable evidence rather than prose.
`compliance/controls.yaml` is the source of truth. Each control references a
validation test, and `compliance/generate_report.py` marks a control PASS only
when the latest evidence bundle contains a successful result for that test.

Expected states are:

- `PASS`: the current evidence satisfies the control;
- `FAIL`: the test ran and observed a violation;
- `UNVERIFIED`: no valid evidence exists for the current report.

Evidence bundles and generated reports under `evidence/` remain outside
version control.

## Repository layout

```text
.
├── clab/                     # containerlab topology and FRR/nftables configs
├── terraform/
│   ├── libvirt/              # VM path for the DC-services host
│   ├── proxmox/              # design notes; module not yet implemented
│   └── vyos-fabric/          # optional real-VyOS fabric
├── ansible/                  # hardening and network/service configuration
├── docker/                   # SIEM, IDS, and zero-trust configuration
├── k8s/                      # Kubernetes security-plane alternative
├── compliance/               # controls, mappings, and report generation
├── tests/
│   ├── validation/           # live checks that emit evidence
│   └── batfish/              # offline policy tests used in CI
├── scripts/                  # deployment, secret, URL, and attack utilities
├── evidence/                 # generated evidence and reports; gitignored
└── .github/workflows/        # NetDevOps CI
```

## Security lifecycle

The repository models the following repeatable workflow:

1. Build the fabric and security plane.
2. Apply hardened configuration through Ansible.
3. Validate routing, segmentation, and host controls.
4. Replay the documented attack chain.
5. Generate a compliance report from captured evidence.

Offline Batfish checks run without a live lab and guard segmentation policy
before merge. Live pytest checks verify behavior against running nodes.
`scripts/attack_chain.sh` exercises recon, scanning, escalation controls, and
failover while collecting SIEM-visible evidence.

## Technical references

- [Architecture](ARCHITECTURE.md)
- [VyOS VM fabric](terraform/vyos-fabric/README.md)
- [Kubernetes security plane](k8s/README.md)
- [Control-to-test mapping](compliance/mappings/cyb-to-repo.md)

## License

The project is distributed under the [MIT License](LICENSE).
