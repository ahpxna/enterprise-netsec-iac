# CompanyXYZ-NG — Enterprise Network Security as Code

CompanyXYZ-NG is a reproducible automated SOC and AI-assisted detection and
response research platform. Network-security IaC remains its foundation for
isolation, realistic telemetry, controlled attack scenarios, and evidence.
The repository combines a three-tier routed fabric, DMZ isolation, dual-ISP
edge routing, centralized detection, zero-trust access, infrastructure
provisioning, configuration management, and evidence-backed compliance checks.

The default fabric uses containerlab, FRRouting, and nftables. The security
plane uses Wazuh, Suricata, Traefik, Authentik, and WireGuard. Terraform and
Ansible provide optional VM-based deployment and day-2 configuration paths.

## Validation status

| Path | Scope | Status |
|---|---|---|
| A | containerlab fabric + Docker Compose security plane | Architecture remediated; live revalidation required |
| B | Terraform/libvirt + VyOS VM fabric | Infrastructure topology implemented; VyOS configuration, Day-2 security controls, HA, and Path-B-specific evidence remain unvalidated |
| C | Kubernetes security plane | Manifests implemented; live deployment unverified |

An earlier Path A run completed on 2026-08-18 on an external Linux host, but it
predates the current topology, firewall, identity, logging, and evidence-engine
changes. It is historical information, not current compliance evidence. Run
`make audit` again before claiming PASS for the present revision. Generated
reports remain local evidence artifacts and are excluded from Git.

Path B consumes the same `intent/fabric.yaml` topology as Path A and includes
all 12 nodes. Libvirt creates addressless isolated Layer-2 networks, while
point-to-point addresses are assigned inside the guests; this avoids treating
small transit networks as libvirt-managed DHCP networks. Data-plane NICs are
created first with stable MAC addresses and management is always appended last.
The inventory is rendered from the same intent, and `vm-configure` requires a
verified local `ansible/inventory/known_hosts` file before it will connect.
`make vm-health` is the current Path-B bootstrap gate; it is deliberately not
an alias for the Containerlab `make audit` suite.

Path C has source-validated manifests but has not completed live-cluster
validation. NetworkPolicy, exact runtime Kubernetes-API egress for Traefik,
service health probes, Wazuh trust wiring, declarative Authentik bootstrap, and
Suricata-to-Wazuh agent forwarding are declared in source; their CNI/runtime
behavior and resource sizing still require `make k8s-smoke` on the target
cluster.

## Quick start

Prerequisites for the default path are Docker, Docker Compose, containerlab,
Ansible Core, Terraform, and Python 3.11 or newer. The historical FRR 9.1.0
container used by live Path A is pinned as a `linux/amd64` single-platform
manifest; Apple-silicon/macOS development should use `make dev-check` rather
than treating Path A live execution as architecture-portable.

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

`TIME-01` is intentionally host-scoped: configure the Linux host chrony service
from `host/chrony-cxyz.sources.example` (or an equivalent NTS policy) so the
kernel clock inherited by Docker workloads is authenticated, then verify it
with `make host-time-check`. A tracking-only chronyd inside a container is not
accepted as clock enforcement.

`VPN-01` is an end-to-end live assurance check. `make validate` prepares and
starts the ignored `vpn-probe` peer, requires a recent WireGuard handshake,
proves the client route uses `wg0`, reaches the approved DC SSH target, and in
the same run proves direct WAN SSH is denied.

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
- Traefik and declaratively bootstrapped Authentik application access control
  for a distinct `ztna-demo-app` (not the canonical routed `dmz-web` asset);
- WireGuard remote-access transport with an end-to-end peer-to-DC fixture.

The full topology and data flows are documented in
[ARCHITECTURE.md](ARCHITECTURE.md). The accepted SOC analytics, AI, correlation,
and response boundaries are documented in
[SOC-AI-ARCHITECTURE.md](docs/SOC-AI-ARCHITECTURE.md).

## Evidence model

Compliance state is derived from machine-readable evidence rather than prose.
`compliance/controls.yaml` is the source of truth. Each control references a
validation test, and `compliance/generate_report.py` marks a control PASS only
when the latest evidence bundle contains a successful result for that test.

Expected states are:

- `PASS`: the current evidence satisfies the control;
- `FAIL`: the test ran and observed a violation;
- `ERROR`: the test or evidence artifact was invalid;
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
├── soc/                      # Logstash, Elasticsearch, and Kibana analytics plane
├── ai/                       # features, training, models, inference, and evaluation
├── response/                 # policy engine, orchestrator, and privileged adapters
├── schemas/                  # versioned event, feature, and response contracts
├── compliance/               # controls, mappings, and report generation
├── tests/
│   ├── validation/           # live checks that emit evidence
│   ├── batfish/              # offline policy tests used in CI
│   └── soc/                  # SOC architecture/schema contract gates
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
- [SOC/AI closed-loop architecture](docs/SOC-AI-ARCHITECTURE.md)
- [Frozen NetSec baseline](docs/NETSEC-BASELINE.md)
- [VyOS VM fabric](terraform/vyos-fabric/README.md)
- [Kubernetes security plane](k8s/README.md)
- [Authentik lifecycle migration](docs/AUTHENTIK-UPGRADE.md)
- [PKI rotation](docs/PKI-ROTATION.md)
- [Security implementation ledger](docs/SECURITY-IMPLEMENTATION-LEDGER.md)
- [Control-to-test mapping](compliance/mappings/cyb-to-repo.md)
- [Security implementation ledger](docs/SECURITY-IMPLEMENTATION-LEDGER.md)
- [Container image supply-chain policy](docs/IMAGE-SUPPLY-CHAIN.md)

Container image selection is tracked in `supply-chain/images.lock.yml`.
`make image-lock-check` is deterministic/offline and runs in CI;
`make verify-image-platforms` performs explicit online OCI index/platform
verification on a networked Docker host. Use `make supply-chain-scan` for the
separate SBOM/Trivy audit.

## License

The project is distributed under the [MIT License](LICENSE).
