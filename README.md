# CompanyXYZ-NG — Enterprise Network Security as Code

> A production-shaped, fully virtual enterprise network with a real blue-team
> stack (SIEM + IDS + Zero-Trust gateway), hardened by Ansible, provisioned by
> Terraform, and **validated by tests that emit evidence** — so every
> compliance claim is reproducible, not asserted.

Implements a three-tier + DMZ + dual-ISP enterprise design using open,
laptop-friendly tooling: **containerlab + FRRouting +
nftables** for the fabric, and **Wazuh / Suricata / Traefik / Authentik /
WireGuard** for security.

> **Validation status (2026-08-18): Path A is complete.** It was deployed on
> an external Linux lab host, Ansible completed with `failed=0`, the live
> validation suite passed **10/10**, and that host's generated compliance
> report showed **10/10 PASS**. The evidence bundle remains on that host, so
> the generated report committed in this checkout intentionally remains the
> no-evidence baseline. Path B is still in progress; Path C is unverified.

```bash
git clone <this-repo> && cd enterprise-netsec-iac
make preflight        # check docker / containerlab / ansible / terraform
make secrets          # generate .env + WireGuard keys + PBKDF2 hashes
make up               # build the routed fabric + security services
make configure        # push CIS-aligned config with Ansible
make audit            # batfish + live validation + attack replay + report
```

Then open the compliance report at [`docs/COMPLIANCE-REPORT.md`](docs/COMPLIANCE-REPORT.md)
and the SIEM at `https://localhost:5601`.

**Full step-by-step run/test instructions (including the real-VyOS-VM and
Kubernetes paths below): [`docs/TESTING-GUIDE.md`](docs/TESTING-GUIDE.md).**

---

## Three deployment paths, pick per component

The commands above are the fastest path (containers + Docker Compose). Two
more are available, independent of each other and of the fast path:

| Path | Fabric | Security plane | Status |
|---|---|---|---|
| **A — Fast (default)** | containerlab + FRR/nftables | docker-compose | ✅ Complete; external lab 10/10 |
| **B — Real NOS** | Terraform + libvirt + **real VyOS VMs** — [`terraform/vyos-fabric/`](terraform/vyos-fabric/), [ADR 0004](docs/adr/0004-vm-fabric-real-nos.md) | docker-compose | 🚧 In progress |
| **C — Kubernetes** | either fabric | **k8s** — [`k8s/`](k8s/), [ADR 0005](docs/adr/0005-kubernetes-security-plane.md) | ⚪ Unverified |

Note on "real Cisco/ASA": genuine Cisco IOS/ASA images are proprietary and
gated behind Cisco licensing — no automation here can legally fetch them.
The VyOS path is the real, open-source NOS substitute. Appropriately licensed
Cisco images can also be supplied per node to `terraform/vyos-fabric` (see that
directory's README).

---

## Design rationale

Earlier project iterations described security testing without retaining
machine-checkable output. The current architecture addresses that limitation:
**a control is only marked compliant when a test produced a machine-checkable
evidence file.** See [ADR 0002](docs/adr/0002-evidence-first-compliance.md).

The full old→new mapping is in
[`compliance/mappings/cyb-to-repo.md`](compliance/mappings/cyb-to-repo.md).

## What's inside

| Layer | Tech | Purpose |
|-------|------|---------|
| Fabric | containerlab, FRRouting, nftables | 3-tier campus, DMZ, dual-ISP edge |
| Provisioning | Terraform (libvirt / Proxmox) | VM path for the DC-services host |
| Config mgmt | Ansible roles | CIS-aligned hardening, RADIUS, NTP, syslog-TLS |
| SIEM | Wazuh | ingest firewall/device logs → alerts |
| IDS | Suricata | packet-level detection |
| ZTNA | Traefik + Authentik + WireGuard | secure remote access / home-cloud gateway |
| Assurance | pytest + Batfish + `controls.yaml` | evidence-first compliance |
| CI | GitHub Actions | lint, secret-scan, Batfish policy, TF validate |

## Architecture

Full diagram and data-flow walkthrough: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
A text sketch suitable for importing into draw.io lives at the top of that file.

## Repository layout

```
.
├── clab/                     # containerlab topology + device configs (FRR/nftables)
├── terraform/
│   ├── libvirt/               # VM path for the DC-services host
│   ├── proxmox/                # notes only — not yet a built module
│   └── vyos-fabric/           # REAL VyOS VMs replacing the container fabric
├── ansible/                  # roles: hardening, radius, ntp, syslog-tls, ids, vpn, vyos_edge
├── docker/                   # siem (Wazuh), ids (Suricata), zero-trust-gateway
├── k8s/                      # Kubernetes alternative to docker-compose for the security plane
├── compliance/               # controls.yaml (source of truth) + report generator
├── tests/
│   ├── validation/           # LIVE tests against the running lab (emit evidence)
│   └── batfish/              # OFFLINE config-policy tests (run in CI, no lab)
├── scripts/                  # attack_chain.sh, gen-secrets.sh, mkhash.sh, ...
├── evidence/runs/            # timestamped evidence bundles (gitignored)
├── docs/                     # ARCHITECTURE, ADRs, runbooks, generated report
└── .github/workflows/        # NetDevOps CI
```

## The security lifecycle this repo models

**Build → Harden → Validate → Attack → Report**, all reproducible:

1. **Build** — `make net` boots the fabric.
2. **Harden** — `make configure` applies Ansible roles mapped to CIS/NIST.
3. **Validate** — `make validate` runs live tests (segmentation, hardening,
   routing) that each write an evidence JSON.
4. **Attack** — `make attack` replays the CYB-240 chain (recon → scan → fallback
   → escalation-guard → failover) and captures what the SIEM saw.
5. **Report** — `make report` regenerates `docs/COMPLIANCE-REPORT.md`, where a
   control is PASS only if its evidence exists.

## Roadmap / upgrade ideas

Three paths extend the project toward operational use. Full details, technology
choices, and implementation/validation status are documented in
[`docs/PROJECT-IDEAS.md`](docs/PROJECT-IDEAS.md). **Priority: #1 and #2.**

1. **Automated SOC (Network-as-Code)** — clone → fabric + pre-wired Wazuh SIEM
   collecting from every device. (This repo already ships the core of it.)
2. **Zero-Trust home-cloud gateway** — the `ztna` profile + WireGuard is a real,
   usable secure gateway for a Pi/NAS. See [homecloud runbook](docs/runbooks/homecloud.md).
3. **DMZ vulnerability lab** — extend `docker/dmz-app` with deliberately
   vulnerable targets under Suricata watch, for pentest-tool testing / team
   training. (Detection rules already present, not yet a standalone build.)

## License and third-party notices

The project is MIT licensed. Required third-party notices and attribution are
retained in [`LICENSE`](LICENSE).
