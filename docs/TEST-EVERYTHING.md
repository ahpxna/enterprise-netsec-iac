# Run the whole pipeline and test every corner

This is the complete test plan for the repository, from checks that need nothing but Python up to the three live
deployment paths. Every command below exists in the `Makefile` or `scripts/`. The one-command runner
(`./scripts/try-on-linux.sh`, see [LINUX-QUICKSTART.md](LINUX-QUICKSTART.md)) runs levels 0–2 for you. This page
explains what each step proves, how to run any piece on its own, and which corners still need a person.

## What has actually been run (be honest about it)

| Layer | Run for real? | Where |
|---|---|---|
| Level 0: static gates, 383 unit/contract tests, Logstash compile gate | yes, every push | GitHub Actions + macOS |
| SOC plane: `soc-up`, `soc-smoke` | yes | Docker Desktop, macOS arm64 (throwaway project) |
| Honeypot path: Cowrie → Logstash → `soc-alerts-*`, redaction, decision signal (`honeypot_e2e.py`) | yes, including a negative test | same |
| AI/response plane: demo model, `soc-ai-up` (observe), features → inference → decisions | yes | same |
| Live SOC/AI verifiers (`make soc-ai-validate`) | partly; see the results table at the end | same, without a fabric |
| Path A fabric (containerlab, FRR, nftables), Wazuh, ZTNA, VPN, hardening, attack chain, enforcement on firewalls | **partly**: one full run on Kali Linux (2026-10-18): fabric, DMZ lab, RTR-01 and enforcement (COR-01, RESP-01/03, SOC-01..03) PASS; `configure`, the VPN probe, DET-01 and the VRRP failover failed (ledger INC-076) | Linux x86-64 |
| Path B (Terraform/libvirt/VyOS) | **no** | needs a KVM host |
| Path C (Kubernetes) | **no** (manifests are schema-validated offline only) | needs a cluster |

## Which machine for which level

| Level | Machine | Time (first run) |
|---|---|---|
| 0 offline | anything with Python 3.11–3.13 (macOS fine); Docker optional (Batfish, Logstash gate) | minutes |
| 1 SOC + AI only | any Docker host, 8 GiB for Docker (macOS/arm64 fine) | 15–30 min |
| 2 full Path A | Linux **x86-64**, sudo, 12 GiB RAM, 25 GiB disk | ~1 h, mostly image pulls |
| 3 Path B | KVM/libvirt host, ~11 GiB for the VMs (32 GiB with the security stack), a VyOS 1.4.x qcow2 | hours |
| 4 Path C | k3s single node, 4 vCPU / 8 GiB free | ~1 h |

---

## Level 0: no containers

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-ci.txt -r requirements-soc-test.txt -r requirements-soc-live.txt
./scripts/try-on-linux.sh --offline  # renders --check, static gates, pytest (writes logs/try-linux/<time>/report.md)
make dev-check                       # CI parity incl. Compose/Kustomize render, yamllint, ansible-lint (needs docker CLI, kubectl)
```

What it proves: generated configs match the single intent (`render_* --check`), security/SOC/AI invariants
(isolation, least privilege, fail-closed defaults, protected networks, pinned images, CI contract), 27 controls wired
to verifiers, 383 unit and contract tests (decision engine, signed commands, orchestrator journal/TTL/rollback,
feature pipeline, model promotion, honeypot redaction regexes, runner, explorer).

Extra offline corners, each its own command:

| Corner | Command | Proves |
|---|---|---|
| Logstash pipelines compile on the pinned Logstash (needs Docker) | `make soc-logstash-check` | no unknown plugin setting, both Compose and Kubernetes trees |
| Firewall policy, pre-merge | `docker run -d -p 9996:9996 -p 9997:9997 batfish/allinone@sha256:445818fc17c0e24eb097387c84184334ad3fc42807de1ed9fef773762a0be515` then `pip install -r requirements-batfish.txt && make batfish` | the rendered firewall/routing snapshot satisfies the policy tests |
| Explorer model is consistent | `python scripts/netviz.py --check` | topology, IP plan and flows derived from the sources agree |
| Images pinned and multi-arch | `make image-lock-check` and (online) `make verify-image-platforms` | every external image is locked by digest with amd64/arm64 |
| Vulnerabilities and SBOM (needs Trivy) | `make supply-chain-scan` | no HIGH/CRITICAL in locked images and IaC |
| Secrets in history | `make lint` (includes gitleaks) | no credential in any commit |
| Kubernetes manifests | `kubectl kustomize k8s/ >/dev/null && python scripts/check_k8s_schema.py` | Path C renders and matches the v1.30 API schemas |

## Level 1: SOC + AI planes on any Docker host

```bash
make soc-up                          # compiles the pipelines first, then ES + Logstash + Kibana (TLS, least privilege)
make soc-smoke                       # 4 sources + a malformed line -> normalized, raw copy, dead letter, dashboard
python scripts/demo_registry.py --write-env   # DEMO model (synthetic: proves wiring only)
make soc-ai-up                       # features, inference (mTLS), enrichment, decision, orchestrator - observe mode
make soc-ai-status                   # per-stream counts and service state
```

On Linux, `./scripts/try-on-linux.sh --quick` does all of this, plus the offline levels and a management network for the
orchestrator. On macOS, create that network yourself before `soc-ai-up` (and remove it afterwards):
`docker network create --subnet 10.1.1.0/24 cxyz_mgmt`.

> **Do not experiment in your real project by accident.** `docker-compose.yml` names the project `cxyz-security`. For a
> throwaway run, use a copy of the repository and `export COMPOSE_PROJECT_NAME=cxyzscratch` before every `make` (tear
> down with `docker compose --profile soc --profile soc-ai down -v` in that copy).

Healthy looks like: all containers `healthy`/`Up` with `RestartCount` 0 after a few minutes
(`docker ps --format '{{.Names}} {{.Status}}'`), the enrichment worker printing `"sent": N` for its outbox, the decision
worker printing `outcomes` such as `alert`, and **nothing** in any firewall blocklist (observe mode).

## Level 2: the full Path A lab (Linux x86-64)

```bash
./scripts/try-on-linux.sh            # everything; add --with-lstm for control AI-04
```

The stages, in order, and what each proves:

| Stage | Proves |
|---|---|
| `host-*`, `deps-*` | the host can run the lab (CPU, RAM, disk, sudo, Docker, containerlab, sysctl, Python) |
| `offline-*` | level 0 on this host |
| `secrets`, `images`, `dc-network`, `wazuh-config` | secrets/PKI are generated, local images build, the DC bridge exists with fabric addresses reserved |
| `fabric-up`, `fabric-verify` | 12 nodes up, containment sets present on both firewalls, enforcement agents listening |
| `security-up` | Wazuh, Suricata, ZTNA gateway, DMZ app start |
| `soc-up`, `soc-smoke` | ingestion works end to end |
| `demo-model`, `soc-ai-up` | the AI/response loop starts in observe mode |
| `dmzlab-up`, `dmzlab-verify` | Juice Shop and Cowrie answer from pc1 through fw-dmz, fw-dmz counts them, the DMZ host cannot reach internal zones |
| `dmzlab-siem` | a real Telnet session from pc1 reaches `soc-alerts-*` as `cowrie.honeypot`, the password appears nowhere (normalized and raw), and the decision runner turns it into one `honeypot` signal |
| `configure` | Ansible hardening applies |
| `validate` | routing health (RTR-01) then SEG-01/02, IDM-01/02, DET-02, HRD-01/02, TIME-01, VPN-01, ZTNA-01 |
| `attack` | DET-01 (a scan from pc1 is detected and alerts in Wazuh), HA-01 (routed traffic keeps flowing through dist2 while dist1 is down; no interruption of 5 s or more) |
| `soc-validate` | LOG-01..03, AI-01..04, COR-01, RESP-01, RESP-03, SOC-01..03 with lab enforcement for ~10 min, then observe mode again |
| `report` | `evidence/COMPLIANCE-REPORT.md` from the evidence just written |

A failed stage prints where (command, make target and line, failing test), the likely cause and the fix, and the
command that re-runs only that stage (`--only <stage>`). Stages after a failure still run if they do not depend on it.

Expected, not bugs: **TIME-01** fails until the host clock uses authenticated NTS (`make host-time-check`); **AI-04**
fails without `--with-lstm`; **RESP-02** applies to Path B only; **RESP-04** is a planned control with no verifier.

### Corners worth poking by hand (Path A running)

| Corner | How | Expected |
|---|---|---|
| Observe mode never blocks | after `soc-ai-up`, before `soc-validate`: `docker exec clab-companyxyz-fw-core nft list set inet cxyz soc_blocklist` (and `fw-dmz` table `dmz`) | empty |
| Enforcement is switched off again | after `soc-validate`: same command, and `docker inspect $(docker compose ps -q soc-response) --format '{{range .Config.Env}}{{println .}}{{end}}' \| grep SOC_MODE` | blocklists drain within the TTL; `SOC_MODE=` is empty (observe) |
| A scan is seen | `make attack` then Kibana `soc-alerts-*`, dataset `suricata.eve` | alerts from pc1 |
| Web attacks are seen | `make dmzlab-attack` then Kibana, dataset `suricata.eve`; `make dmzlab-status` | Suricata alerts; fw-dmz counters move |
| The DMZ cannot pivot | part of `dmzlab-verify` and `dmzlab-attack` | `ok : dmz-web cannot reach ...` |
| Honeypot to SIEM, redaction | `make dmzlab-siem-check` | `PASS: honeypot session -> SIEM ...` |
| Campus NAT is never contained | the `dmzlab-siem` output for pc1 | `protected network: never contained, by design` |
| Elasticsearch outage is accounted, not lost | part of `soc-validate` (LOG-03 stops Elasticsearch briefly) | LOG-03 PASS |
| Wrong or tampered model refuses to serve | part of `soc-validate` (AI-02, AI-03) | PASS |
| Anomaly alone never contains | part of `soc-validate` (COR-01) | PASS |
| TTL, rate limit, rollback, audit chain | part of `soc-validate` (RESP-03, SOC-03) | PASS |
| Live map | `make netviz`, open http://127.0.0.1:8088, run `soc-validate` and watch the containment set | entries appear with expiry, then disappear |
| Service credentials survive re-runs and rotate without a restart | `make soc-ai-up` twice, then `docker compose --profile soc-ai logs soc-service-init \| tail -2`; then `make soc-ai-rotate-keys` and `docker compose logs --since 5m elasticsearch \| grep -c 'has been invalidated'` | `API keys kept: 4, rotated: 0` on re-runs; after a rotation the workers keep working and Elasticsearch logs no invalidated key in use |
| Teardown and restart are clean | `./scripts/try-on-linux.sh --teardown`, then `./scripts/try-on-linux.sh --from secrets` | same results; data volumes kept |
| Hardening is idempotent (exploratory) | run `make configure` twice | second `PLAY RECAP` ideally `changed=0` (not asserted by any test yet) |

## Level 3: Path B (real VyOS VMs)

Follow [terraform/vyos-fabric/README.md](../terraform/vyos-fabric/README.md) for the image and sizing; then:

```bash
make preflight-path-b
cp terraform/vyos-fabric/terraform.tfvars.example terraform/vyos-fabric/terraform.tfvars   # reviewed image paths + SHA-256
make vm-init && make vm-plan && make vm-up
# verify every VM SSH host key from its console into ansible/inventory/known_hosts (automation refuses otherwise)
make vm-configure && make vm-health && make vm-idempotency
# one WireGuard peer handshake within 10 minutes, then:
make vm-audit                        # 13 network + 14 SOC controls, real libvirt VRRP failover; enforcement only during the audit
make vm-down
```

Report: `evidence/PATH-B-COMPLIANCE-REPORT.md`. RESP-02 (endpoint isolation through Wazuh) is a Path B control.

## Level 4: Path C (Kubernetes)

```bash
curl -sfL https://get.k3s.io | sh -s - --disable=traefik && export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
make preflight-k8s
make k8s-up                          # renders runtime secrets/config from the same PKI and .env, applies Kustomize
make k8s-soc-image                   # kind: K8S_IMAGE_LOADER="kind load docker-image"; minikube: "minikube image load"
docker save cxyz/soc-python:local | sudo k3s ctr images import -     # k3s: import the image yourself
make k8s-soc-model                   # copies the approved registry into the PVC and re-verifies it in the cluster
make k8s-smoke                       # jobs complete, NetworkPolicies, ZTNA over trusted TLS, observe mode, model digest, ES auth
make k8s-status
make k8s-down
```

See [k8s/README.md](../k8s/README.md): endpoint isolation fails closed on Path C until the Wazuh API certificate is
reissued with the in-cluster name.

## After any run

* Per-stage logs, `report.md`, `report.json`: `logs/try-linux/<time>/`
* Evidence per control and the report: `evidence/runs/<time>/`, `evidence/COMPLIANCE-REPORT.md`
* Kibana https://127.0.0.1:5602 (user `elastic`), explorer http://127.0.0.1:8088, `make urls` for the rest
* Stop, keeping data: `./scripts/try-on-linux.sh --teardown`

## Results of the Docker Desktop run (2026-10-17, macOS arm64, throwaway project, no fabric)

| Check | Result | Notes |
|---|---|---|
| `make soc-up` from an empty project (includes `soc-logstash-check`) | PASS | Logstash is reported healthy only once `soc-ingestion` is loaded |
| `make soc-smoke` | PASS | 4 sources, raw copy, dead letter, dashboard |
| `scripts/honeypot_e2e.py` (Cowrie on a scratch network, attacker container) | PASS | negative test with the redaction removed: FAIL, naming the 3 leaking fields |
| LOG-01, LOG-02, LOG-03 | PASS | LOG-03 stops Elasticsearch; the event is held and delivered once |
| AI-01, AI-02, AI-03 | PASS | |
| AI-04 | FAIL, expected | the DEMO registry has no five-detector comparison without `--with-lstm` |
| COR-01, RESP-01, RESP-03, SOC-01, SOC-02, SOC-03 | FAIL, no fabric | containment needs the nftables agents on fw-core/fw-dmz; the orchestrator fails closed (`NFTABLES_HA_REVERT_FAILED`) and audits the failure. All six now report that single cause |
| `make soc-ai-up` repeated, `make soc-ai-rotate-keys` | PASS | re-runs keep the 4 service keys; after a rotation, 0 requests with an invalidated key, no restarts |

The first attempt of this run found the bugs recorded as INC-075 in the security ledger (credential rotation on every
`compose up`, the LOG-03 queue counter, cascading verifier failures, `--dry-run` executing checks).
