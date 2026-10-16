# Try the whole lab on a Linux machine with one command

```bash
git clone git@github.com:ahpxna/enterprise-netsec-iac.git && cd enterprise-netsec-iac
git checkout soc-ai
./scripts/try-on-linux.sh            # or: make try-linux
```

That is the whole procedure. The script installs what is missing, builds, starts, tests, and finishes with a table of
PASS/FAIL per stage. If anything fails it tells you **where** (stage, command, failing `make` target and line, failing
test or Python frame), **why** it most likely failed, the container logs that matter, the log file, and the exact command
that re-runs just that stage.

> **Honest status.** The runner, the explorer and every check it calls are unit-tested offline (on macOS). The SOC analytics
> plane (`soc-up`, `soc-smoke`), the honeypot ingestion path and the AI/response services in observe mode (`demo-model`,
> `soc-ai-up`) have been run for real on Docker Desktop (macOS, arm64); that run found and fixed the bugs in ledger INC-074. The Linux
> runner itself, the containerlab fabric, Wazuh, enforcement on the real firewalls and Kubernetes have **not** been run; the first run on a
> real host is the first real test of those stages. If something fails in a way the hints do not explain, send
> `logs/try-linux/<time>/report.md`.

## What you need

| | |
|---|---|
| OS | Ubuntu 24.04 / Debian 12+ / Fedora (other distros: install the tools yourself and use `--no-install`) |
| CPU | **x86-64** for the full lab (the pinned FRR fabric image is `linux/amd64` only). arm64: use `--quick` |
| RAM / disk | 12 GiB / 25 GiB free for the full lab; 8 GiB for `--quick` (Wazuh indexer + Elasticsearch are heavy) |
| Access | a user with `sudo` (packages, `sysctl`, containerlab, routes), and Internet access to pull images (Docker Hub, Elastic, GHCR, quay.io, snapshot.debian.org) |
| Time | the first run is dominated by image pulls and builds; expect tens of minutes to an hour on a good link (not measured) |

## Modes

| Command | What runs | Needs |
|---|---|---|
| `./scripts/try-on-linux.sh` | **everything**: dependencies, offline gates, 12-node containerlab fabric, Wazuh/Suricata/ZTNA, SOC analytics, AI + response (observe mode), Ansible hardening, live validation, attack replay, the live SOC/AI verifiers, compliance report | Linux x86-64, sudo |
| `./scripts/try-on-linux.sh --quick` | no fabric: dependencies, offline gates, SOC analytics + ingestion proof, demo model, AI + response (observe) | Linux, sudo |
| `./scripts/try-on-linux.sh --offline` | only checks that need no containers: static gates + 300+ tests (works on macOS) | Python |
| `--list` | print the stages | |
| `--only soc-up` / `--from soc-up` / `--skip configure` | re-run or resume (dependencies are *not* re-run with `--only`) | |
| `--fail-fast` | stop at the first failure (default: continue with stages that do not depend on it) | |
| `--no-install` | never install packages; only verify | |
| `--with-lstm` | also install CPU PyTorch and build the LSTM + five-detector comparison (needed for control AI-04) | |
| `--dry-run` | show what would run, execute nothing | |
| `--teardown` | stop the lab (volumes are kept) | |

## The stages

`host-os` (OS/CPU/RAM/disk) → `host-sudo` → `deps-packages` → `deps-docker` → `deps-docker-access` → `deps-containerlab` →
`deps-sysctl` (`vm.max_map_count`, inotify, forwarding) → `deps-python` (`.venv` + requirements) → `offline-static` (14 static
gates, one command each so a failure names the gate) → `offline-tests` (pytest) → `offline-compose` → `viz-start` (network
explorer) → `secrets` → `images` → `dc-network` → `wazuh-config` → `fabric-up` → `fabric-verify` (12 nodes, containment sets,
enforcement agents listening) → `security-up` → `soc-up` → `soc-smoke` → `demo-model` → `soc-ai-up` → `configure` → `validate`
→ `attack` → `soc-validate` → `report`.

A stage that depends on a failed stage is reported `BLOCKED by <stage>` instead of failing for the same reason again.
Stages that run *tests* (`offline-tests`, `configure`, `validate`, `attack`, `soc-validate`) are *findings*: when they fail the
run exits non-zero but later independent stages still run.

## Reading a failure

```
✗ FAILED  soc-up  (Start the SOC analytics plane ...)  exit=2  after 94s
    command : make soc-up
    where   : make target 'soc-up' failed at Makefile:121 (exit 2)
              dependency failed to start: container repo-elasticsearch-1 is unhealthy
    cause   : Elasticsearch/Wazuh indexer need a larger vm.max_map_count
    fix     : sudo sysctl -w vm.max_map_count=262144
    log     : logs/try-linux/20261015T101500Z/19-soc-up.log
    re-run  : scripts/try-on-linux.sh --only soc-up
```

Every run writes `logs/try-linux/<timestamp>/`: one `NN-<stage>.log` per stage (full output, plus the container logs
captured on failure), `report.md` and `report.json`. Nothing in `logs/` is committed.

Typical causes the runner recognises: Docker permission or daemon not running, unreachable registry/DNS/proxy, Docker Hub
rate limit, full disk, `vm.max_map_count`, a host port already in use, containerlab missing, CPU architecture mismatch,
missing management/DC network, sudo needing a password, missing Python dependency, no approved model digest, missing Wazuh
PKI, a Logstash pipeline that does not compile on the pinned Logstash (`scripts/check_logstash_config.sh` names the setting), unhealthy containers, and TIME-01 (host NTS). An unrecognised error prints the last output lines and the log path
instead of guessing.

## The network explorer (GNS3-style view)

`viz-start` launches it in the background; or run `make netviz` any time (no containers needed):

* **http://127.0.0.1:8088** — on a remote host: `ssh -L 8088:127.0.0.1:8088 user@host`, then open it locally. It is read-only,
  binds to loopback, has no authentication and never shows a secret value (only names and whether they are set).
* **Topology**: all 12 nodes, 3 L2 segments and the Docker services on the DC bridge. Drag nodes, wheel to zoom, search by
  name or **IP** (`/`). Zoom in to see every interface IP; **click** a node for its interfaces (IP, network, zone, peer),
  static routes, BGP/OSPF/VRRP, firewall chains, listening services, Path B reachability and copy-paste commands; click a
  link for both ends, CIDR, purpose, zone and VRRP VIP.
* **SOC / AI plane**: every data flow (protocol, port, authentication, data) from sources to Elasticsearch, workers, decision,
  orchestrator and the firewalls; click a flow or a service.
* Tables: **IP plan** (every subnet, gateway, member), **Routing** (adjacencies, static routes, masked protocol config),
  **Firewall** (sets, chains, rules with their comments, live containment set), **Services & ports**, **Identity & trust**
  (PKI, Elasticsearch roles, which secrets exist, what can never be auto-contained, model registry, index streams),
  **Controls** (every control with its latest evidence), **Access & commands**, **Notes & checks** (self-check of the model
  and known limits).
* **Live overlay** (needs Docker): coloured status dots per container, the real `soc_blocklist` contents with expiry on both
  firewalls, per-index document counts. When Docker is down the page says so and stays a static, accurate map.

Everything is derived from `intent/fabric.yaml`, the containerlab/FRR/nftables configs, `docker-compose.yml`, the policies and
`compliance/controls.yaml`; `python scripts/netviz.py --check` fails if the derived model is inconsistent.

## The DMZ deception lab (vulnerable web app + honeypot)

`make dmzlab-up` (the runner's `dmzlab-up`/`dmzlab-verify` stages do it for you in full mode) adds two deliberately hostile-facing services
**inside the DMZ, behind fw-dmz**: a vulnerable web application and an SSH/Telnet honeypot. They join the network namespace of the `dmz-web`
node, so they appear on the DMZ segment with its address **195.1.1.161** (ports `3000`, `2222`, `2223`); every probe crosses fw-dmz (new
connections are counted and logged as `CXYZ-DMZLAB-*`, Suricata sees them) and the existing pivot deny stops either one from reaching an internal
zone. They publish nothing on the host and run without capabilities.

| Role | Choice | Why this one |
|---|---|---|
| Vulnerable web app | **OWASP Juice Shop** (`bkimminich/juice-shop`, pinned digest) | An OWASP *flagship* project, actively maintained, modern stack (Node/Angular/REST), 100+ challenges across the OWASP Top 10 with a built-in scoreboard, and a very large body of public write-ups, which makes the traffic and the detections easy to cross-check. DVWA is the classic starter but is PHP/MySQL, small and slow-moving; Juice Shop is the better-regarded training target today. Alternatives: OWASP WebGoat (guided lessons, Java), OWASP crAPI (API security), bWAPP/Mutillidae (older). |
| Honeypot | **Cowrie** (`cowrie/cowrie`, pinned digest) | The de-facto standard medium-interaction SSH/Telnet honeypot: fake shell and filesystem, records credentials, commands and downloaded files as JSON, widely used in research. Alternatives: T-Pot (all-in-one, heavy), Dionaea (malware capture), OpenCanary (lightweight multi-protocol). |

```bash
make dmzlab-up        # needs the fabric (make net); re-run after any `make net`, the namespace it joins is recreated
make dmzlab-attack    # controlled hostile traffic from pc1: SQLi, XSS, traversal, scanner UA, telnet session; also proves the DMZ cannot pivot inward
make dmzlab-status    # containers + fw-dmz hit counters
make dmzlab-down
```

The honeypot's JSON log is mounted **read-only** into Logstash and normalized as dataset `cowrie.honeypot` into `soc-alerts-*` (attacker-supplied
passwords are redacted in the received line itself, so neither `soc-alerts-*` nor the raw copy in `soc-raw-*` stores them). The lab is for *your* isolated test network only: the vulnerable app contains real exploitable flaws.
A honeypot interaction from a source (a login attempt or worse) is also an **independent corroborating signal** for the decision engine
(`honeypot` in policy `COR-001`); together with an AI anomaly for the same address it makes that address eligible for automatic containment.
Campus attackers reach the DMZ NATed to fw-core's outside address, which is protected and never blocked, so this corroboration works for
sources outside the campus. The Cowrie image, its hardening options and the path from its log to `soc-alerts-*` and to the decision
runner's signal query were run for real; Juice Shop and the shared-namespace wiring behind fw-dmz have not been run on a real host.

## What to expect (not bugs)

* **The model is a DEMO.** `demo-model` builds an approved registry from deterministic synthetic data with relaxed promotion
  floors, so the whole loop can start. It proves wiring only; its approval note and model id say so. Replace it with a real
  captured dataset (`ai/training/README.md`) before believing any score.
* **Observe mode.** The decision runner and orchestrator ship in `observe`: eligible decisions become analyst alerts and
  nothing is blocked. `soc-validate` switches them to enforce **only for its own run**, blocks a few documentation-range
  addresses (203.0.113.x / 198.51.100.x) for about a minute, stops Elasticsearch briefly (LOG-03) and then restores observe mode.
* **TIME-01 may fail** until the host clock is disciplined by authenticated NTS (`host/chrony-cxyz.sources.example`,
  `make host-time-check`). That is the control working, not the lab.
* **AI-04 fails without `--with-lstm`** (no five-detector comparison in the registry). **RESP-04** (OPNsense HA) is a planned
  control with no verifier; **RESP-02** (endpoint isolation) applies to Path B only.
* The install steps use the official `get.docker.com` (Docker, only on distributions without a suitable package) and
  `get.containerlab.dev` installers. Use `--no-install` to skip every install and only verify.

## After the run

| What | Where |
|---|---|
| Kibana | https://127.0.0.1:5602 (user `elastic`, password = `ELASTIC_PASSWORD` in `.env`; trust `soc/certs/ca.crt`) |
| Wazuh dashboard | https://127.0.0.1:5601 (`WAZUH_DASHBOARD_PASSWORD`) |
| Network explorer | http://127.0.0.1:8088 |
| Per-control evidence | `evidence/runs/<timestamp>/`, report `evidence/COMPLIANCE-REPORT.md` |
| Lab shells | `docker exec -it clab-companyxyz-<node> sh` |
| Stop (keep data) | `./scripts/try-on-linux.sh --teardown` (also stops the explorer) |
| Stop the explorer only | `make netviz-stop` |

## The same thing by hand

```bash
make secrets && make images && make dc-network && make wazuh-config
make net && make security && make configure          # fabric + Wazuh/Suricata/ZTNA + hardening (full mode)
make soc-up && make soc-smoke
python scripts/demo_registry.py --write-env           # DEMO model; or promote a real one
make soc-ai-up                                        # observe mode
make validate && make attack && make soc-ai-validate && make report
```
