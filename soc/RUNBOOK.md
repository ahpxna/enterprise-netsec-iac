# SOC analytics operations

## Start and inspect

```bash
make secrets
make soc-up
make soc-health
make soc-status
```

Kibana listens on `https://127.0.0.1:5602`. Trust `soc/certs/ca.crt` locally
and authenticate as an authorized Elastic user. Never copy `soc/certs/ca.key`
into a container, evidence bundle, or browser trust store.

`make soc-up` is intentionally ordered:

1. copy only the CA certificate and each service's own leaf identity into
   separate named volumes;
2. wait for Elasticsearch health;
3. apply built-in-account passwords, least-privilege Logstash role, ILM, and
   index templates;
4. wait for Logstash and Kibana;
5. idempotently import version-controlled Kibana objects.

## Data paths

| Dataset | Runtime source | Owner |
|---|---|---|
| `suricata.eve` | `/var/log/suricata/eve.json` | Suricata container/bind mount |
| `wazuh.alerts` | `/var/ossec/logs/alerts/alerts.json` | Wazuh Manager volume |
| `firewall.syslog` | authenticated `/var/log/cxyz/soc-remote.log` records from firewall hosts | mTLS syslog relay |
| `freeradius.auth` | authenticated relay records tagged by FreeRADIUS | FreeRADIUS + mTLS relay |
| `network.syslog` | remaining authenticated network-device records | mTLS syslog relay |

Logstash reads these locations read-only. It has no network path to the fabric
and publishes no ingestion port. Synthetic smoke input exists only in the
`soc_fixtures` named volume and is written through an explicit operator exec.

## Dashboards and data access

The version-controlled import provides four read-only dashboards:

| Dashboard | Reads | Operational question |
|---|---|---|
| SOC Overview | normalized telemetry | What is the current cross-source security picture? |
| Network / NIDS | network, firewall, and Suricata events | Which network paths and IDS signals need triage? |
| AI | `soc-ai-*` | Which model, feature schema, score, and latency produced an anomaly? |
| Response | `soc-response-*` | Was a decision applied, verified, expired, or rolled back? |

The matching data views are deliberately distinct: normal telemetry
(`soc-network-*`, `soc-endpoint-*`, `soc-auth-*`, `soc-alerts-*`), AI
(`soc-ai-*`), response audit (`soc-response-*`), raw integrity
(`soc-raw-*`), and dead-letter (`soc-deadletter-*`). Standard analyst
dashboards do not read raw records. `event.original` is retained for repair
and restricted incident review, not casual dashboard display.

Kibana is an evidence and review surface only. It has no response controls and
does not create an AI-to-firewall shortcut. A response is represented in the
Response dashboard only after the decision runner and orchestrator write an
append-only `soc-response-*` audit event.

## Failure handling

- JSON, syslog, RADIUS, or firewall parser failures go to
  `soc-deadletter-YYYY.MM.dd` with `event.original`, tags, and `error.message`.
- Elasticsearch document-level 400/404 failures go to the persistent Logstash
  DLQ. An unreachable Elasticsearch endpoint is retried from the persistent
  queue and is not mislabeled as a DLQ event.
- `cxyz.ingestion_id` is a deterministic SHA-256 fingerprint and is used as the
  Elasticsearch document ID, so replaying the same source record overwrites
  rather than inflating event counts.
- `make soc-status` reports cluster state, per-dataset counts, and every raw,
  normalized, feature, AI, response, and dead-letter stream count without
  printing credentials.

## Retention and shutdown

Normalized events use `soc-events-30d`; raw records use `soc-raw-14d`; parser
failures use `soc-deadletter-14d`. Change retention through version-controlled ILM policies,
not ad-hoc API calls.

`make soc-down` removes only SOC service containers and retains all named
volumes. It does not stop Wazuh, Suricata, ZTNA, or other Compose profiles.

## AI and response planes

### Prerequisites and start

```bash
make soc-up                       # analytics plane (above)
# train, evaluate and promote a model first - see ai/training/README.md
make soc-ai-promote CANDIDATE=<dir> APPROVER=<name>   # prints metadata_sha256
# put the printed digest in .env as SOC_AI_METADATA_SHA256 (an independent channel,
# not next to the registry) and the real revision in SOC_GIT_SHA
make soc-ai-preflight             # refuses to start without approvals, PKI and signing key
make soc-ai-up                    # features, inference API, enrichment, decision, orchestrator
make soc-ai-status                # per-stream counts and service state
```

`SOC_PATH=path-a|path-b` selects the deployment (`response/deployments/<path>/`): Path A
enforces with nftables on `fw-core`/`fw-dmz`, Path B with the VyOS API (and the controlled
`pc1` endpoint through Wazuh Active Response; provision the least-privilege Wazuh API user with
`make soc-ai-wazuh-user`). Every service runs read-only as uid 10001 with its *own* credential
volume (`soc_run_*`); no service receives another's credentials, and `soc-service-init` never
receives a CA signing key. Only the decision runner holds the Ed25519 signing key; the
orchestrator holds the public key.

### Shipped state: observe

Both response services start in `observe` mode. The runner records eligible decisions as
**analyst alerts** (`decision.outcome: alert`, no `response_request_id`); the orchestrator
accepts nothing and applies nothing. Review the false-positive rate in the Response and AI
dashboards for as long as you need before enabling anything.

### Enabling automatic response (a deliberate decision)

1. Confirm the protections in the policy: `protected_ips` / `protected_networks` / `protected_hosts`,
   `allowed_isolation_hosts` (empty by default; Path B enrols only `pc1`), TTL and rate limit.
2. Edit `mode: observe` to `mode: enforce` in **both** `response/deployments/<path>/{decision,response}.yaml`,
   review and commit the change, and restart: `make soc-ai-up`.
3. To go back, revert the commit and run `make soc-ai-up` again. Containment already applied expires on its
   own: nftables elements carry a firewall-side timeout, and the orchestrator's TTL sweep reverts the rest.

Never set `SOC_MODE=enforce` in `.env` for standing operation: the override exists only for the live
validation below, and `make soc-ai-restore` removes it.

### Live validation

```bash
python -m pip install -r requirements-soc-live.txt
make soc-ai-validate              # Path A (make vm-audit runs the same verifiers for Path B)
```

`soc-ai-validate-up` recreates only the decision runner and orchestrator with `SOC_MODE=enforce` and the
60-second validation policy, the tests drive a **controlled scenario** (TEST-NET source addresses, tagged
fixtures, an injected anomaly standing in for model output), and `soc-ai-restore` returns the services to the
reviewed observe configuration afterwards. The scenario blocks a few documentation-range addresses for about a
minute; it also stops Elasticsearch briefly for LOG-03 and restores it. Evidence is written under
`evidence/runs/<timestamp>/`; run it in the same `make` invocation as `validate`/`attack` (or use `make audit`)
so one strict report covers every control. A precondition that is not met (enforcement off, a missing endpoint)
produces `ERROR`, never a pass. Until it has run, controls LOG-01..03, AI-01..04, COR-01, RESP-01..03 and SOC-01..03
are `UNVERIFIED`.

### Failure behaviour

- Elasticsearch down: the orchestrator keeps applying, verifying and expiring from its SQLite journal and resumes
  audit export; the decision runner and workers retry and never skip.
- Model missing, tampered or unapproved: the API answers 503 `MODEL_NOT_READY`; static Wazuh/Suricata detection is
  unaffected and no automatic response can originate from the AI path.
- Orchestrator restart: startup recovery compensates unfinished operations before any command is accepted.
- A firewall peer unreachable: apply/verify fail closed, a partial apply is compensated, and the failure is audited
  (`FAILED`); the recovery sweep retries with backoff.

### Kubernetes (Path C)

`make k8s-soc-image` (build and, with `K8S_IMAGE_LOADER="kind load docker-image"`, load the image), `make k8s-up`,
`make k8s-soc-model` (copies `ai/registry/active` into the model PVC and re-verifies its provenance inside the
cluster), re-render `make k8s-runtime-config` after setting `SOC_AI_METADATA_SHA256`, then `make k8s-smoke`. Endpoint
isolation is not configured in Path C until the Wazuh API certificate carries the in-cluster name; `isolate_host`
fails closed with `BACKEND_NOT_CONFIGURED` meanwhile.

## Assurance boundary

The source tree, dashboard definitions and offline tests do not prove live behaviour. Verified offline in this
repository: parsers' contracts, feature/model/evaluation/promotion pipelines, signing, the decision runner,
orchestrator, every transport against in-process TLS servers, the enforcement agent and Active Response script, the
verifiers' own logic (against an in-process lab), static trust-boundary invariants (with mutation tests) and the
Kubernetes manifests' API-schema validity. **Not verified anywhere in this repository's CI:** the Docker, containerlab,
VyOS and Kubernetes runtime behaviour, image builds, a real Wazuh/VyOS API, the Logstash pipelines on real input, and
the VLAN 30/40/50/99, Core-SPAN and OPNsense-HA network-fidelity gate (the lab fabric is nftables/VyOS; RESP-04 stays
planned). Those are proven only by `make soc-smoke`, `make soc-ai-validate`, `make vm-audit` and `make k8s-smoke` on
lab hosts.
