# SOC analytics plane

Elasticsearch, Logstash, and Kibana form the primary analytics plane. Wazuh
Manager remains the endpoint HIDS, FIM, static-rule, and Active Response
engine; its `alerts.json` is tailed read-only by Logstash.

## Runtime

```bash
make secrets
make soc-up
make soc-health
make soc-smoke
```

When started, Kibana is available only on `https://127.0.0.1:5602`.
Elasticsearch has no published host port. The local CA signing key stays on
the operator host and is not mounted into any container. `make soc-down` stops
services without deleting the persistent Elasticsearch, Logstash queue/DLQ,
Kibana, or certificate volumes.

The profile ingests:

- `/var/log/suricata/eve.json` as `suricata.eve`;
- `/var/ossec/logs/alerts/alerts.json` as `wazuh.alerts`;
- authenticated relay output `/var/log/cxyz/soc-remote.log`, classified as
  `firewall.syslog`, `freeradius.auth`, or `network.syslog`.

The existing Ansible `syslog_tls` role sends server and network-device logs to
the mTLS relay. The RADIUS role configures authentication outcomes to syslog
while explicitly keeping successful and failed passwords out of messages.

Integration fixtures use a Docker named volume and `docker exec`, not a network
listener. They exercise the same filters without modifying source-owned log
files. Exact source payloads first go to append-only `soc-raw-*`; parser
failures go to `soc-deadletter-*` without losing `event.original`. Normalized
events are split across `soc-network-*`, `soc-endpoint-*`, `soc-auth-*`, and
`soc-alerts-*`; Elasticsearch mapping failures additionally enter the
persistent Logstash DLQ.

The version-controlled Kibana import contains distinct data views for
normalized telemetry, AI events, response audit events, raw integrity records,
and dead-letter records. Four read-only dashboards cover SOC Overview,
Network/NIDS, AI, and Response. Raw payloads are deliberately absent from the
ordinary analyst dashboards. Their existence is not a runtime assurance claim
until `make soc-smoke` succeeds on the target host.

## Workers

`workers/` holds the Python services that sit between Elasticsearch and the AI/response planes. Each runs under its own least-privilege Elasticsearch role (`elasticsearch/*-role.json`):

| Worker | Role | Does |
|---|---|---|
| `features.py` | `cxyz_feature_engine_role` | closed five-minute windows -> `soc-features-*`, idempotent by vector ID |
| `enrichment.py` | `cxyz_ai_event_writer_role` | pulls vectors, scores them over mTLS (with window history for sequence models), writes `soc-ai-*` through an SQLite outbox |
| `export_events.py` | feature identity | exports normalized events for dataset building (never `event.original`) |
| (`response/service`) | decision / orchestrator roles | see [`../response/README.md`](../response/README.md) |

See [RUNBOOK.md](RUNBOOK.md) for data ownership, failure semantics, retention, the AI/response lifecycle, live
validation, and the explicit assurance boundary.
