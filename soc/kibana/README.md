# Kibana

saved-objects/soc-overview.ndjson is the version-controlled Kibana import.
Bootstrap imports it idempotently over HTTPS using a temporary management
identity, then revokes that identity; the persistent Kibana server uses only
`kibana_system`.

## Data views

The import deliberately separates telemetry from raw payloads and future
privileged-response artifacts:

| Data view | Indices | Intended audience |
|---|---|---|
| CompanyXYZ SOC Telemetry | soc-network-*, soc-endpoint-*, soc-auth-*, soc-alerts-* | SOC analysts |
| CompanyXYZ SOC AI | soc-ai-* | SOC analysts and model reviewers |
| CompanyXYZ SOC Response Audit | soc-response-* | Authorized response reviewers |
| CompanyXYZ SOC Raw Integrity | soc-raw-* | Restricted incident review only |
| CompanyXYZ SOC Dead Letter | soc-deadletter-* | Ingestion operators |

The normal dashboards do not use the raw data view. Raw source payloads and
dead-letter event.original may contain sensitive operational content; access
must be controlled through Kibana roles rather than through a broad analyst
data view.

## Dashboards

| Dashboard | Purpose | Security boundary |
|---|---|---|
| CompanyXYZ SOC Overview | Latest normalized telemetry across Suricata, Wazuh, firewall, and RADIUS | Read-only analyst view |
| CompanyXYZ Network / NIDS | Network flows, firewall decisions, and Suricata alerts | Does not expose management or response credentials |
| CompanyXYZ AI | Model identity, feature schema, scores, anomaly status, and inference latency | An anomaly is correlation input, never a containment command |
| CompanyXYZ Response | Decision and response lifecycle audit | Read-only; it cannot invoke actions |

Saved searches deliberately omit password fields and event.original. A
dashboard is evidence only after it reads live indexed events; its presence in
Git does not assert successful ingestion, inference, correlation, or response.
