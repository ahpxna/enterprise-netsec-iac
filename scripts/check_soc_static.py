#!/usr/bin/env python3
"""Static fail-closed checks for the SOC ingestion MVP."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
SERVICES = COMPOSE["services"]
ERRORS: list[str] = []


def require(condition: bool, message: str) -> None:
    if not condition:
        ERRORS.append(message)


def load_json(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text())


def role_streams(role: dict) -> set[str]:
    return {
        stream
        for grant in role.get("indices", [])
        for stream in grant.get("names", [])
    }


def role_grant(role: dict, stream: str) -> dict | None:
    return next(
        (grant for grant in role.get("indices", []) if stream in grant.get("names", [])),
        None,
    )


REQUIRED_SOC_SCHEMAS = {
    "schemas/ecs/soc-event.schema.json",
    "schemas/ecs/soc-raw-event.schema.json",
    "schemas/events/anomaly-event-v1.schema.json",
    "schemas/events/correlation-decision-event-v1.schema.json",
    "schemas/events/dataset-manifest-v1.schema.json",
    "schemas/events/model-provenance-v1.schema.json",
    "schemas/features/network-window-v1.schema.json",
    "schemas/features/endpoint-window-v1.schema.json",
    "schemas/response/action-request.schema.json",
    "response/schemas/response-command-v1.schema.json",
    "response/schemas/response-audit-event-v1.schema.json",
}
for relative in REQUIRED_SOC_SCHEMAS:
    path = ROOT / relative
    require(path.is_file(), f"missing required SOC schema: {relative}")
    if path.is_file():
        try:
            schema = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            ERRORS.append(f"invalid required SOC schema {relative}: {exc}")
            continue
        require(
            schema.get("$schema", "").endswith("2020-12/schema"),
            f"SOC schema must use draft 2020-12: {relative}",
        )
        require(schema.get("type") == "object", f"SOC schema must describe an object: {relative}")
        require("$id" in schema, f"SOC schema must have a stable ID: {relative}")


for name in ("soc-cert-init", "elasticsearch", "soc-account-setup", "logstash", "kibana", "soc-kibana-setup", "soc-kibana-bootstrap-revoke"):
    require(name in SERVICES, f"missing SOC service: {name}")
    require("soc" in SERVICES.get(name, {}).get("profiles", []), f"{name} must remain profile-scoped")

es = SERVICES.get("elasticsearch", {})
require(not es.get("ports"), "Elasticsearch must never publish a host port")
es_env = es.get("environment", {})
for setting in (
    "xpack.security.enabled",
    "xpack.security.http.ssl.enabled",
    "xpack.security.transport.ssl.enabled",
):
    require(str(es_env.get(setting, "")).lower() == "true", f"Elasticsearch lost {setting}=true")
require("elastic_data:/usr/share/elasticsearch/data" in es.get("volumes", []), "Elasticsearch data is not persistent")

kibana = SERVICES.get("kibana", {})
require(kibana.get("ports") == ["127.0.0.1:5602:5601"], "Kibana must bind only to loopback:5602")
require(str(kibana.get("environment", {}).get("SERVER_SSL_ENABLED", "")).lower() == "true", "Kibana HTTPS is disabled")
require("revoke-kibana-bootstrap.sh" in (ROOT / "docker-compose.yml").read_text(), "SOC bootstrap account revocation job is not mounted")

bootstrap_job = SERVICES.get("soc-kibana-setup", {})
revoke_job = SERVICES.get("soc-kibana-bootstrap-revoke", {})
require(
    bootstrap_job.get("networks") == ["cxyz_soc_front"],
    "Kibana saved-object bootstrap must only reach the Kibana frontend",
)
require(
    revoke_job.get("networks") == ["cxyz_soc_backend"],
    "Kibana bootstrap revocation must only reach the Elasticsearch backend",
)
require(not bootstrap_job.get("restart"), "Kibana bootstrap importer must be one-shot")
require(not revoke_job.get("restart"), "Kibana bootstrap revocation must be one-shot")
require(
    bootstrap_job.get("command") == ["bash", "/setup/bootstrap-kibana.sh"],
    "Kibana bootstrap job must use the audited importer",
)
require(
    revoke_job.get("command") == ["bash", "/setup/revoke-kibana-bootstrap.sh"],
    "Kibana bootstrap revocation must use the audited deleter",
)
require(
    set(revoke_job.get("environment", {})) == {"ELASTIC_PASSWORD"},
    "Kibana bootstrap revocation must receive only the Elasticsearch administrator secret",
)

logstash = SERVICES.get("logstash", {})
require(not logstash.get("ports"), "Logstash must not publish synthetic or production ingestion ports")
require(logstash.get("networks") == ["cxyz_soc_backend"], "Logstash must remain isolated on the private SOC backend")
require("soc_fixtures:/fixtures" in logstash.get("volumes", []), "Logstash fixture volume is missing")
require(
    "/_node/pipelines/soc-ingestion" in " ".join(logstash.get("healthcheck", {}).get("test", [])),
    "Logstash health must require the soc-ingestion pipeline, not just a responding API (a broken pipeline crash-loops)",
)
require("dmzlab_cowrie_var:/honeypot/cowrie:ro" in logstash.get("volumes", []), "Logstash must read the honeypot log volume read-only")
for name in ("dmz-vuln", "dmz-honeypot"):
    lab = SERVICES.get(name, {})
    require(lab.get("profiles") == ["dmzlab"] and not lab.get("ports"), f"{name} must stay profile-scoped and publish no host port")
    require(lab.get("network_mode") == "container:clab-companyxyz-dmz-web", f"{name} must join the dmz-web namespace behind fw-dmz")
    require(lab.get("cap_drop") == ["ALL"] and "no-new-privileges:true" in (lab.get("security_opt") or []), f"{name} must run without capabilities")
    require(lab.get("networks") is None and not lab.get("privileged"), f"{name} must have no network of its own and not be privileged")

pipeline_dir = ROOT / "soc/logstash/pipelines"
required_pipeline_files = {
    "10-opnsense.conf",
    "20-suricata.conf",
    "30-wazuh.conf",
    "35-wazuh-archives.conf",
    "40-radius.conf",
    "45-cowrie.conf",
    "50-network-syslog.conf",
    "70-normalize-ecs.conf",
    "90-output.conf",
}
require(
    {path.name for path in pipeline_dir.glob("*.conf")} == required_pipeline_files,
    "Logstash source pipelines must exactly match the phase contract",
)
pipeline = "\n".join(path.read_text() for path in sorted(pipeline_dir.glob("*.conf")))
for token in (
    "/var/log/suricata/eve.json",
    "/var/ossec/logs/alerts/alerts.json",
    "/var/log/cxyz/soc-remote.log",
    "suricata.eve",
    "wazuh.alerts",
    "wazuh.archives",
    "firewall.syslog",
    "freeradius.auth",
    "cowrie.honeypot",
    "/honeypot/cowrie/log/cowrie/cowrie.json",
    'remove_field => ["password"]',
    'hosts => ["https://elasticsearch:9200"]',
    "ssl_certificate_authorities",
    "soc-raw-",
    '[@metadata][index_family] in ["network", "endpoint", "auth", "alerts"]',
    'index => "soc-%{[@metadata][index_family]}-%{+YYYY.MM.dd}"',
    "soc-deadletter-",
    "_parse_failure",
    "fingerprint",
    'clones => ["soc_raw"]',
    "source_authentication",
):
    require(token in pipeline, f"Logstash pipeline lost required contract: {token}")
require("ssl_verification_mode => \"none\"" not in pipeline, "Logstash TLS verification cannot be disabled")
outputs = pipeline.count("elasticsearch {")
# The writer role cannot manage templates (403 at bootstrap stops the whole pipeline); templates and
# ILM are installed by soc-account-setup and the SOC indices are plain daily indices.
for setting in ("manage_template => false", "ilm_enabled => false", "data_stream => false"):
    require(pipeline.count(setting) == outputs, f"every Elasticsearch output must set {setting}")
# The csv filter has no tag_on_failure option; Logstash refuses the whole pipeline if it is set.
for block in re.findall(r"\bcsv\s*\{(.*?)\n\s*\}", pipeline, flags=re.S):
    require("tag_on_failure" not in block, "csv filter does not support tag_on_failure")
require("soc-ai-" not in pipeline, "Logstash must not write AI-owned indices")
require("soc-response-" not in pipeline, "Logstash must not write response-owned indices")

raw_output = pipeline.split('id => "soc-raw-output"', 1)
require(len(raw_output) == 2, "Logstash raw output is missing")
if len(raw_output) == 2:
    raw_output = raw_output[1].split("} else if", 1)[0]
    require('index => "soc-raw-%{+YYYY.MM.dd}"' in raw_output, "raw events lost the raw stream")
    require('action => "create"' in raw_output, "raw events must be create-only")
    require(
        'action => "index"' not in raw_output and 'action => "update"' not in raw_output,
        "raw events must never be indexed or updated in place",
    )

raw_schema = load_json("schemas/ecs/soc-raw-event.schema.json")
require(
    raw_schema.get("properties", {}).get("cxyz", {}).get("properties", {}).get("schema_version", {}).get("const") == "soc-raw-v1",
    "raw schema version contract is missing",
)
require(
    raw_schema.get("properties", {}).get("event", {}).get("properties", {}).get("dataset", {}).get("pattern", "").endswith(r"\.raw$"),
    "raw event dataset must remain distinct from normalized events",
)
raw_template = load_json("soc/elasticsearch/templates/soc-raw-v1.json")
require(
    raw_template.get("index_patterns") == ["soc-raw-*"],
    "raw index template must only target soc-raw-*",
)
require(
    "Append-only" in raw_template.get("_meta", {}).get("description", ""),
    "raw index template must document append-only ownership",
)

writer_role = json.loads((ROOT / "soc/elasticsearch/logstash-writer-role.json").read_text())
writer_indices = {
    name for grant in writer_role["indices"] for name in grant["names"]
}
require("soc-ai-*" not in writer_indices, "Logstash role must not write AI indices")
require("soc-response-*" not in writer_indices, "Logstash role must not write response indices")
require("soc-raw-*" in writer_indices, "Logstash role lost append-only raw access")
raw_grant = role_grant(writer_role, "soc-raw-*")
require(raw_grant is not None, "Logstash role lost raw stream grant")
if raw_grant is not None:
    raw_privileges = set(raw_grant.get("privileges", []))
    require("create_doc" in raw_privileges, "Logstash raw stream must require create_doc")
    require(
        not {"create", "index", "write", "update", "delete", "all"} & raw_privileges,
        "Logstash raw stream must never permit overwrite, update, or deletion",
    )

for name in ("feature-engine-role.json", "decision-engine-role.json", "response-orchestrator-role.json"):
    require((ROOT / "soc/elasticsearch" / name).is_file(), f"missing future SOC least-privilege role: {name}")

feature_role = load_json("soc/elasticsearch/feature-engine-role.json")
decision_role = load_json("soc/elasticsearch/decision-engine-role.json")
orchestrator_role = load_json("soc/elasticsearch/response-orchestrator-role.json")
require(
    role_streams(feature_role) == {
        "soc-network-*", "soc-endpoint-*", "soc-auth-*", "soc-alerts-*", "soc-features-*",
    },
    "feature engine role must only read normalized telemetry and write feature vectors",
)
require(
    "soc-raw-*" not in role_streams(decision_role),
    "decision engine must not read raw source payloads",
)
require(
    "soc-ai-*" in role_streams(decision_role) and "soc-response-*" in role_streams(decision_role),
    "decision engine must consume AI evidence and emit a separate response stream",
)
require(
    role_streams(orchestrator_role) == {"soc-response-*"},
    "response orchestrator must only access append-only response audit data",
)
orchestrator_grant = role_grant(orchestrator_role, "soc-response-*")
if orchestrator_grant is not None:
    orchestrator_privileges = set(orchestrator_grant.get("privileges", []))
    require("create_doc" in orchestrator_privileges, "response audit must require create_doc")
    require(
        not {"create", "index", "write", "update", "delete", "all"} & orchestrator_privileges,
        "response audit role must not overwrite, update, or delete transitions",
    )

ai_template = load_json("soc/elasticsearch/templates/soc-ai-v1.json")
response_template = load_json("soc/elasticsearch/templates/soc-response-v1.json")
require(ai_template.get("index_patterns") == ["soc-ai-*"], "AI template must only own soc-ai-*")
require(response_template.get("index_patterns") == ["soc-response-*"], "response template must only own soc-response-*")
require(
    "never a raw-event overwrite" in ai_template.get("_meta", {}).get("description", ""),
    "AI stream must be documented as a new event rather than raw-event mutation",
)
require(
    "Append-only" in response_template.get("_meta", {}).get("description", ""),
    "response stream must be documented as append-only",
)

compose_text = (ROOT / "docker-compose.yml").read_text()
require("/source/ca.key" not in compose_text, "SOC CA signing key must never enter a container volume")
require("./soc/certs:/source" not in compose_text, "SOC cert init must use file-level mounts, never the CA directory")

makefile = (ROOT / "Makefile").read_text()
bootstrap_run = "docker compose --profile soc run --rm --no-deps soc-kibana-setup"
revoke_run = "docker compose --profile soc run --rm --no-deps soc-kibana-bootstrap-revoke"
require(bootstrap_run in makefile, "soc-up must execute Kibana bootstrap as a one-shot job")
require(revoke_run in makefile, "soc-up must execute Kibana bootstrap revocation as a one-shot job")
if bootstrap_run in makefile and revoke_run in makefile:
    require(
        makefile.index(bootstrap_run) < makefile.index(revoke_run),
        "Kibana bootstrap identity must be revoked immediately after import",
    )

bootstrap_script = (ROOT / "soc/kibana/bootstrap-kibana.sh").read_text()
revoke_script = (ROOT / "soc/elasticsearch/revoke-kibana-bootstrap.sh").read_text()
elastic_bootstrap = (ROOT / "soc/elasticsearch/bootstrap-elastic.sh").read_text()
require(
    "cxyz_kibana_bootstrap:" in bootstrap_script and "KIBANA_BOOTSTRAP_PASSWORD" in bootstrap_script,
    "Kibana import must use the temporary bootstrap identity",
)
require(
    r'\"roles\":[\"kibana_admin\"]' in elastic_bootstrap,
    "Kibana bootstrap identity must have an explicit bootstrap-only role",
)
require(
    "-X DELETE" in revoke_script and "_security/user/cxyz_kibana_bootstrap" in revoke_script,
    "Kibana bootstrap revocation must delete the temporary identity",
)
require(
    "KIBANA_BOOTSTRAP_PASSWORD" not in revoke_script,
    "Kibana bootstrap revocation must not retain the bootstrap credential",
)

for service, volume in (
    ("elasticsearch", "elasticsearch_certs"),
    ("kibana", "kibana_certs"),
    ("logstash", "logstash_certs"),
):
    mounts = "\n".join(str(item) for item in SERVICES[service].get("volumes", []))
    require(volume in mounts, f"{service} does not have a dedicated least-privilege certificate volume")

settings = (ROOT / "soc/logstash/config/logstash.yml").read_text()
require("dead_letter_queue.enable: true" in settings, "Logstash DLQ must be enabled")
require("queue.type: persisted" in settings, "Logstash persistent queue must be enabled")

saved_objects_text = (ROOT / "soc/kibana/saved-objects/soc-overview.ndjson").read_text()
saved_objects = [
    json.loads(line)
    for line in saved_objects_text.splitlines()
    if line.strip()
]
require(
    {item.get("type") for item in saved_objects} == {"index-pattern", "search", "dashboard"},
    "Kibana saved objects must be limited to data views, read-only searches, and dashboards",
)
data_views = {
    item["id"]: item["attributes"].get("title")
    for item in saved_objects
    if item.get("type") == "index-pattern"
}
require(
    data_views == {
        "soc-events": "soc-network-*,soc-endpoint-*,soc-auth-*,soc-alerts-*",
        "soc-ai": "soc-ai-*",
        "soc-response": "soc-response-*",
        "soc-raw": "soc-raw-*",
        "soc-deadletter": "soc-deadletter-*",
    },
    "Kibana data views must keep telemetry, AI, response, raw, and dead-letter streams separate",
)

searches = {
    item["id"]: item
    for item in saved_objects
    if item.get("type") == "search"
}
for search_id, search in searches.items():
    columns = search.get("attributes", {}).get("columns", [])
    require(
        "event.original" not in columns,
        f"Kibana saved search {search_id} must not display raw original payload",
    )
    require(
        not any(
            token in str(column).lower()
            for column in columns
            for token in ("password", "secret", "credential")
        ),
        f"Kibana saved search {search_id} must not display secret-like fields",
    )

dashboards = {
    item["id"]: item
    for item in saved_objects
    if item.get("type") == "dashboard"
}
dashboard_views = {
    "cxyz-soc-overview": "soc-events",
    "cxyz-network-nids": "soc-events",
    "cxyz-ai": "soc-ai",
    "cxyz-response": "soc-response",
}
require(
    set(dashboard_views) <= set(dashboards),
    "Kibana must retain SOC Overview, Network/NIDS, AI, and Response dashboards",
)
for dashboard_id, permitted_view in dashboard_views.items():
    dashboard = dashboards.get(dashboard_id)
    if dashboard is None:
        continue
    panel_searches = [
        ref.get("id")
        for ref in dashboard.get("references", [])
        if ref.get("type") == "search"
    ]
    require(panel_searches != [], f"Kibana dashboard {dashboard_id} must have saved-search panels")
    for search_id in panel_searches:
        search = searches.get(search_id)
        require(search is not None, f"Kibana dashboard {dashboard_id} references missing search {search_id}")
        if search is None:
            continue
        source_views = [
            ref.get("id")
            for ref in search.get("references", [])
            if ref.get("type") == "index-pattern"
        ]
        require(
            source_views == [permitted_view],
            f"Kibana dashboard {dashboard_id} crossed its data-view boundary",
        )
require(
    all(
        ref.get("id") not in {"soc-raw", "soc-deadletter"}
        for dashboard in dashboards.values()
        for ref in dashboard.get("references", [])
    ),
    "Kibana dashboards must not attach raw or dead-letter data views directly",
)
for forbidden in (
    "ELASTIC_PASSWORD",
    "KIBANA_SYSTEM_PASSWORD",
    "KIBANA_BOOTSTRAP_PASSWORD",
    "LOGSTASH_PASSWORD",
):
    require(forbidden not in saved_objects_text, f"Kibana saved objects must not contain {forbidden}")

architecture = (ROOT / "docs/SOC-AI-ARCHITECTURE.md").read_text()
require(
    "AI services cannot call either adapter directly" in " ".join(architecture.split()),
    "architecture must forbid direct AI-to-adapter calls",
)
require(
    "An anomaly alone never authorizes containment" in architecture,
    "architecture must forbid anomaly-only containment",
)
response_command = load_json("response/schemas/response-command-v1.schema.json")
require(
    response_command.get("properties", {})
    .get("authorization", {})
    .get("properties", {})
    .get("issuer", {})
    .get("const") == "decision_engine",
    "response command must originate from the decision engine",
)
response_request = load_json("schemas/response/action-request.schema.json")
require(
    response_request.get("properties", {}).get("issued_by", {}).get("const") == "decision_engine",
    "response request must originate from the decision engine",
)
for path in (ROOT / "ai").glob("**/*"):
    if not path.is_file() or path.suffix not in {".py", ".sh", ".json", ".yaml", ".yml", ".toml"}:
        continue
    source = path.read_text().lower()
    for forbidden in (
        "opnsense_api",
        "opnsense_",
        "soc_blocklist",
        "wazuh_active_response",
        "wazuh_api",
        "response/adapters",
        "response.adapters",
    ):
        require(
            forbidden not in source,
            f"AI source {path.relative_to(ROOT)} must not call or configure a privileged response adapter",
        )

for policy in ("soc-events-30d", "soc-raw-14d", "soc-deadletter-14d", "soc-features-30d", "soc-ai-90d", "soc-response-365d"):
    policy_path = ROOT / "soc/elasticsearch/ilm" / f"{policy}.json"
    require(policy_path.is_file(), f"missing Elasticsearch ILM policy: {policy}")

if ERRORS:
    print("SOC static checks FAILED:")
    for error in ERRORS:
        print(f" - {error}")
    raise SystemExit(1)

print("OK: SOC ingestion plane retains TLS, isolation, persistence, source, ECS, DLQ, and dashboard contracts")
