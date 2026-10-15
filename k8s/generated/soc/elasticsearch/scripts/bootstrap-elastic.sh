#!/usr/bin/env bash
set -euo pipefail

es="https://elasticsearch:9200"
curl_es() {
  curl --silent --show-error --fail-with-body --cacert /certs/ca.crt \
    --user "elastic:${ELASTIC_PASSWORD}" "$@"
}

curl_es -X POST "$es/_security/user/kibana_system/_password" \
  -H 'Content-Type: application/json' \
  --data "{\"password\":\"${KIBANA_SYSTEM_PASSWORD}\"}"

curl_es -X PUT "$es/_security/role/cxyz_logstash_writer" \
  -H 'Content-Type: application/json' \
  --data-binary @/setup/logstash-writer-role.json

curl_es -X PUT "$es/_security/user/cxyz_logstash" \
  -H 'Content-Type: application/json' \
  --data "{\"password\":\"${LOGSTASH_PASSWORD}\",\"roles\":[\"cxyz_logstash_writer\"],\"full_name\":\"CompanyXYZ Logstash writer\"}"

curl_es -X PUT "$es/_security/user/cxyz_kibana_bootstrap" \
  -H 'Content-Type: application/json' \
  --data "{\"password\":\"${KIBANA_BOOTSTRAP_PASSWORD}\",\"roles\":[\"kibana_admin\"],\"full_name\":\"CompanyXYZ Kibana saved-object bootstrap\"}"

# Future service roles are provisioned before their services exist. No future
# service user or credential is created here; each later phase introduces its
# own secret and can only assume this bounded role.
for role in feature-engine-role ai-event-writer-role decision-engine-role response-orchestrator-role; do
  curl_es -X PUT "$es/_security/role/cxyz_${role//-/_}" \
    -H 'Content-Type: application/json' \
    --data-binary "@/setup/${role}.json"
done

# Optional password-based service identities (Kubernetes Path C). Compose uses
# per-service API keys instead (provision-service-credentials.sh) and leaves these
# variables unset, in which case nothing is created here.
service_user() { # service_user USER ROLE PASSWORD FULL_NAME
  [ -n "$3" ] || return 0
  curl_es -X PUT "$es/_security/user/$1" \
    -H 'Content-Type: application/json' \
    --data "{\"password\":\"$3\",\"roles\":[\"$2\"],\"full_name\":\"$4\"}"
}
service_user cxyz_feature cxyz_feature_engine_role "${SOC_FEATURE_PASSWORD:-}" "CompanyXYZ feature worker"
service_user cxyz_ai_writer cxyz_ai_event_writer_role "${SOC_AI_WRITER_PASSWORD:-}" "CompanyXYZ AI enrichment writer"
service_user cxyz_decision cxyz_decision_engine_role "${SOC_DECISION_PASSWORD:-}" "CompanyXYZ decision runner"
service_user cxyz_response cxyz_response_orchestrator_role "${SOC_RESPONSE_PASSWORD:-}" "CompanyXYZ response orchestrator"

for policy in /setup/ilm/*.json; do
  name="$(basename "$policy" .json)"
  curl_es -X PUT "$es/_ilm/policy/$name" \
    -H 'Content-Type: application/json' --data-binary "@$policy"
done

for template in /setup/templates/*.json; do
  name="$(basename "$template" .json)"
  curl_es -X PUT "$es/_index_template/$name" \
    -H 'Content-Type: application/json' --data-binary "@$template"
done

echo "SOC Elasticsearch roles, users, and templates are current"
