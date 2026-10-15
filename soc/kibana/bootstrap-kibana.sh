#!/usr/bin/env bash
set -euo pipefail

response="$(curl --silent --show-error --fail --cacert /certs/ca.crt \
  --user "cxyz_kibana_bootstrap:${KIBANA_BOOTSTRAP_PASSWORD}" \
  -H 'kbn-xsrf: soc-bootstrap' \
  -F file=@/setup/saved-objects/soc-overview.ndjson \
  'https://kibana:5601/api/saved_objects/_import?overwrite=true')"

printf '%s' "$response" | grep -q '"success":true' || {
  echo "Kibana saved-object import failed: $response" >&2
  exit 1
}
echo "SOC Kibana data views and dashboards are current"
