#!/usr/bin/env bash
set -euo pipefail

# Kibana reports healthy before it has registered its application privileges
# with Elasticsearch; until then kibana_admin requests get 403. Retry only that
# case, for a bounded time, and fail on anything else.
deadline=$((SECONDS + 180))
while :; do
  code="$(curl --silent --show-error --cacert /certs/ca.crt \
    --user "cxyz_kibana_bootstrap:${KIBANA_BOOTSTRAP_PASSWORD}" \
    -H 'kbn-xsrf: soc-bootstrap' \
    -F file=@/setup/saved-objects/soc-overview.ndjson \
    -o /tmp/import.json -w '%{http_code}' \
    'https://kibana:5601/api/saved_objects/_import?overwrite=true')"
  [[ "$code" == 403 && SECONDS -lt deadline ]] || break
  echo "Kibana privileges not registered yet (HTTP 403); retrying ..." >&2
  sleep 5
done
response="$(cat /tmp/import.json)"

[[ "$code" == 200 ]] && printf '%s' "$response" | grep -q '"success":true' || {
  echo "Kibana saved-object import failed (HTTP $code): $response" >&2
  exit 1
}
echo "SOC Kibana data views and dashboards are current"
