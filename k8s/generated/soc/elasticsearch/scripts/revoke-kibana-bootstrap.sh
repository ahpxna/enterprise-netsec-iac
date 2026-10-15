#!/usr/bin/env bash
# Revoke the broad saved-object importer immediately after a successful import.
# The persistent Kibana server keeps using only its built-in kibana_system user.
set -euo pipefail

curl --silent --show-error --fail-with-body --cacert /certs/ca.crt \
  --user "elastic:${ELASTIC_PASSWORD}" \
  -X DELETE "https://elasticsearch:9200/_security/user/cxyz_kibana_bootstrap"

echo "SOC Kibana bootstrap identity revoked"
