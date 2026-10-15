#!/usr/bin/env bash
# One-shot job: give every SOC service its OWN credential set in its OWN volume.
#
#  * Elasticsearch API keys, scoped by the least-privilege role JSON of that
#    service (re-running invalidates the previous key by name, i.e. rotates it).
#  * The service's TLS identity, copied from specific host-mounted files. The CA
#    signing keys are never mounted here, so they cannot reach any service volume.
#  * Optional operator-supplied firewall / Wazuh API secrets for the orchestrator.
#
# Nothing is printed. Files are owned by the service UID (10001) and read-only.
set -euo pipefail
umask 077

es="https://elasticsearch:9200"
uid=10001

curl_es() {
  curl --silent --show-error --fail-with-body --cacert /certs/ca.crt \
    --user "elastic:${ELASTIC_PASSWORD}" "$@"
}

put() { # put SRC DEST_DIR DEST_NAME
  install -o "$uid" -g 0 -m 0400 "$1" "$2/$3"
}

put_secret() { # put_secret VALUE DEST_DIR DEST_NAME   (skips empty values)
  [ -n "$1" ] || return 0
  printf '%s' "$1" > "$2/$3"
  chown "$uid":0 "$2/$3"
  chmod 0400 "$2/$3"
}

api_key() { # api_key KEY_NAME ROLE_FILE DEST_DIR
  local name="$1" role="$2" dest="$3" body response encoded
  curl_es -X DELETE "$es/_security/api_key" -H 'Content-Type: application/json' \
    --data "{\"name\":\"$name\"}" >/dev/null 2>&1 || true
  body="$(printf '{"name":"%s","expiration":"90d","role_descriptors":{"%s":%s}}' \
    "$name" "$name" "$(tr -d '\n' < "$role")")"
  response="$(curl_es -X POST "$es/_security/api_key" -H 'Content-Type: application/json' --data "$body")"
  encoded="$(printf '%s' "$response" | sed -n 's/.*"encoded":"\([^"]*\)".*/\1/p')"
  [ -n "$encoded" ] || { echo "could not create API key $name" >&2; exit 1; }
  printf '%s' "$encoded" > "$dest/es.key"
  chown "$uid":0 "$dest/es.key"
  chmod 0400 "$dest/es.key"
}

for dir in ai-api feature enrichment decision response; do
  mkdir -p "/out/$dir"
  find "/out/$dir" -mindepth 1 -delete   # fresh credential set every run
  chown "$uid":0 "/out/$dir"
  chmod 0700 "/out/$dir"
done

# inference API: server identity + the single client CA it trusts
put /source/soc-ai-api.crt /out/ai-api tls.crt
put /source/soc-ai-api.key /out/ai-api tls.key
put /source/ai-client-ca.crt /out/ai-api client-ca.crt

# feature worker
put /certs/ca.crt /out/feature ca.crt
api_key soc-feature-engine /setup/feature-engine-role.json /out/feature

# enrichment worker (AI writer): ES key + mTLS client identity for the inference API
put /certs/ca.crt /out/enrichment ca.crt
put /source/soc-enrichment.crt /out/enrichment client.crt
put /source/soc-enrichment.key /out/enrichment client.key
api_key soc-ai-event-writer /setup/ai-event-writer-role.json /out/enrichment

# decision runner: signing key, ES key, mTLS client identity for the orchestrator
put /certs/ca.crt /out/decision ca.crt
put /source/decision-key-1.key /out/decision signing.key
put /source/soc-decision.crt /out/decision client.crt
put /source/soc-decision.key /out/decision client.key
api_key soc-decision-engine /setup/decision-engine-role.json /out/decision

# orchestrator: server identity, the decision client CA, verification KEYS ONLY,
# the client identity used toward firewall agents, ES key, optional API secrets
put /certs/ca.crt /out/response ca.crt
put /source/soc-response.crt /out/response tls.crt
put /source/soc-response.key /out/response tls.key
put /source/soc-response.crt /out/response client.crt
put /source/soc-response.key /out/response client.key
put /source/decision-ca.crt /out/response decision-ca.crt
[ ! -f /source/wazuh-root-ca.pem ] || put /source/wazuh-root-ca.pem /out/response wazuh-ca.crt
mkdir -p /out/response/keys
install -o "$uid" -g 0 -m 0444 /source/decision-key-1.pub /out/response/keys/decision-key-1.pub
chown "$uid":0 /out/response/keys
chmod 0555 /out/response/keys
put_secret "${VYOS_API_KEY:-}" /out/response vyos-api.key
put_secret "${WAZUH_RESPONSE_CREDENTIALS:-}" /out/response wazuh-response.cred
put_secret "${OPNSENSE_CREDENTIALS:-}" /out/response opnsense.cred
api_key soc-response-orchestrator /setup/response-orchestrator-role.json /out/response

echo "SOC service credentials are provisioned (values not shown)"
