#!/usr/bin/env bash
# One-shot job: give every SOC service its OWN credential set in its OWN volume.
#
#  * Elasticsearch API keys, scoped by the least-privilege role JSON of that
#    service. Re-running KEEPS a key that still authenticates as that service
#    with the same role: Compose re-runs this job on every `up` of a dependent
#    service, and rotating then would invalidate the key a running worker holds
#    (it would get HTTP 401 until restarted). A key is rotated when it is
#    missing, rejected (invalidated, expired), its role JSON changed, or
#    SOC_ROTATE_SERVICE_KEYS=1 (make soc-ai-rotate-keys). Services re-read the
#    key file when it changes, so a rotation needs no restart.
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

key_is_current() { # key_is_current KEY_NAME ROLE_FILE DEST_DIR
  local name="$1" role="$2" dest="$3" reply
  [ "${SOC_ROTATE_SERVICE_KEYS:-0}" != 1 ] || return 1
  [ -s "$dest/es.key" ] && [ -s "$dest/es.key.role" ] || return 1
  [ "$(sha256sum "$role" | cut -d' ' -f1)" = "$(cat "$dest/es.key.role")" ] || return 1
  reply="$(curl --silent --fail --cacert /certs/ca.crt -H "Authorization: ApiKey $(cat "$dest/es.key")" \
    "$es/_security/_authenticate" 2>/dev/null)" || return 1
  printf '%s' "$reply" | grep -q '"authentication_type":"api_key"' &&
    printf '%s' "$reply" | grep -Eq "\"api_key\":\{[^}]*\"name\":\"$name\""
}

api_key() { # api_key KEY_NAME ROLE_FILE DEST_DIR
  local name="$1" role="$2" dest="$3" body response encoded previous
  if key_is_current "$name" "$role" "$dest"; then
    chown "$uid":0 "$dest/es.key" "$dest/es.key.role"
    chmod 0400 "$dest/es.key" "$dest/es.key.role"
    kept=$((kept + 1))
    return 0
  fi
  # The active keys of this service, invalidated only once the new one is in place (below).
  previous="$(curl_es "$es/_security/api_key?name=$name&active_only=true" 2>/dev/null |
    grep -o '"id":"[^"]*"' | sed 's/^"id"://' | paste -sd, - || true)"
  body="$(printf '{"name":"%s","expiration":"90d","role_descriptors":{"%s":%s}}' \
    "$name" "$name" "$(tr -d '\n' < "$role")")"
  response="$(curl_es -X POST "$es/_security/api_key" -H 'Content-Type: application/json' --data "$body")"
  encoded="$(printf '%s' "$response" | sed -n 's/.*"encoded":"\([^"]*\)".*/\1/p')"
  [ -n "$encoded" ] || { echo "could not create API key $name" >&2; exit 1; }
  printf '%s' "$encoded" > "$dest/.es.key.new"
  sha256sum "$role" | cut -d' ' -f1 > "$dest/.es.key.role.new"
  chown "$uid":0 "$dest/.es.key.new" "$dest/.es.key.role.new"
  chmod 0400 "$dest/.es.key.new" "$dest/.es.key.role.new"
  mv -f "$dest/.es.key.role.new" "$dest/es.key.role"
  # rename(2) is atomic: a running worker (it re-reads the file when it changes) sees the old or the new key.
  mv -f "$dest/.es.key.new" "$dest/es.key"
  # Only now invalidate the previous key: a worker picks up the new file on its next request, so there is
  # no moment in which the file holds a key that Elasticsearch already rejects.
  if [ -n "$previous" ]; then
    curl_es -X DELETE "$es/_security/api_key" -H 'Content-Type: application/json' \
      --data "{\"ids\":[$previous]}" >/dev/null
  fi
  rotated=$((rotated + 1))
}

kept=0
rotated=0

for dir in ai-api feature enrichment decision response; do
  mkdir -p "/out/$dir"
  # Fresh files every run, except the API key api_key() decides to keep or rotate.
  find "/out/$dir" -mindepth 1 ! -name es.key ! -name es.key.role -delete
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

echo "SOC service credentials are provisioned (values not shown); API keys kept: $kept, rotated: $rotated"
