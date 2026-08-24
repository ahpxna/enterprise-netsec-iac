#!/usr/bin/env bash
# Idempotent secret bootstrap. Never prints secrets to stdout. Never commits.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

[ -f .env ] || { cp .env.example .env; echo "created .env from template"; }

# Add fields introduced after an operator's initial bootstrap without replacing
# any existing local values.
for required in \
  'RADIUS_TEST_PASSWORD=CHANGE_ME_ephemeral_integration_password' \
  'RADIUS_TEST_CRYPT=CHANGE_ME_see_scripts_mkhash' \
  'RADIUS_SECRET_PC1_PROBE=CHANGE_ME_unique_pc1_probe_min_32_chars'; do
  key="${required%%=*}"
  grep -q "^${key}=" .env || printf '\n%s\n' "$required" >> .env
done

gen() { openssl rand -base64 36 | tr -d '\n'; }

# Replace CHANGE_ME_* placeholders in .env with real random values, once.
while IFS='=' read -r k v; do
  [[ "$v" == CHANGE_ME* ]] || continue
  case "$k" in
    RADIUS_ADMIN_CRYPT) new="$(bash scripts/mkhash.sh "$(gen)")";;
    RADIUS_TEST_CRYPT) continue;;
    *) new="$(gen)";;
  esac
  # portable in-place edit
  awk -v key="$k" -v val="$new" -F= 'BEGIN{OFS="="}
    $1==key{$2=val} {print}' .env > .env.tmp && mv .env.tmp .env
  echo "  set $k"
done < <(grep '=' .env)

# Keep the positive RADIUS test credential only in ignored .env; FreeRADIUS
# receives the one-way verifier below.  This proves both Accept and Reject
# behavior without placing a reusable password in source control.
test_password="$(awk -F= '$1 == "RADIUS_TEST_PASSWORD" {sub(/^[^=]*=/, ""); gsub(/^"|"$/, ""); print; exit}' .env)"
test_crypt="$(awk -F= '$1 == "RADIUS_TEST_CRYPT" {print $2; exit}' .env)"
if [[ "$test_crypt" == CHANGE_ME* ]]; then
  test_hash="$(bash scripts/mkhash.sh "$test_password")"
  awk -v val="$test_hash" -F= 'BEGIN{OFS="="}
    $1 == "RADIUS_TEST_CRYPT" {$2=val} {print}' .env > .env.tmp && mv .env.tmp .env
  echo "  set RADIUS_TEST_CRYPT"
fi

# TLS identity for the dedicated syslog relay. Private material stays local.
relay_certs="docker/syslog-relay/certs"
mkdir -p "$relay_certs"
if [ ! -f "$relay_certs/ca.crt" ]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 825 \
    -subj "/CN=CompanyXYZ Lab Logging CA" \
    -keyout "$relay_certs/ca.key" -out "$relay_certs/ca.crt" >/dev/null 2>&1
  openssl req -newkey rsa:3072 -nodes \
    -subj "/CN=syslog-relay.companyxyz.lab" \
    -keyout "$relay_certs/relay.key" -out "$relay_certs/relay.csr" >/dev/null 2>&1
  openssl x509 -req -days 397 -sha256 \
    -in "$relay_certs/relay.csr" \
    -CA "$relay_certs/ca.crt" -CAkey "$relay_certs/ca.key" -CAcreateserial \
    -extfile <(printf '%s\n' 'subjectAltName=DNS:syslog-relay.companyxyz.lab,IP:172.16.50.11') \
    -out "$relay_certs/relay.crt" >/dev/null 2>&1
  chmod 600 "$relay_certs"/*.key
  echo "  generated syslog relay CA and server certificate"
fi

# Per-node mTLS identities. The relay rejects clients that do not present one
# of these CA-signed identities, preventing unauthenticated log injection.
client_dir="$relay_certs/clients"
mkdir -p "$client_dir"
for node in server1 edge core dist1 dist2 fw-core fw-dmz; do
  cert="$client_dir/$node.crt"
  key="$client_dir/$node.key"
  if [ ! -f "$cert" ] || [ ! -f "$key" ]; then
    cn="$node.companyxyz.lab"
    openssl req -newkey rsa:3072 -nodes -subj "/CN=$cn" \
      -keyout "$key" -out "$client_dir/$node.csr" >/dev/null 2>&1
    openssl x509 -req -days 397 -sha256 \
      -in "$client_dir/$node.csr" \
      -CA "$relay_certs/ca.crt" -CAkey "$relay_certs/ca.key" -CAcreateserial \
      -extfile <(printf '%s\n' \
        'basicConstraints=CA:FALSE' \
        'keyUsage=digitalSignature,keyEncipherment' \
        'extendedKeyUsage=clientAuth' \
        "subjectAltName=DNS:$cn") \
      -out "$cert" >/dev/null 2>&1
    rm -f "$client_dir/$node.csr"
    chmod 600 "$key"
    echo "  generated syslog mTLS identity for $node"
  fi
done

# The LinuxServer WireGuard container owns its persisted configuration and
# peer keys beneath wireguard/config/.  Keeping a second unused key lifecycle
# here was misleading and risked testing the wrong credentials.
echo "secrets ready (values NOT shown; stored in .env and local service config)"
