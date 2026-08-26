#!/usr/bin/env bash
# Idempotent secret bootstrap. Never prints secrets to stdout. Never commits.
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

[ -f .env ] || { cp .env.example .env; echo "created .env from template"; }
chmod 600 .env

# Add fields introduced after an operator's initial bootstrap without replacing
# any existing local values.
for required in \
  'WAZUH_REGISTRATION_PASSWORD=CHANGE_ME_agent_enrollment_min_32_chars' \
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

cert_has_days() {
  local cert="$1" days="$2"
  [ -f "$cert" ] && openssl x509 -checkend "$((days * 86400))" -noout -in "$cert" >/dev/null 2>&1
}

cert_has_dns_san() {
  local cert="$1" dns="$2"
  [ -f "$cert" ] || return 1
  openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null \
    | tr ',' '\n' | grep -Eq "^[[:space:]]*DNS:${dns//./\.}[[:space:]]*$"
}

require_signing_key() {
  local key="$1"
  [ -f "$key" ] || { echo "missing signing key $key; cannot renew certificates" >&2; exit 1; }
}

# TLS identity for the dedicated syslog relay. Private material stays local.
relay_certs="docker/syslog-relay/certs"
mkdir -p "$relay_certs"
if [ ! -f "$relay_certs/ca.crt" ]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 825 \
    -subj "/CN=CompanyXYZ Lab Logging CA" \
    -keyout "$relay_certs/ca.key" -out "$relay_certs/ca.crt" >/dev/null 2>&1
  chmod 600 "$relay_certs/ca.key"
  echo "  generated syslog relay CA"
elif ! cert_has_days "$relay_certs/ca.crt" 90; then
  echo "syslog CA expires within 90 days; perform planned CA overlap/rotation before renewal" >&2
  exit 1
fi

if [ ! -f "$relay_certs/relay.key" ] || ! cert_has_days "$relay_certs/relay.crt" 30; then
  require_signing_key "$relay_certs/ca.key"
  [ -f "$relay_certs/relay.key" ] || openssl genrsa -out "$relay_certs/relay.key" 3072 >/dev/null 2>&1
  openssl req -new -key "$relay_certs/relay.key" \
    -subj "/CN=syslog-relay.companyxyz.lab" \
    -out "$relay_certs/relay.csr" >/dev/null 2>&1
  openssl x509 -req -days 397 -sha256 \
    -in "$relay_certs/relay.csr" \
    -CA "$relay_certs/ca.crt" -CAkey "$relay_certs/ca.key" -CAcreateserial \
    -extfile <(printf '%s\n' 'subjectAltName=DNS:syslog-relay.companyxyz.lab,IP:172.16.50.11') \
    -out "$relay_certs/relay.crt" >/dev/null 2>&1
  rm -f "$relay_certs/relay.csr"
  chmod 600 "$relay_certs/relay.key"
  echo "  generated/renewed syslog relay server certificate"
fi

# Per-node mTLS identities. The relay rejects clients that do not present one
# of these CA-signed identities, preventing unauthenticated log injection.
client_dir="$relay_certs/clients"
mkdir -p "$client_dir"
for node in server1 edge core dist1 dist2 fw-core fw-dmz; do
  cert="$client_dir/$node.crt"
  key="$client_dir/$node.key"
  if [ ! -f "$key" ] || ! cert_has_days "$cert" 30; then
    require_signing_key "$relay_certs/ca.key"
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

# Local CA and leaf used by Traefik. Tests trust this CA explicitly instead of
# disabling certificate verification. Rotate leafs automatically; fail early
# when the CA itself approaches expiry so operators can perform overlap safely.
ztna_certs="docker/zero-trust-gateway/certs"
mkdir -p "$ztna_certs"
org_domain="$(awk -F= '$1 == "ORG_DOMAIN" {sub(/^[^=]*=/, ""); gsub(/^"|"$/, ""); print; exit}' .env)"
org_domain="${org_domain:-companyxyz.lab}"
if [ ! -f "$ztna_certs/ca.crt" ]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 825 \
    -subj "/CN=CompanyXYZ Lab ZTNA CA" \
    -keyout "$ztna_certs/ca.key" -out "$ztna_certs/ca.crt" >/dev/null 2>&1
  chmod 600 "$ztna_certs/ca.key"
  echo "  generated ZTNA lab CA"
elif ! cert_has_days "$ztna_certs/ca.crt" 90; then
  echo "ZTNA CA expires within 90 days; perform planned CA overlap/rotation" >&2
  exit 1
fi
if [ ! -f "$ztna_certs/tls.key" ] || ! cert_has_days "$ztna_certs/tls.crt" 30 \
    || ! cert_has_dns_san "$ztna_certs/tls.crt" "app.${org_domain}" \
    || ! cert_has_dns_san "$ztna_certs/tls.crt" "sso.${org_domain}"; then
  require_signing_key "$ztna_certs/ca.key"
  [ -f "$ztna_certs/tls.key" ] || openssl genrsa -out "$ztna_certs/tls.key" 3072 >/dev/null 2>&1
  openssl req -new -key "$ztna_certs/tls.key" \
    -subj "/CN=app.${org_domain}" -out "$ztna_certs/tls.csr" >/dev/null 2>&1
  openssl x509 -req -days 397 -sha256 \
    -in "$ztna_certs/tls.csr" \
    -CA "$ztna_certs/ca.crt" -CAkey "$ztna_certs/ca.key" -CAcreateserial \
    -extfile <(printf '%s\n' \
      'basicConstraints=CA:FALSE' \
      'keyUsage=digitalSignature,keyEncipherment' \
      'extendedKeyUsage=serverAuth' \
      "subjectAltName=DNS:app.${org_domain},DNS:sso.${org_domain}") \
    -out "$ztna_certs/tls.crt" >/dev/null 2>&1
  rm -f "$ztna_certs/tls.csr"
  chmod 600 "$ztna_certs/tls.key"
  echo "  generated/renewed ZTNA gateway certificate"
fi

# The LinuxServer WireGuard container owns its persisted configuration and
# peer keys beneath wireguard/config/.  Keeping a second unused key lifecycle
# here was misleading and risked testing the wrong credentials.
chmod 600 .env
echo "secrets ready (values NOT shown; stored in .env and local service config)"
