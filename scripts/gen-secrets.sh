#!/usr/bin/env bash
# Idempotent secret bootstrap. Never prints secrets to stdout. Never commits.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

[ -f .env ] || { cp .env.example .env; echo "created .env from template"; }

gen() { openssl rand -base64 36 | tr -d '\n'; }

# Replace CHANGE_ME_* placeholders in .env with real random values, once.
while IFS='=' read -r k v; do
  [[ "$v" == CHANGE_ME* ]] || continue
  case "$k" in
    RADIUS_ADMIN_CRYPT) new="$(bash scripts/mkhash.sh "$(gen)")";;
    *) new="$(gen)";;
  esac
  # portable in-place edit
  awk -v key="$k" -v val="$new" -F= 'BEGIN{OFS="="}
    $1==key{$2=val} {print}' .env > .env.tmp && mv .env.tmp .env
  echo "  set $k"
done < <(grep '=' .env)

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

# WireGuard server + peer keys
mkdir -p wireguard/keys && chmod 700 wireguard/keys
if [ ! -f wireguard/keys/server.key ]; then
  wg genkey | tee wireguard/keys/server.key | wg pubkey > wireguard/keys/server.pub 2>/dev/null \
    || { echo "wg not installed; skipping WG keygen (install wireguard-tools)"; }
  chmod 600 wireguard/keys/* 2>/dev/null || true
  echo "  generated WireGuard server keypair"
fi
echo "secrets ready (values NOT shown; stored in .env / wireguard/keys, both gitignored)"
