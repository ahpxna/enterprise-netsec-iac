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
    RADIUS_ADMIN_PBKDF2) new="$(bash scripts/mkhash.sh "$(gen)")";;
    *) new="$(gen)";;
  esac
  # portable in-place edit
  awk -v key="$k" -v val="$new" -F= 'BEGIN{OFS="="}
    $1==key{$2=val} {print}' .env > .env.tmp && mv .env.tmp .env
  echo "  set $k"
done < <(grep '=' .env)

# WireGuard server + peer keys
mkdir -p wireguard/keys && chmod 700 wireguard/keys
if [ ! -f wireguard/keys/server.key ]; then
  wg genkey | tee wireguard/keys/server.key | wg pubkey > wireguard/keys/server.pub 2>/dev/null \
    || { echo "wg not installed; skipping WG keygen (install wireguard-tools)"; }
  chmod 600 wireguard/keys/* 2>/dev/null || true
  echo "  generated WireGuard server keypair"
fi
echo "secrets ready (values NOT shown; stored in .env / wireguard/keys, both gitignored)"
