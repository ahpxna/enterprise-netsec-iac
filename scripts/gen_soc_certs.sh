#!/usr/bin/env bash
# Idempotently create the local SOC analytics-plane CA, the SOC service PKI and the
# decision signing key. Private material stays under soc/certs (gitignored) and
# no signing key is ever mounted into a container.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="$ROOT/soc/certs"
mkdir -p "$CERT_DIR"

cert_valid() {
  local cert="$1"
  [ -f "$cert" ] && openssl x509 -checkend $((30 * 86400)) -noout -in "$cert" >/dev/null 2>&1
}

cert_signed_by() {
  local cert="$1" ca="$2"
  [ -f "$cert" ] && openssl verify -CAfile "$CERT_DIR/$ca.crt" "$cert" >/dev/null 2>&1
}

cert_has_dns_san() {
  local cert="$1" dns="$2"
  [ -f "$cert" ] || return 1
  openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null \
    | tr ',' '\n' | grep -Eq "^[[:space:]]*DNS:${dns//./\\.}[[:space:]]*$"
}

ensure_ca() {
  local name="$1" subject="$2"
  if [ ! -f "$CERT_DIR/$name.key" ] || ! cert_valid "$CERT_DIR/$name.crt"; then
    openssl req -x509 -newkey rsa:3072 -nodes -days 825 -sha256 \
      -subj "/CN=$subject" \
      -keyout "$CERT_DIR/$name.key" -out "$CERT_DIR/$name.crt" >/dev/null 2>&1
    echo "  generated $subject"
  fi
}

# issue_leaf NAME SAN USAGE [CA]  - CN is NAME; the leaf must carry DNS:NAME.
issue_leaf() {
  local name="$1" san="$2" usage="$3" ca="${4:-ca}"
  if [ ! -f "$CERT_DIR/$name.key" ] \
      || ! cert_valid "$CERT_DIR/$name.crt" \
      || ! cert_signed_by "$CERT_DIR/$name.crt" "$ca" \
      || ! cert_has_dns_san "$CERT_DIR/$name.crt" "$name"; then
    openssl req -newkey rsa:3072 -nodes -subj "/CN=$name" \
      -keyout "$CERT_DIR/$name.key" -out "$CERT_DIR/$name.csr" >/dev/null 2>&1
    openssl x509 -req -days 397 -sha256 \
      -in "$CERT_DIR/$name.csr" -CA "$CERT_DIR/$ca.crt" \
      -CAkey "$CERT_DIR/$ca.key" -CAcreateserial \
      -extfile <(printf '%s\n' \
        'basicConstraints=CA:FALSE' \
        'keyUsage=digitalSignature,keyEncipherment' \
        "extendedKeyUsage=$usage" \
        "subjectAltName=$san") \
      -out "$CERT_DIR/$name.crt" >/dev/null 2>&1
    rm -f "$CERT_DIR/$name.csr"
    echo "  generated/renewed SOC certificate for $name"
  fi
}

ensure_ca ca "CompanyXYZ SOC Analytics CA"

# --- Elastic stack (existing)
issue_leaf elasticsearch "DNS:elasticsearch,DNS:localhost,IP:127.0.0.1" "serverAuth"
issue_leaf kibana "DNS:kibana,DNS:localhost,IP:127.0.0.1" "serverAuth"
issue_leaf logstash "DNS:logstash" "serverAuth,clientAuth"

# --- SOC AI / response service PKI. Client identities are signed by dedicated
# client CAs so a server only trusts the one caller it is meant to serve.
ensure_ca ai-client-ca "CompanyXYZ SOC AI Client CA"
ensure_ca decision-ca "CompanyXYZ SOC Decision Client CA"
issue_leaf soc-ai-api "DNS:soc-ai-api" "serverAuth"
issue_leaf soc-enrichment "DNS:soc-enrichment" "clientAuth" ai-client-ca
issue_leaf soc-response "DNS:soc-response" "serverAuth,clientAuth"
issue_leaf soc-decision "DNS:soc-decision" "clientAuth" decision-ca

# --- Firewall enforcement endpoints reached on the out-of-band management plane.
# Path A: constrained nftables agents. Path B: VyOS HTTPS API. Management IPs
# come from intent/fabric.yaml (fw-core 10.1.1.20, fw-dmz 10.1.1.30).
issue_leaf enforcer-fw-core "DNS:enforcer-fw-core,DNS:fw-core,IP:10.1.1.20" "serverAuth"
issue_leaf enforcer-fw-dmz "DNS:enforcer-fw-dmz,DNS:fw-dmz,IP:10.1.1.30" "serverAuth"
issue_leaf vyos-api-fw-core "DNS:vyos-api-fw-core,DNS:fw-core,IP:10.1.1.20" "serverAuth"
issue_leaf vyos-api-fw-dmz "DNS:vyos-api-fw-dmz,DNS:fw-dmz,IP:10.1.1.30" "serverAuth"

# --- Decision-engine signing key (Ed25519). The private key is mounted only into
# the decision service; the orchestrator receives the public key ring.
sign_dir="$CERT_DIR/decision"
mkdir -p "$sign_dir"
if [ ! -f "$sign_dir/decision-key-1.key" ]; then
  openssl genpkey -algorithm ed25519 -out "$sign_dir/decision-key-1.key" >/dev/null 2>&1
  openssl pkey -in "$sign_dir/decision-key-1.key" -pubout -out "$sign_dir/decision-key-1.pub" >/dev/null 2>&1
  echo "  generated decision signing key decision-key-1"
fi

chmod 600 "$CERT_DIR"/*.key "$sign_dir"/*.key
chmod 644 "$CERT_DIR"/*.crt "$sign_dir"/*.pub
