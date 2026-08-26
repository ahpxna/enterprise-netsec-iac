#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
set -a
# shellcheck disable=SC1091
source .env
set +a

hash_password() {
  printf '%s\n' "$1" | docker run --rm -i wazuh/wazuh-indexer@sha256:66b7640cce54f5f20a65e8320601b4570a1306d9f9b334d30bcaa324720a517c \
    bash -c 'read -r password; /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$password"' \
    | tail -n 1 | tr -d '\r'
}

admin_hash="$(hash_password "$WAZUH_INDEXER_PASSWORD")"
dashboard_hash="$(hash_password "$WAZUH_DASHBOARD_PASSWORD")"
[[ "$admin_hash" == \$2* && "$dashboard_hash" == \$2* ]] || {
  echo "failed to generate Wazuh bcrypt hashes" >&2
  exit 1
}

mkdir -p docker/wazuh/generated
awk -v admin="$admin_hash" -v dashboard="$dashboard_hash" '
  {gsub(/__ADMIN_HASH__/, admin); gsub(/__DASHBOARD_HASH__/, dashboard); print}
' docker/wazuh/internal_users.yml.tmpl > docker/wazuh/generated/internal_users.yml
chmod 600 docker/wazuh/generated/internal_users.yml
echo "generated Wazuh internal user database (passwords not printed)"
