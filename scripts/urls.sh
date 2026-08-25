#!/usr/bin/env bash
set -euo pipefail
DOMAIN="${ORG_DOMAIN:-companyxyz.lab}"
echo "Service URLs (default local access):"
echo "  Wazuh SIEM dashboard : https://localhost:5601   (admin / see .env)"
echo "  Protected app        : https://app.${DOMAIN}      (resolve to 127.0.0.1 for local lab)"
echo "  Authentik SSO        : https://sso.${DOMAIN}      (resolve to 127.0.0.1 for local lab)"
echo "  Traefik dashboard    : not host-published; configure an authenticated api@internal router if needed"
