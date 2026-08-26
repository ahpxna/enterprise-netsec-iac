#!/usr/bin/env bash
# Optional developer/auditor supply-chain check. Keep this separate from PR CI:
# vulnerability/advisory feeds and registry/network availability evolve outside
# the repository, so a deterministic source commit should not randomly change
# PR status when those external services change.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v trivy >/dev/null 2>&1 || {
  echo "supply-chain-scan: install Trivy first (https://trivy.dev/)" >&2
  exit 2
}

python scripts/check_image_lock.py

OUT="${SUPPLY_CHAIN_DIR:-evidence/supply-chain}"
mkdir -p "$OUT"

trivy fs --format cyclonedx --output "$OUT/sbom.cdx.json" .
trivy config --severity HIGH,CRITICAL --exit-code 1 .
echo "OK: SBOM written to $OUT/sbom.cdx.json and HIGH/CRITICAL IaC scan passed"
