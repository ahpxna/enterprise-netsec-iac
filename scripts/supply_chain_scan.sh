#!/usr/bin/env bash
# Optional developer/auditor supply-chain check. It is intentionally separate
# from PR CI until the remaining mutable application images have approved
# upgrade/digest baselines; adding it as a blocking gate today would conflate
# known migration work with source regressions.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v trivy >/dev/null 2>&1 || {
  echo "supply-chain-scan: install Trivy first (https://trivy.dev/)" >&2
  exit 2
}

OUT="${SUPPLY_CHAIN_DIR:-evidence/supply-chain}"
mkdir -p "$OUT"

trivy fs --format cyclonedx --output "$OUT/sbom.cdx.json" .
trivy config --severity HIGH,CRITICAL --exit-code 1 .
echo "OK: SBOM written to $OUT/sbom.cdx.json and HIGH/CRITICAL IaC scan passed"
