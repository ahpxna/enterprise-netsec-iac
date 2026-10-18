#!/bin/bash
# Wraps the wazuh-certs-generator image's /entrypoint.sh.
#
# The upstream wazuh-certs-tool.sh only accepts DNS names with a dot and a TLD
# ("Invalid IP or DNS wazuh-indexer"), but the indexer is reached as the dotless
# Compose/Kubernetes service name `wazuh-indexer` with full hostname verification,
# so its certificate needs exactly that SAN. After the entrypoint downloads the
# tool, make the trailing ".tld" optional in that one regex; everything else in
# the tool and the entrypoint runs unchanged.
set -euo pipefail

if [[ $# -eq 1 ]]; then                       # called from the patched entrypoint with the downloaded tool
  tool="$1"
  sed -i 's/\\\.(\[A-Za-z\]{2,})\$" )/(\\.[A-Za-z]{2,})?$" )/' "$tool"
  if ! grep -qF '(\.[A-Za-z]{2,})?$" )' "$tool"; then
    echo "certs-entrypoint: could not relax the DNS-name check in $tool (upstream tool changed?)" >&2
    exit 1
  fi
  exit 0
fi

awk '{ print } /^chmod 700 "\$OUTPUT_FILE"$/ { print "bash /cxyz-certs-entrypoint.sh \"$OUTPUT_FILE\" || exit 1"; n++ }
     END { exit n != 1 }' /entrypoint.sh > /entrypoint-cxyz.sh \
  || { echo "certs-entrypoint: upstream /entrypoint.sh layout changed" >&2; exit 1; }
# Kept in / like the original: the tool resolves /config.yml from its caller's directory.
bash /entrypoint-cxyz.sh
[[ -f /certificates/root-ca.pem ]] || { echo "certs-entrypoint: no certificates were produced" >&2; exit 1; }

# Upstream leaves /certificates at 0500 root, so the host user cannot even stat the files for
# scripts/check_wazuh_pki.py. Open the directory and the public certificates; private keys keep
# upstream's 0400 and service-account owners (1000 indexer/dashboard, 999 manager).
chmod 0755 /certificates
for f in /certificates/*.pem; do
  [[ "$f" == *-key.pem ]] || chmod 0444 "$f"
done
