#!/usr/bin/env bash
# Emit a PBKDF2-SHA256 hash for a password (NIST SP 800-63B: store hashes).
# Usage: scripts/mkhash.sh 'plaintext'
set -euo pipefail
python3 - "$1" <<'PY'
import hashlib, os, sys, base64
pw = sys.argv[1].encode()
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', pw, salt, 210000)
print("pbkdf2_sha256$210000$" + base64.b64encode(salt).decode()
      + "$" + base64.b64encode(dk).decode())
PY
