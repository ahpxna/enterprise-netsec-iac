#!/usr/bin/env bash
# Emit a salted SHA-512 crypt hash supported by FreeRADIUS 3 Crypt-Password.
# Usage: scripts/mkhash.sh 'plaintext'
set -euo pipefail
openssl passwd -6 "$1"
