#!/usr/bin/env bash
# One command to install, build, run and test the whole CompanyXYZ lab on a Linux machine.
# All logic lives in scripts/try_linux.py (standard-library Python); this wrapper only makes sure
# a Python 3 interpreter exists to start it.  See `./scripts/try-on-linux.sh --help`.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is missing; installing it (sudo may ask for your password) ..." >&2
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y python3 python3-pip
  else
    echo "cannot install python3 automatically on this system; install Python >= 3.9 and re-run" >&2
    exit 3
  fi
fi

exec python3 scripts/try_linux.py "$@"
