#!/usr/bin/env bash
# Verify host has the tools this project needs; print install hints if not.
set -uo pipefail
ok=0
check() {
  if command -v "$1" >/dev/null 2>&1; then
    printf "  \033[32m✔\033[0m %-14s %s\n" "$1" "$($1 --version 2>&1 | head -1)"
  else
    printf "  \033[31mx\033[0m %-14s MISSING — %s\n" "$1" "$2"; ok=1
  fi
}
echo "== Preflight =="
check docker        "https://docs.docker.com/engine/install/"
check containerlab  "bash -c \"\$(curl -sL https://get.containerlab.dev)\""
check ansible       "pipx install ansible-core"
check terraform     "https://developer.hashicorp.com/terraform/install"
check python3       "apt install python3"
check chronyc       "apt install chrony; configure host NTS from host/chrony-cxyz.sources.example"
check nft           "apt install nftables (needed inside fw nodes only)"
[ $ok -eq 0 ] && echo -e "\n\033[32mAll good.\033[0m" || echo -e "\n\033[31mInstall the missing tools above.\033[0m"
exit $ok
