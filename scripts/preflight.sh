#!/usr/bin/env bash
# Profile-aware host prerequisite checks. Keep startup requirements separate
# from audit/Path-B/Kubernetes tooling so `make up` does not require unrelated
# hypervisor or lint binaries.
set -uo pipefail
profile="${1:-audit}"
ok=0

check() {
  local cmd="$1" hint="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    printf "  \033[32m✔\033[0m %-18s %s\n" "$cmd" "$($cmd --version 2>&1 | head -1)"
  else
    printf "  \033[31mx\033[0m %-18s MISSING — %s\n" "$cmd" "$hint"
    ok=1
  fi
}

check_compose() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    printf "  \033[32m✔\033[0m %-18s %s\n" "docker compose" "$(docker compose version 2>&1 | head -1)"
  else
    printf "  \033[31mx\033[0m %-18s MISSING — Docker Compose v2 plugin\n" "docker compose"
    ok=1
  fi
}

check_python_module() {
  local module="$1" hint="$2"
  if python3 -c "import ${module}" >/dev/null 2>&1; then
    printf "  \033[32m✔\033[0m %-18s importable\n" "python:${module}"
  else
    printf "  \033[31mx\033[0m %-18s MISSING — %s\n" "python:${module}" "$hint"
    ok=1
  fi
}

case "$profile" in
  path-a)
    echo "== Preflight: Path A startup =="
    check docker "https://docs.docker.com/engine/install/"
    check_compose
    check containerlab "bash -c \"\$(curl -sL https://get.containerlab.dev)\""
    check python3 "install Python 3.12+"
    ;;
  audit)
    echo "== Preflight: Path A audit/developer tooling =="
    "$0" path-a || ok=1
    check ansible "pipx install ansible-core"
    check terraform "https://developer.hashicorp.com/terraform/install"
    check chronyc "install chrony; configure host NTS from host/chrony-cxyz.sources.example"
    check yamllint "python -m pip install -r requirements-ci.txt"
    check ansible-lint "python -m pip install -r requirements-ci.txt"
    check gitleaks "https://github.com/gitleaks/gitleaks"
    check_python_module pytest "python -m pip install -r requirements-ci.txt"
    check_python_module pybatfish "python -m pip install -r requirements-batfish.txt"
    ;;
  path-b)
    echo "== Preflight: Path B/KVM =="
    check terraform "https://developer.hashicorp.com/terraform/install"
    check ansible "pipx install ansible-core"
    check virsh "install libvirt client/KVM tooling"
    check python3 "install Python 3.12+"
    ;;
  k8s)
    echo "== Preflight: Path C/Kubernetes =="
    check kubectl "https://kubernetes.io/docs/tasks/tools/"
    check python3 "install Python 3.12+"
    check curl "install curl"
    ;;
  *)
    echo "unknown preflight profile: $profile (expected path-a|audit|path-b|k8s)" >&2
    exit 2
    ;;
esac

if [[ "$ok" -eq 0 ]]; then
  echo -e "\n\033[32mAll good for $profile.\033[0m"
else
  echo -e "\n\033[31mInstall the missing tools above.\033[0m"
fi
exit "$ok"
