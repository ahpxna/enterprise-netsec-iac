#!/usr/bin/env bash
# macOS-friendly static/developer gate. No KVM, libvirt daemon, containerlab,
# nftables, or privileged host networking is required.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "dev-check: missing required tool: $1" >&2
    exit 2
  }
}

for tool in python docker kubectl yamllint ansible-lint; do
  require "$tool"
done

echo "==> deterministic source/render checks"
python scripts/render_fabric.py --check
python scripts/render_batfish_snapshot.py --check
python scripts/render_vm_inventory.py --check
python scripts/render_k8s_assets.py --check
python scripts/check_vyos_boot.py
python scripts/check_path_b_intent.py
python scripts/security_static_checks.py
python scripts/check_image_lock.py
python scripts/check_ci_contract.py
python scripts/check_yaml_syntax.py
python -m compileall -q scripts compliance tests
find scripts clab/configs -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
python compliance/check_wiring.py
python -m pytest tests/unit tests/soc -q

echo "==> Docker Compose / YAML / Ansible / Kubernetes render"
docker compose --env-file .env.example --profile siem --profile ids --profile ztna --profile dmz --profile vpn-test config --quiet
yamllint .
( cd ansible && ansible-lint )
kubectl kustomize k8s/ >/tmp/cxyz-k8s-rendered.yaml

echo "==> Terraform fmt/validate in Linux containers (no host libvirt/KVM required)"
TF_IMAGE="${TF_IMAGE:-hashicorp/terraform@sha256:fd5debae63188975d6febc6aa5bd1a982a588f55e4a4ddb7de28be923f250456}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/terraform"
cp -R terraform/libvirt "$tmp/terraform/libvirt"
cp -R terraform/vyos-fabric "$tmp/terraform/vyos-fabric"
for module in libvirt vyos-fabric; do
  docker run --rm \
    -u "$(id -u):$(id -g)" \
    -v "$tmp:/work" \
    -w /work \
    "$TF_IMAGE" -chdir="terraform/$module" init -backend=false -input=false >/dev/null
  docker run --rm \
    -u "$(id -u):$(id -g)" \
    -v "$tmp:/work" \
    -w /work \
    "$TF_IMAGE" -chdir="terraform/$module" fmt -check -recursive
  docker run --rm \
    -u "$(id -u):$(id -g)" \
    -v "$tmp:/work" \
    -w /work \
    "$TF_IMAGE" -chdir="terraform/$module" validate
 done

echo "OK: macOS developer checks passed without KVM/libvirt/containerlab/nftables"
