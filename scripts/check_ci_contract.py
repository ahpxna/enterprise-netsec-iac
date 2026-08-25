#!/usr/bin/env python3
"""Guard the audited CI/Makefile checks against silent coverage drift.

This is deliberately text-based: it verifies that the repository's critical
source checks remain wired into both the local ``make lint`` path and GitHub
Actions without trying to execute host-dependent tooling.
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = (ROOT / ".github/workflows/netdevops-ci.yml").read_text()
MAKEFILE = (ROOT / "Makefile").read_text()
ERRORS: list[str] = []


def fail(message: str) -> None:
    ERRORS.append(message)


def make_target_body(name: str) -> str:
    match = re.search(rf"(?ms)^\.PHONY:\s+{re.escape(name)}\s*$.*?^{re.escape(name)}:[^\n]*\n(?P<body>(?:\t[^\n]*\n|\n)*)", MAKEFILE)
    if not match:
        fail(f"Makefile target {name!r} is missing")
        return ""
    return match.group("body")


lint_body = make_target_body("lint")

# These checks are cheap, deterministic source invariants. They must be present
# in both developer lint and PR CI so one path cannot silently become weaker.
shared_checks = {
    "Path A topology drift": "python scripts/render_fabric.py --check",
    "Batfish snapshot drift": "python scripts/render_batfish_snapshot.py --check",
    "Path B inventory drift": "python scripts/render_vm_inventory.py --check",
    "Kubernetes generated asset drift": "python scripts/render_k8s_assets.py --check",
    "VyOS bootstrap invariants": "python scripts/check_vyos_boot.py",
    "Path B intent invariants": "python scripts/check_path_b_intent.py",
    "security regression invariants": "python scripts/security_static_checks.py",
    "CI contract guard": "python scripts/check_ci_contract.py",
    "compliance wiring": "python compliance/check_wiring.py",
}
for label, command in shared_checks.items():
    if command not in lint_body:
        fail(f"make lint lost {label}: {command}")
    if command not in WORKFLOW:
        fail(f"GitHub Actions lost {label}: {command}")

# Syntax gates prevent a shell/Python parse regression from waiting until a
# later runtime job. Keep them mirrored locally and in CI.
for label, token in {
    "Python syntax gate": "python -m compileall -q scripts compliance tests",
    "Bash syntax gate": "bash -n",
}.items():
    if token not in lint_body:
        fail(f"make lint lost {label}")
    if token not in WORKFLOW:
        fail(f"GitHub Actions lost {label}")

# CI-only infrastructure-independent gates. These intentionally remain in CI
# rather than being required by this script on developer machines.
ci_tokens = {
    "Docker Compose render": "config --quiet",
    "Kustomize render": "kubectl kustomize k8s/",
    "yamllint": "yamllint .",
    "ansible-lint": "ansible-lint",
    "full-history gitleaks": "--log-opts=--all",
    "Batfish policy tests": "pytest tests/batfish -v",
    "libvirt Terraform fmt": "terraform -chdir=terraform/libvirt fmt -check",
    "libvirt Terraform validate": "terraform -chdir=terraform/libvirt validate",
    "VyOS Terraform fmt": "terraform -chdir=terraform/vyos-fabric fmt -check",
    "VyOS Terraform validate": "terraform -chdir=terraform/vyos-fabric validate",
}
for label, token in ci_tokens.items():
    if token not in WORKFLOW:
        fail(f"GitHub Actions lost {label}")

if ERRORS:
    print("CI contract check FAILED:", file=sys.stderr)
    for error in ERRORS:
        print(f" - {error}", file=sys.stderr)
    raise SystemExit(1)

print("OK: local lint and GitHub Actions retain the audited CI contract")
