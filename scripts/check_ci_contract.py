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
dev_check_body = make_target_body("dev-check")
if "bash scripts/dev_check.sh" not in dev_check_body:
    fail("make dev-check must execute scripts/dev_check.sh")

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
    "container image lock": "python scripts/check_image_lock.py",
    "CI contract guard": "python scripts/check_ci_contract.py",
    "compliance wiring": "python compliance/check_wiring.py",
    "YAML syntax including custom tags": "python scripts/check_yaml_syntax.py",
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
    "pinned CI Python requirements": "python -m pip install -r requirements-ci.txt",
    "pinned Batfish Python requirements": "python -m pip install -r requirements-batfish.txt",
    "server1 deterministic image build": "docker build --pull=false -t cxyz/server1:ci docker/server1",
    "syslog relay deterministic image build": "docker build --pull=false -t cxyz/syslog-relay:ci docker/syslog-relay",
    "WireGuard peer fixture Compose render": "--profile vpn-test",
}
for label, token in ci_tokens.items():
    if token not in WORKFLOW:
        fail(f"GitHub Actions lost {label}")

# Third-party Actions and the Batfish service are immutable references. Tags
# can move and make the same repository commit execute different code later.
supply_chain_tokens = {
    "checkout v7.0.0 SHA": "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
    "setup-python v7.0.0 SHA": "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
    "setup-terraform v4.0.1 SHA": "hashicorp/setup-terraform@dfe3c3f87815947d99a8997f908cb6525fc44e9e",
    "Terraform CLI pin": 'terraform_version: "1.15.9"',
    "Batfish image digest": "batfish/allinone@sha256:445818fc17c0e24eb097387c84184334ad3fc42807de1ed9fef773762a0be515",
    "Gitleaks image digest": "ghcr.io/gitleaks/gitleaks@sha256:e1b35e12a8c6fa8901f060459cfb6b2fc4c484d3afbe3b029733a3bbfab07055",
}
for label, token in supply_chain_tokens.items():
    if token not in WORKFLOW:
        fail(f"GitHub Actions lost immutable supply-chain pin: {label}")
if "batfish/allinone:latest" in WORKFLOW:
    fail("Batfish CI service must never use :latest")

if "runs-on: ubuntu-latest" in WORKFLOW:
    fail("CI runner OS must be explicitly pinned; ubuntu-latest is forbidden")
if WORKFLOW.count("runs-on: ubuntu-24.04") < 4:
    fail("every audited CI job must remain pinned to ubuntu-24.04")

requirements_ci = (ROOT / "requirements-ci.txt").read_text().splitlines()
requirements_batfish = (ROOT / "requirements-batfish.txt").read_text().splitlines()
for filename, lines in (("requirements-ci.txt", requirements_ci), ("requirements-batfish.txt", requirements_batfish)):
    entries = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    for entry in entries:
        if "==" not in entry:
            fail(f"{filename} contains a non-exact dependency: {entry}")
if any(token in WORKFLOW for token in ("pip install ansible-core ansible-lint", "pip install pybatfish pytest")):
    fail("CI must install Python tooling from exact requirements files, not floating command lines")

if ERRORS:
    print("CI contract check FAILED:", file=sys.stderr)
    for error in ERRORS:
        print(f" - {error}", file=sys.stderr)
    raise SystemExit(1)

print("OK: local lint and GitHub Actions retain the audited CI contract")
