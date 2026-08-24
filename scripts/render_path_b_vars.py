#!/usr/bin/env python3
"""Render ignored Path B Terraform secret inputs from the canonical .env.

Terraform receives only the deployment SSH public key. Long-lived BGP/OSPF
credentials remain in .env (or a future secret backend) and are injected only
by Ansible Day-2, so Terraform state is not a routing-credential store.
"""
from __future__ import annotations

import argparse
import json
import pathlib

from env_exec import parse_dotenv

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "terraform" / "vyos-fabric" / "bootstrap.auto.tfvars.json"
LEGACY_OUT = ROOT / "terraform" / "vyos-fabric" / "routing.auto.tfvars.json"


def strong(value: str) -> bool:
    return len(value) >= 24 and not value.startswith("CHANGE_ME")


def load_public_key(path_text: str) -> str:
    path = pathlib.Path(path_text).expanduser()
    if not path.is_absolute():
        path = (ROOT / path).resolve()
    if not path.is_file():
        raise SystemExit(f"Path B SSH public key file not found: {path}")
    value = path.read_text().strip()
    parts = value.split()
    if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
        raise SystemExit(f"Unsupported SSH public key format in {path}")
    return " ".join(parts[:2])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    env = parse_dotenv(ROOT / ".env")
    key_file = env.get("PATH_B_SSH_PUBLIC_KEY_FILE", "")
    if not key_file:
        raise SystemExit("PATH_B_SSH_PUBLIC_KEY_FILE is not set in .env")
    public_key = load_public_key(key_file)
    payload = {"ssh_public_key": public_key}
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not OUT.exists() or OUT.read_text() != rendered:
            raise SystemExit(f"stale or missing {OUT.relative_to(ROOT)}; run make path-b-vars")
        return 0
    LEGACY_OUT.unlink(missing_ok=True)
    OUT.write_text(rendered)
    OUT.chmod(0o600)
    print(f"rendered {OUT.relative_to(ROOT)} (secret values not shown)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
