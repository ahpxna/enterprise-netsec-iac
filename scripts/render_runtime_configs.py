#!/usr/bin/env python3
"""Render secret-bearing Path A routing configs into a gitignored directory."""

from __future__ import annotations

import pathlib
import shutil
import sys

from env_exec import parse_dotenv

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "clab" / "configs"
OUTPUT = ROOT / "clab" / "runtime-configs"
ENV = ROOT / ".env"

REPLACEMENTS = {
    "CHANGE_ME_bgp_isp1": "BGP_ISP1_SECRET",
    "CHANGE_ME_bgp_isp2": "BGP_ISP2_SECRET",
    "CHANGE_ME_ospf_key": "OSPF_MD5_SECRET",
}


def main() -> int:
    if not ENV.is_file():
        print("missing .env; run make secrets", file=sys.stderr)
        return 1
    values = parse_dotenv(ENV)
    secrets = {placeholder: values.get(key, "") for placeholder, key in REPLACEMENTS.items()}
    if any(len(value) < 24 or value.startswith("CHANGE_ME") for value in secrets.values()):
        print("routing secrets are missing, weak, or placeholders; run make secrets", file=sys.stderr)
        return 1
    if len(set(secrets.values())) != len(secrets):
        print("routing secrets must be unique", file=sys.stderr)
        return 1

    OUTPUT.mkdir(parents=True, exist_ok=True)
    for path in SOURCE.iterdir():
        if not path.is_file():
            continue
        target = OUTPUT / path.name
        if path.suffix == ".conf":
            text = path.read_text()
            for placeholder, value in secrets.items():
                text = text.replace(placeholder, value)
            if "CHANGE_ME_" in text:
                print(f"unresolved runtime placeholder in {path}", file=sys.stderr)
                return 1
            target.write_text(text)
            target.chmod(0o600)
        else:
            shutil.copy2(path, target)
    print(f"rendered secret-bearing routing configs under {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
