#!/usr/bin/env python3
"""Refuse to start the SOC AI/response services unless their approvals exist.

Checks, without contacting any service: the approved-model digest is set and equals
the SHA-256 of the registry's metadata, the registry is `approved`, the selected
deployment/policy files exist and parse, the service PKI and signing key exist, and
the Git SHA stamped into features is valid.  Nothing here weakens a runtime check; it
only turns a late container crash into an early, readable refusal.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from env_exec import parse_dotenv  # noqa: E402

REQUIRED_CERTS = (
    "ca.crt", "soc-ai-api.crt", "soc-ai-api.key", "ai-client-ca.crt", "soc-enrichment.crt",
    "soc-enrichment.key", "soc-response.crt", "soc-response.key", "decision-ca.crt",
    "soc-decision.crt", "soc-decision.key", "decision/decision-key-1.key", "decision/decision-key-1.pub",
)


def main() -> int:
    env_file = ROOT / ".env"
    if not env_file.is_file():
        print("missing .env; run make secrets", file=sys.stderr)
        return 1
    env = parse_dotenv(env_file)
    errors: list[str] = []

    digest = env.get("SOC_AI_METADATA_SHA256", "")
    metadata = ROOT / "ai/registry/active/metadata.json"
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        errors.append("SOC_AI_METADATA_SHA256 is unset: promote a model (make soc-ai-promote) and set the printed digest")
    elif not metadata.is_file():
        errors.append("ai/registry/active/metadata.json is missing")
    else:
        actual = hashlib.sha256(metadata.read_bytes()).hexdigest()
        if actual != digest:
            errors.append("SOC_AI_METADATA_SHA256 does not match ai/registry/active/metadata.json")
        elif json.loads(metadata.read_text()).get("status") != "approved":
            errors.append("the active registry metadata is not approved")

    path = env.get("SOC_PATH", "path-a")
    policy = env.get("SOC_POLICY", "default")
    for relative in (f"response/deployments/{path}/response.yaml", f"response/deployments/{path}/decision.yaml",
                     f"response/policies/{policy}.yaml"):
        if not (ROOT / relative).is_file():
            errors.append(f"missing {relative}")
    for name in REQUIRED_CERTS:
        if not (ROOT / "soc/certs" / name).is_file():
            errors.append(f"missing soc/certs/{name}; run make secrets")
    if not re.fullmatch(r"[a-fA-F0-9]{7,64}", env.get("SOC_GIT_SHA", "")) or set(env.get("SOC_GIT_SHA", "")) == {"0"}:
        errors.append("SOC_GIT_SHA must be the real Git revision (git rev-parse HEAD)")
    if path == "path-b":
        for key in ("VYOS_API_KEY", "WAZUH_RESPONSE_CREDENTIALS"):
            if not env.get(key) or env[key].startswith("CHANGE_ME"):
                errors.append(f"{key} is unset; run make secrets")
    if errors:
        print("SOC AI preflight FAILED:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1
    print("OK: SOC AI/response preflight (approved model digest, PKI, signing key, deployment files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
