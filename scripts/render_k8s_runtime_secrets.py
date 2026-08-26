#!/usr/bin/env python3
"""Render ignored Kubernetes runtime Secrets from the existing local secret state.

This keeps Kustomize source free of plaintext credentials while making Path C
use the same Wazuh PKI and application secrets as the Compose path.
"""
from __future__ import annotations

import base64
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "k8s/runtime-secrets.yaml"
ENV = ROOT / ".env"


def load_env() -> dict[str, str]:
    if not ENV.exists():
        raise FileNotFoundError(".env is missing; run make secrets")
    result: dict[str, str] = {}
    for raw in ENV.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip().strip('"').strip("'")
    return result


def b64(path: pathlib.Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"missing {path.relative_to(ROOT)}; run make wazuh-config/secrets")
    return base64.b64encode(path.read_bytes()).decode()


def secret(name: str, data: dict[str, str], secret_type: str = "Opaque") -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": "cxyz-security"},
        "type": secret_type,
        "data": data,
    }


def main() -> int:
    try:
        env = load_env()
        required = (
            "WAZUH_INDEXER_PASSWORD",
            "WAZUH_DASHBOARD_PASSWORD",
            "WAZUH_API_PASSWORD",
            "AUTHENTIK_SECRET_KEY",
            "AUTHENTIK_POSTGRES_PASSWORD",
        )
        missing = [key for key in required if not env.get(key) or env[key].startswith("CHANGE_ME")]
        if missing:
            raise ValueError(f"runtime secret values are missing/uninitialized: {', '.join(missing)}")

        cert_dir = ROOT / "docker/wazuh/certs"
        ztna_dir = ROOT / "docker/zero-trust-gateway/certs"
        docs = [
            secret(
                "cxyz-security-secrets",
                {key: base64.b64encode(env[key].encode()).decode() for key in required},
            ),
            secret(
                "cxyz-wazuh-tls",
                {
                    name: b64(cert_dir / name)
                    for name in (
                        "root-ca.pem",
                        "root-ca-manager.pem",
                        "wazuh.indexer.pem",
                        "wazuh.indexer-key.pem",
                        "admin.pem",
                        "admin-key.pem",
                        "wazuh.manager.pem",
                        "wazuh.manager-key.pem",
                        "wazuh.dashboard.pem",
                        "wazuh.dashboard-key.pem",
                    )
                },
            ),
            secret(
                "cxyz-wazuh-security-config",
                {"internal_users.yml": b64(ROOT / "docker/wazuh/generated/internal_users.yml")},
            ),
            secret(
                "cxyz-ztna-tls",
                {
                    "tls.crt": b64(ztna_dir / "tls.crt"),
                    "tls.key": b64(ztna_dir / "tls.key"),
                },
                "kubernetes.io/tls",
            ),
        ]
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    OUT.write_text(yaml.safe_dump_all(docs, sort_keys=False, explicit_start=True))
    OUT.chmod(0o600)
    print(f"rendered ignored Path C runtime secrets: {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
