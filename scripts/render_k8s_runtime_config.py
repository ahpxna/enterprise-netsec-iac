#!/usr/bin/env python3
"""Render non-secret Path C runtime settings and Traefik file-provider config.

Kustomize intentionally remains deterministic and secret-free.  Values that are
operator-configurable in .env (domain and WireGuard listener settings) are
rendered into an ignored runtime ConfigMap/NetworkPolicy immediately before
`make k8s-up`.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "k8s/runtime-config.yaml"
ENV = ROOT / ".env"

if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
from env_exec import parse_dotenv  # noqa: E402

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def settings() -> dict[str, str]:
    if not ENV.is_file():
        raise ValueError(".env is missing; run make secrets")
    values = parse_dotenv(ENV)
    domain = values.get("ORG_DOMAIN", "companyxyz.lab").strip().lower()
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError(f"ORG_DOMAIN is not a valid DNS domain: {domain!r}")
    try:
        port = int(values.get("WG_SERVER_PORT", "51820"))
        peers = int(values.get("WG_PEER_COUNT", "4"))
    except ValueError as exc:
        raise ValueError("WG_SERVER_PORT and WG_PEER_COUNT must be integers") from exc
    if not 1 <= port <= 65535:
        raise ValueError("WG_SERVER_PORT must be between 1 and 65535")
    if not 1 <= peers <= 64:
        raise ValueError("WG_PEER_COUNT must be between 1 and 64")
    endpoint = values.get("WG_ENDPOINT", "auto").strip() or "auto"
    if any(ch.isspace() for ch in endpoint):
        raise ValueError("WG_ENDPOINT must not contain whitespace")
    return {
        "ORG_DOMAIN": domain,
        "AUTHENTIK_BASE_URL": f"https://sso.{domain}",
        "AUTHENTIK_APP_URL": f"https://app.{domain}",
        "AUTHENTIK_SSO_URL": f"https://sso.{domain}",
        "WG_SERVER_PORT": str(port),
        "WG_PEER_COUNT": str(peers),
        "WG_ENDPOINT": endpoint,
    }


def traefik_dynamic(values: dict[str, str]) -> str:
    app = values["AUTHENTIK_APP_URL"]
    sso = values["AUTHENTIK_SSO_URL"]
    app_host = app.removeprefix("https://")
    sso_host = sso.removeprefix("https://")
    return f"""http:
  routers:
    authentik:
      entryPoints: [websecure]
      rule: \"Host(`{sso_host}`)\"
      service: authentik
      tls: {{}}
    ztna-outpost:
      entryPoints: [websecure]
      rule: \"Host(`{app_host}`) && PathPrefix(`/outpost.goauthentik.io/`)\"
      priority: 100
      service: authentik
      tls: {{}}
    ztna-demo:
      entryPoints: [websecure]
      rule: \"Host(`{app_host}`)\"
      middlewares: [authentik-forwardauth]
      service: ztna-demo
      tls: {{}}
  middlewares:
    authentik-forwardauth:
      forwardAuth:
        address: http://authentik-server.cxyz-security.svc.cluster.local:9000/outpost.goauthentik.io/auth/traefik
        trustForwardHeader: false
        maxResponseBodySize: 4194304
        authResponseHeaders:
          - X-authentik-username
          - X-authentik-groups
          - X-authentik-email
  services:
    authentik:
      loadBalancer:
        servers:
          - url: http://authentik-server.cxyz-security.svc.cluster.local:9000
    ztna-demo:
      loadBalancer:
        servers:
          - url: http://ztna-demo-app.cxyz-security.svc.cluster.local:8080
tls:
  stores:
    default:
      defaultCertificate:
        certFile: /run/cxyz-ztna/tls.crt
        keyFile: /run/cxyz-ztna/tls.key
"""


def documents(values: dict[str, str]) -> list[dict]:
    return [
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "cxyz-runtime-settings", "namespace": "cxyz-security"},
            "data": values,
        },
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "cxyz-traefik-dynamic", "namespace": "cxyz-security"},
            "data": {"dynamic.yaml": traefik_dynamic(values)},
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "wireguard-vpn", "namespace": "cxyz-security"},
            "spec": {
                "podSelector": {"matchLabels": {"app": "wireguard"}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {
                        "ports": [
                            {"protocol": "UDP", "port": int(values["WG_SERVER_PORT"])}
                        ]
                    }
                ],
                # hostNetwork reply/routed peer behavior remains CNI-dependent.
                "egress": [{}],
            },
        },
    ]


def rendered() -> str:
    return yaml.safe_dump_all(documents(settings()), sort_keys=False, explicit_start=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        expected = rendered()
    except (OSError, ValueError) as exc:
        print(f"Path C runtime config: {exc}", file=sys.stderr)
        return 1
    if args.check:
        if not OUT.is_file() or OUT.read_text() != expected:
            print("k8s/runtime-config.yaml is missing/stale; run make k8s-runtime-config", file=sys.stderr)
            return 1
        print("OK: Path C runtime settings match .env")
        return 0
    OUT.write_text(expected)
    OUT.chmod(0o600)
    print(f"rendered ignored Path C runtime config: {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
