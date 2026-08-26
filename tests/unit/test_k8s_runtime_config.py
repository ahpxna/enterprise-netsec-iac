from __future__ import annotations

import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("render_k8s_runtime_config", ROOT / "scripts/render_k8s_runtime_config.py")
assert SPEC and SPEC.loader
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def write_env(path: pathlib.Path, *, domain: str = "corp.example", port: str = "51999", peers: str = "7") -> None:
    path.write_text(
        f"ORG_DOMAIN={domain}\n"
        f"WG_SERVER_PORT={port}\n"
        "WG_ENDPOINT=vpn.corp.example\n"
        f"WG_PEER_COUNT={peers}\n"
    )


def test_custom_domain_and_wireguard_knobs_render_into_path_c(tmp_path: pathlib.Path, monkeypatch):
    env = tmp_path / ".env"
    write_env(env)
    monkeypatch.setattr(runtime, "ENV", env)
    values = runtime.settings()
    assert values["AUTHENTIK_APP_URL"] == "https://app.corp.example"
    assert values["AUTHENTIK_SSO_URL"] == "https://sso.corp.example"
    assert values["WG_SERVER_PORT"] == "51999"
    assert values["WG_PEER_COUNT"] == "7"
    dynamic = runtime.traefik_dynamic(values)
    assert "Host(`app.corp.example`)" in dynamic
    assert "Host(`sso.corp.example`)" in dynamic
    assert "trustForwardHeader: false" in dynamic
    docs = runtime.documents(values)
    vpn_policy = next(doc for doc in docs if doc.get("metadata", {}).get("name") == "wireguard-vpn")
    assert vpn_policy["spec"]["ingress"][0]["ports"][0]["port"] == 51999


def test_invalid_runtime_domain_is_rejected(tmp_path: pathlib.Path, monkeypatch):
    env = tmp_path / ".env"
    write_env(env, domain="not a domain")
    monkeypatch.setattr(runtime, "ENV", env)
    with pytest.raises(ValueError, match="valid DNS domain"):
        runtime.settings()


def test_invalid_wireguard_port_is_rejected(tmp_path: pathlib.Path, monkeypatch):
    env = tmp_path / ".env"
    write_env(env, port="70000")
    monkeypatch.setattr(runtime, "ENV", env)
    with pytest.raises(ValueError, match="between 1 and 65535"):
        runtime.settings()
