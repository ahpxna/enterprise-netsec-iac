"""Closed, validated service configuration (``response-service-v1`` / ``decision-service-v1``).

Configuration names files and endpoints only; it never contains a secret value.
Unknown keys are rejected so a typo cannot silently weaken a control.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

import yaml

from ..adapters.base import AdapterOutcome
from ..adapters.blocklist import (
    BlocklistAdapter,
    BlocklistPeer,
    NftablesBlocklistAdapter,
    VyosBlocklistAdapter,
)
from ..adapters.opnsense import OPNsenseBlocklistAdapter
from ..adapters.wazuh import WazuhIsolationAdapter
from ..transports.nftables import NftablesRawSet
from ..transports.opnsense import OPNsenseRawSet
from ..transports.ownership import OwnedBlocklistClient, OwnershipLedger
from ..transports.vyos import VyosRawSet
from ..transports.wazuh_api import WazuhApiClient


class ConfigError(ValueError):
    pass


def _closed(value: Any, required: set[str], optional: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigError(f"{label} must be a mapping")
    missing, unknown = required - set(value), set(value) - required - optional
    if missing or unknown:
        raise ConfigError(f"{label}: missing={sorted(missing)} unknown={sorted(unknown)}")
    return value


def load_yaml(path: str | Path) -> Mapping[str, Any]:
    try:
        document = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read configuration {path}") from exc
    if not isinstance(document, Mapping):
        raise ConfigError("configuration must be a mapping")
    return document


def _elastic(value: Any) -> Mapping[str, Any]:
    return _closed(value, {"url", "ca", "api_key_file"}, set(), "elasticsearch")


def _effective_mode(cfg: Mapping[str, Any], environ: Mapping[str, str] | None) -> str:
    """The committed ``mode`` unless the operator environment explicitly overrides it.

    ``SOC_MODE`` lives in the gitignored ``.env``, so a live validation run can enable
    enforcement without editing (and thereby dirtying) the reviewed deployment files.
    """

    override = (os.environ if environ is None else environ).get("SOC_MODE", "").strip()
    mode = override or cfg["mode"]
    if mode not in {"observe", "enforce"}:
        raise ConfigError("mode must be observe or enforce")
    return mode


def parse_response_service(document: Mapping[str, Any], environ: Mapping[str, str] | None = None) -> Mapping[str, Any]:
    cfg = _closed(
        document,
        {"schema_version", "mode", "state_dir", "policy_file", "verify_keys_dir", "elasticsearch", "listen",
         "firewall"},
        {"wazuh", "tick_seconds"},
        "response service",
    )
    if cfg["schema_version"] != "response-service-v1":
        raise ConfigError("unsupported response service schema")
    cfg = {**cfg, "mode": _effective_mode(cfg, environ)}
    _elastic(cfg["elasticsearch"])
    _closed(cfg["listen"], {"host", "port", "cert", "key", "client_ca"}, set(), "listen")
    firewall = _closed(cfg["firewall"], {"backend", "peers"}, set(), "firewall")
    if firewall["backend"] not in {"nftables", "vyos", "opnsense"}:
        raise ConfigError("firewall backend must be nftables, vyos or opnsense")
    peers = firewall["peers"]
    if not isinstance(peers, list) or len(peers) < 2:
        raise ConfigError("at least two firewall peers are required")
    allowed = {
        "nftables": ({"name", "url", "ca", "client_cert", "client_key"}, set()),
        "vyos": ({"name", "url", "ca", "api_key_file"}, set()),
        "opnsense": ({"name", "url", "ca", "credentials_file"}, set()),
    }[firewall["backend"]]
    for peer in peers:
        _closed(peer, allowed[0], allowed[1], "firewall peer")
    if "wazuh" in cfg:
        _closed(cfg["wazuh"], {"url", "ca", "credentials_file"}, set(), "wazuh")
    tick = cfg.get("tick_seconds", 10)
    if type(tick) is not int or not 2 <= tick <= 300:
        raise ConfigError("tick_seconds must be an integer between 2 and 300")
    return cfg


def parse_decision_service(document: Mapping[str, Any], environ: Mapping[str, str] | None = None) -> Mapping[str, Any]:
    cfg = _closed(
        document,
        {"schema_version", "mode", "state_dir", "policy_file", "signing_key_file", "signing_key_id",
         "elasticsearch"},
        {"orchestrator", "protected_assets", "threat_intel_file", "poll_seconds", "min_score"},
        "decision service",
    )
    if cfg["schema_version"] != "decision-service-v1":
        raise ConfigError("unsupported decision service schema")
    cfg = {**cfg, "mode": _effective_mode(cfg, environ)}
    _elastic(cfg["elasticsearch"])
    if cfg["mode"] == "enforce":
        _closed(cfg.get("orchestrator"), {"url", "ca", "client_cert", "client_key"}, set(), "orchestrator")
    poll = cfg.get("poll_seconds", 15)
    if type(poll) is not int or not 5 <= poll <= 600:
        raise ConfigError("poll_seconds must be an integer between 5 and 600")
    score = cfg.get("min_score", 0.90)
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0.90 <= score <= 1:
        raise ConfigError("min_score must be between 0.90 and 1")
    return cfg


class UnavailableAdapter:
    """Fail-closed stand-in used when an action's backend is not configured."""

    def __init__(self, *, name: str, action: str) -> None:
        self.name, self.action = name, action

    def recovery_reference(self, command: Mapping[str, object]) -> str:
        return f"{self.name}:unconfigured:{command.get('idempotency_key')}"

    def _fail(self) -> AdapterOutcome:
        return AdapterOutcome.failure(code="BACKEND_NOT_CONFIGURED",
                                      message=f"{self.action} has no configured backend")

    def apply(self, command):  # noqa: D102
        return self._fail()

    def verify(self, command, *, adapter_reference):  # noqa: D102
        return self._fail()

    def revert(self, command, *, adapter_reference):  # noqa: D102
        # Nothing was ever applied, so there is nothing to undo.
        return AdapterOutcome.success(adapter_reference=adapter_reference, evidence_refs=("unconfigured:noop",))


def build_adapters(cfg: Mapping[str, Any], state_dir: Path) -> list:
    """Wire reviewed transports into the two fixed adapters (no network I/O)."""

    firewall = cfg["firewall"]
    peers: list[BlocklistPeer] = []
    for peer in firewall["peers"]:
        backend = firewall["backend"]
        if backend == "nftables":
            raw = NftablesRawSet.from_files(url=peer["url"], ca=peer["ca"], client_cert=peer["client_cert"],
                                            client_key=peer["client_key"])
        elif backend == "vyos":
            raw = VyosRawSet.from_files(url=peer["url"], ca=peer["ca"], api_key_file=peer["api_key_file"])
        else:
            raw = OPNsenseRawSet.from_files(url=peer["url"], ca=peer["ca"],
                                            credentials_file=peer["credentials_file"])
        ledger = OwnershipLedger(Path(state_dir) / "ownership" / f"{peer['name']}.sqlite")
        peers.append(BlocklistPeer(peer["name"], OwnedBlocklistClient(raw, ledger)))
    adapter: BlocklistAdapter
    if firewall["backend"] == "nftables":
        adapter = NftablesBlocklistAdapter(peers=peers)
    elif firewall["backend"] == "vyos":
        adapter = VyosBlocklistAdapter(peers=peers)
    else:
        if len(peers) != 2:
            raise ConfigError("OPNsense HA requires exactly two peers")
        adapter = OPNsenseBlocklistAdapter(primary=peers[0], secondary=peers[1])
    if "wazuh" in cfg:
        wazuh = cfg["wazuh"]
        endpoint = WazuhIsolationAdapter(client=WazuhApiClient.from_files(
            url=wazuh["url"], ca=wazuh["ca"], credentials_file=wazuh["credentials_file"]))
    else:
        endpoint = UnavailableAdapter(name="wazuh", action="isolate_host")
    return [adapter, endpoint]
