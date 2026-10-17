"""Entrypoints: ``python -m response.service orchestrator|decision --config FILE``."""

from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import ssl
import sys
from threading import Event, Thread
import time
from typing import Any, Mapping

from urllib.parse import urlsplit

from soc.workers.common import ElasticClient, FileAuthorization, address_toward, single_owner
from soc.workers.https import DeliveryError, JsonHTTPS

from ..decision import DecisionEngine
from ..orchestrator.engine import ResponseOrchestrator
from ..orchestrator.store import SQLiteResponseStore
from ..policy import PolicyCatalog
from ..signing import Ed25519CommandAuthenticator
from .api import create_app
from .config import (
    ConfigError,
    build_adapters,
    load_yaml,
    parse_decision_service,
    parse_response_service,
)
from .decision_runner import DecisionRunner, DecisionState
from .runner import AuditExporter, ResponseService


def _elastic(cfg: Mapping[str, Any]) -> ElasticClient:
    return ElasticClient(JsonHTTPS(cfg["url"], ca=cfg["ca"], authorization=FileAuthorization(cfg["api_key_file"])))


def run_orchestrator(config_path: Path) -> int:
    cfg = parse_response_service(load_yaml(config_path))
    host = cfg["listen"]["host"]
    if host == "toward-elasticsearch":
        # Bind only the network that reaches Elasticsearch (the private SOC backend),
        # never the management/egress networks this container is also attached to.
        host = address_toward(urlsplit(cfg["elasticsearch"]["url"]).hostname, 9200)
    address = ipaddress.ip_address(host)
    if address.is_unspecified or address.is_multicast:
        raise ConfigError("listen.host must be an explicit interface address")
    state_dir = Path(cfg["state_dir"])
    os.umask(0o077)
    store = SQLiteResponseStore(state_dir / "journal.sqlite")
    try:
        orchestrator = ResponseOrchestrator(
            catalog=PolicyCatalog.from_path(cfg["policy_file"]),
            authenticator=Ed25519CommandAuthenticator.verifier(cfg["verify_keys_dir"]),
            store=store,
            adapters=build_adapters(cfg, state_dir),
        )
        service = ResponseService(
            orchestrator=orchestrator, exporter=AuditExporter(store, _elastic(cfg["elasticsearch"])),
            mode=cfg["mode"],
        )
        service.start()
        stop = Event()

        def schedule() -> None:
            while not stop.wait(cfg.get("tick_seconds", 10)):
                try:
                    service.tick()
                except Exception as exc:  # keep scheduling; the failure stays visible in metrics/logs
                    print(f"tick failed: {type(exc).__name__}", file=sys.stderr, flush=True)

        Thread(target=schedule, daemon=True, name="response-scheduler").start()
        import uvicorn

        listen = cfg["listen"]
        uvicorn.run(
            create_app(service), host=host, port=int(listen["port"]), ssl_certfile=listen["cert"],
            ssl_keyfile=listen["key"], ssl_ca_certs=listen["client_ca"], ssl_cert_reqs=ssl.CERT_REQUIRED,
            proxy_headers=False, access_log=False, limit_concurrency=16,
        )
        stop.set()
        return 0
    finally:
        store.close()


def _load_intel(path: str | None) -> list[str]:
    if not path:
        return []
    return [
        line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def run_decision(config_path: Path, *, once: bool = False) -> int:
    cfg = parse_decision_service(load_yaml(config_path))
    os.umask(0o077)
    state_path = Path(cfg["state_dir"]) / "state.sqlite"
    sender = None
    if cfg["mode"] == "enforce":
        orch = cfg["orchestrator"]
        transport = JsonHTTPS(orch["url"], ca=orch["ca"], cert=orch["client_cert"], key=orch["client_key"])

        def sender(command: Mapping[str, Any]) -> None:
            status, _ = transport.request("POST", "/v1/commands", dict(command))
            if status not in (200, 202):
                raise DeliveryError("COMMAND_NOT_ACCEPTED", retryable=False)

    with single_owner(state_path):
        state = DecisionState(state_path)
        try:
            engine = DecisionEngine(
                PolicyCatalog.from_path(cfg["policy_file"]),
                Ed25519CommandAuthenticator.signer(cfg["signing_key_file"], cfg["signing_key_id"]),
            )
            runner = DecisionRunner(
                elastic=_elastic(cfg["elasticsearch"]), engine=engine, state=state, mode=cfg["mode"],
                send_command=sender, min_score=cfg.get("min_score", 0.90),
                protected_assets=cfg.get("protected_assets", []),
                threat_intel=_load_intel(cfg.get("threat_intel_file")),
            )
            while True:
                try:
                    print({"run": runner.run_once(), "outcomes": state.counts()}, flush=True)
                except DeliveryError as exc:
                    print({"waiting": exc.code}, flush=True)
                if once:
                    return 0
                time.sleep(cfg.get("poll_seconds", 15))
        finally:
            state.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("orchestrator", "decision"):
        sub = commands.add_parser(name)
        sub.add_argument("--config", type=Path, required=True)
        if name == "decision":
            sub.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "orchestrator":
            return run_orchestrator(args.config)
        return run_decision(args.config, once=args.once)
    except ConfigError as exc:
        raise SystemExit(f"configuration refused: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
