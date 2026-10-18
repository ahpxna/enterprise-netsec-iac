"""Compose services on the shared DC bridge must not collide with containerlab's static hosts.

containerlab wires server1 and fw-core into br-cxyz-dc outside Docker IPAM, so Docker does not
know their addresses. A dynamically addressed service takes the first free IP (.1 = server1),
which silently splits traffic between two hosts (the Wazuh indexer was unreachable this way).
"""
from __future__ import annotations

import ipaddress
import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _fabric_dc_addresses() -> set[str]:
    intent = yaml.safe_load((ROOT / "intent/fabric.yaml").read_text())
    return {
        attachment["address"].split("/")[0]
        for node in intent["nodes"].values()
        for attachment in node.get("attachments", [])
        if attachment["link"] == "dc"
    }


def test_every_dc_bridge_service_has_a_fixed_non_colliding_address():
    subnet = ipaddress.ip_network(yaml.safe_load((ROOT / "intent/fabric.yaml").read_text())["links"]["dc"]["cidr"])
    reserved = _fabric_dc_addresses() | {"172.16.50.253"}           # + the Docker bridge gateway
    seen: dict[str, str] = {}
    for compose in ("docker-compose.yml", "docker-compose.path-a.yml"):
        services = (yaml.safe_load((ROOT / compose).read_text()) or {}).get("services") or {}
        for name, service in services.items():
            networks = service.get("networks") or {}
            if "cxyz_dc" not in networks:
                continue
            assert isinstance(networks, dict), f"{name}: cxyz_dc needs a fixed ipv4_address"
            address = (networks["cxyz_dc"] or {}).get("ipv4_address")
            assert address, f"{name}: cxyz_dc needs a fixed ipv4_address (dynamic IPs collide with server1)"
            assert ipaddress.ip_address(address) in subnet, f"{name}: {address} outside {subnet}"
            assert address not in reserved, f"{name}: {address} is a containerlab/gateway address"
            assert seen.setdefault(address, name) == name, f"{name} and {seen[address]} share {address}"
    assert seen, "no services found on cxyz_dc"
