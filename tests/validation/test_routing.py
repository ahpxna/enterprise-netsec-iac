"""Control-plane health gate. Security tests are invalid until this passes."""

from __future__ import annotations

import os
from pathlib import Path

from conftest import in_node

ROOT = Path(__file__).resolve().parents[2]


def _local_secret(name: str) -> str:
    if os.environ.get(name):
        return os.environ[name]
    env_file = ROOT / ".env"
    if not env_file.exists():
        return ""
    for raw in env_file.read_text().splitlines():
        key, separator, value = raw.partition("=")
        if separator and key == name:
            return value.strip().strip('"').strip("'")
    return ""


def _show(node: str, command: str) -> str:
    result = in_node(node, "vtysh", "-c", command)
    assert result.returncode == 0, f"{node}: {command}: {result.stderr}"
    return result.stdout


def test_ospf_md5_and_bgp_ttl(evidence):
    edge_running = _show("edge", "show running-config")
    core_running = _show("core", "show running-config")
    dist1_running = _show("dist1", "show running-config")
    dist2_running = _show("dist2", "show running-config")
    bgp_summary = _show("edge", "show bgp ipv4 unicast summary")
    core_neighbors = _show("core", "show ip ospf neighbor")
    edge_routes = _show("edge", "show ip route")
    core_routes = _show("core", "show ip route")
    dist1_routes = _show("dist1", "show ip route")
    dist2_routes = _show("dist2", "show ip route")

    expected_peers = {"198.10.10.1", "197.10.10.1"}
    established_peers = {
        fields[0]
        for line in bgp_summary.splitlines()
        if (fields := line.split())
        and fields[0] in expected_peers
        and fields[-1].isdigit()
    }
    bgp_established = len(established_peers)
    ospf_full = sum("Full" in line for line in core_neighbors.splitlines())
    auth_everywhere = all(
        "message-digest" in config
        for config in (core_running, dist1_running, dist2_running)
    )
    gtsm = edge_running.count("ttl-security hops 1") >= 2
    edge_default = "0.0.0.0/0" in edge_routes
    dc_route = "172.16.50.0/24" in core_routes
    campus_defaults = {
        "dist1": "0.0.0.0/0" in dist1_routes,
        "dist2": "0.0.0.0/0" in dist2_routes,
    }

    routing_secrets = [
        _local_secret(name)
        for name in ("BGP_ISP1_SECRET", "BGP_ISP2_SECRET", "OSPF_MD5_SECRET")
    ]
    strong_unique = (
        all(len(secret) >= 24 and not secret.startswith("CHANGE_ME") for secret in routing_secrets)
        and len(set(routing_secrets)) == 3
    )
    runtime_dir = ROOT / "clab" / "runtime-configs"
    runtime_configs = [
        runtime_dir / name
        for name in ("edge.frr.conf", "isp1.frr.conf", "isp2.frr.conf", "core.frr.conf", "dist1.frr.conf", "dist2.frr.conf")
    ]
    runtime_materialized = all(path.is_file() for path in runtime_configs)
    runtime_placeholders = [
        str(path.relative_to(ROOT))
        for path in runtime_configs
        if path.is_file() and "CHANGE_ME_" in path.read_text()
    ]

    observed = {
        "bgp_established": bgp_established,
        "ospf_full_neighbors": ospf_full,
        "ospf_auth_all_participants": auth_everywhere,
        "bgp_gtsm_both_peers": gtsm,
        "routing_secrets_strong_unique": strong_unique,
        "runtime_configs_materialized": runtime_materialized,
        "runtime_placeholder_files": runtime_placeholders,
        "edge_default_route": edge_default,
        "core_dc_route": dc_route,
        "campus_default_routes": campus_defaults,
    }
    evidence(
        control="RTR-01",
        assertion="BGP 2/2 Established; OSPF 2/2 Full; auth and required routes present",
        observed=observed,
        enforcement_node="edge,core,dist1,dist2",
    )
    assert bgp_established == 2, f"expected 2 established BGP peers, got {bgp_established}"
    assert ospf_full == 2, f"expected 2 Full OSPF neighbors, got {ospf_full}"
    assert auth_everywhere, "OSPF authentication missing on one or more peers"
    assert gtsm, "BGP GTSM missing on one or more peers"
    assert strong_unique, "routing authentication material is missing, weak, reused, or still a placeholder"
    assert runtime_materialized and not runtime_placeholders, "Path A runtime routing configs are absent or still contain placeholders"
    assert edge_default and dc_route and all(campus_defaults.values()), (
        "required default/DC routes missing"
    )
