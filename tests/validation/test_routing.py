"""Control-plane health gate. Security tests are invalid until this passes."""

from __future__ import annotations

from conftest import in_node


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

    observed = {
        "bgp_established": bgp_established,
        "ospf_full_neighbors": ospf_full,
        "ospf_auth_all_participants": auth_everywhere,
        "bgp_gtsm_both_peers": gtsm,
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
    assert edge_default and dc_route and all(campus_defaults.values()), (
        "required default/DC routes missing"
    )
