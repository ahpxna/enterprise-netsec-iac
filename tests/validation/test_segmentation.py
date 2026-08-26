"""Live segmentation proof with service health and enforcement attribution."""

from __future__ import annotations

import re
import time
import os
import pathlib

from conftest import in_node


ROOT = pathlib.Path(__file__).resolve().parents[2]


def _local_secret(name: str) -> str:
    if os.environ.get(name):
        return os.environ[name]
    env_file = ROOT / ".env"
    if env_file.exists():
        for raw in env_file.read_text().splitlines():
            key, separator, value = raw.partition("=")
            if separator and key == name:
                return value.strip().strip('"').strip("'")
    return ""


def _tcp_reachable(src: str, dst_ip: str, port: int, timeout: int = 5) -> bool:
    result = in_node(src, "nc", "-z", "-w", "3", dst_ip, str(port), timeout=timeout)
    return result.returncode == 0


def _udp_listener(node: str, port: int) -> bool:
    result = in_node(node, "sh", "-c", f"ss -H -uln | grep -E ':{port}([[:space:]]|$)'")
    return result.returncode == 0


def _tcp_listener(node: str, port: int) -> bool:
    result = in_node(node, "sh", "-c", f"ss -H -tln | grep -E ':{port}([[:space:]]|$)'")
    return result.returncode == 0


def _management_interface_down(node: str) -> bool:
    result = in_node(node, "sh", "-c", "ip -o link show dev eth0 2>/dev/null")
    return result.returncode == 0 and "state DOWN" in result.stdout


def _counter(node: str, table: str, name: str) -> int:
    result = in_node(node, "nft", "list", "counter", "inet", table, name)
    if result.returncode != 0:
        raise AssertionError(f"cannot read nft counter {table}/{name}: {result.stderr}")
    match = re.search(r"packets\s+(\d+)", result.stdout)
    if not match:
        raise AssertionError(f"cannot parse nft counter {table}/{name}: {result.stdout}")
    return int(match.group(1))


def _udp_probe(src: str, dst_ip: str, port: int) -> None:
    in_node(src, "sh", "-c", f"printf cxyz-control-probe | nc -u -w 1 {dst_ip} {port}")


def test_user_vlan_blocked_from_radius(evidence):
    """SEG-01: healthy DC services, DNS allowed, RADIUS/SSH denied by fw-core."""
    radius_healthy = _udp_listener("server1", 1812)
    dns_healthy = _udp_listener("server1", 53)
    ssh_healthy = _tcp_listener("server1", 22)
    mgmt_ssh = _tcp_reachable("pc4", "172.16.50.1", 22)
    pc4_secret = _local_secret("RADIUS_SECRET_PC4")
    radius_positive = False
    if pc4_secret:
        command = (
            "printf '%s\\n' 'User-Name = cxyz-precondition' "
            "'User-Password = deliberately-invalid' | "
            f"radclient -x 172.16.50.1 auth '{pc4_secret}'"
        )
        response = in_node("pc4", "sh", "-c", command)
        radius_positive = "Access-Reject" in (response.stdout + response.stderr)

    radius_before = _counter("fw-core", "cxyz", "seg01_radius_drop")
    ssh_before = _counter("fw-core", "cxyz", "seg01_ssh_drop")
    _udp_probe("pc1", "172.16.50.1", 1812)
    user_ssh = _tcp_reachable("pc1", "172.16.50.1", 22)
    user_mgmt_bypass = _tcp_reachable("pc1", "10.1.1.50", 22)
    pc1_mgmt_down = _management_interface_down("pc1")
    time.sleep(0.25)
    radius_after = _counter("fw-core", "cxyz", "seg01_radius_drop")
    ssh_after = _counter("fw-core", "cxyz", "seg01_ssh_drop")

    dns = in_node("pc1", "dig", "+time=2", "+tries=1", "@172.16.50.1", "server1.companyxyz.lab")
    dns_allowed = dns.returncode == 0 and "172.16.50.1" in dns.stdout

    observed = {
        "precondition_radius_listener": radius_healthy,
        "precondition_dns_listener": dns_healthy,
        "precondition_ssh_listener": ssh_healthy,
        "positive_mgmt_ssh": mgmt_ssh,
        "positive_mgmt_radius_response": radius_positive,
        "positive_user_dns": dns_allowed,
        "user_ssh_reachable": user_ssh,
        "user_management_bypass_reachable": user_mgmt_bypass,
        "pc1_management_interface_down": pc1_mgmt_down,
        "radius_counter_delta": radius_after - radius_before,
        "ssh_counter_delta": ssh_after - ssh_before,
    }
    evidence(
        control="SEG-01",
        assertion="healthy services; DNS allowed; user RADIUS/SSH denied by fw-core counters",
        observed=observed,
        enforcement_node="fw-core",
        counter_before=radius_before + ssh_before,
        counter_after=radius_after + ssh_after,
    )

    assert radius_healthy and dns_healthy and ssh_healthy, "DC service precondition failed"
    assert mgmt_ssh and radius_positive, "management positive-control flow failed"
    assert dns_allowed, "allowed user-to-DC DNS flow failed"
    assert not user_ssh, "user VLAN reached DC SSH"
    assert pc1_mgmt_down and not user_mgmt_bypass, "pc1 retained an alternate Docker-management path"
    assert radius_after > radius_before, "RADIUS deny not attributed to fw-core"
    assert ssh_after > ssh_before, "SSH deny not attributed to fw-core"


def test_dmz_cannot_pivot_internal(evidence):
    """SEG-02: healthy internal target; DMZ attempt denied by fw-dmz counter."""
    target_healthy = _tcp_listener("server1", 22)
    positive_control = _tcp_reachable("pc4", "172.16.50.1", 22)
    before = _counter("fw-dmz", "dmz", "dmz_pivot_drop")
    dmz_to_dc = _tcp_reachable("dmz-web", "172.16.50.1", 22)
    dmz_mgmt_bypass = _tcp_reachable("dmz-web", "10.1.1.50", 22)
    dmz_mgmt_down = _management_interface_down("dmz-web")
    time.sleep(0.25)
    after = _counter("fw-dmz", "dmz", "dmz_pivot_drop")

    observed = {
        "precondition_ssh_listener": target_healthy,
        "positive_mgmt_ssh": positive_control,
        "dmz_to_dc_reachable": dmz_to_dc,
        "dmz_management_bypass_reachable": dmz_mgmt_bypass,
        "dmz_management_interface_down": dmz_mgmt_down,
        "pivot_counter_delta": after - before,
    }
    evidence(
        control="SEG-02",
        assertion="healthy internal SSH target; DMZ denied and fw-dmz counter increases",
        observed=observed,
        enforcement_node="fw-dmz",
        counter_before=before,
        counter_after=after,
    )
    assert target_healthy and positive_control, "internal service precondition failed"
    assert not dmz_to_dc, "DMZ reached the DC SSH service"
    assert dmz_mgmt_down and not dmz_mgmt_bypass, "DMZ host retained an alternate Docker-management path"
    assert after > before, "DMZ deny not attributed to fw-dmz"
