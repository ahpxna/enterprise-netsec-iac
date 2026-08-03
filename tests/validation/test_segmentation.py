"""
SEG-01 / SEG-02 — segmentation is asserted by *doing* the connection and
observing it fail, not by reading an ACL and assuming.
"""
import pytest
from conftest import in_node


def _tcp_reachable(src, dst_ip, port, timeout=5):
    # ncat -z returns 0 if the port is reachable, non-zero if blocked/closed
    r = in_node(src, "nc", "-z", "-w", "3", dst_ip, str(port), timeout=timeout)
    return r.returncode == 0


def test_user_vlan_blocked_from_radius(evidence):
    """SEG-01: PC1 (user VLAN) must NOT reach Server1 RADIUS (1812) or SSH (22)."""
    radius = _tcp_reachable("pc1", "172.16.50.1", 1812)
    ssh = _tcp_reachable("pc1", "172.16.50.1", 22)
    dns_ok = in_node("pc1", "nc", "-zu", "-w", "3", "172.16.50.1", "53").returncode == 0
    evidence(control="SEG-01", radius_reachable=radius, ssh_reachable=ssh,
             dns_reachable=dns_ok, expectation="radius+ssh blocked, dns allowed")
    assert not radius, "RADIUS reachable from user VLAN — segmentation FAILED"
    assert not ssh, "SSH reachable from user VLAN — segmentation FAILED"


def test_dmz_cannot_pivot_internal(evidence):
    """SEG-02: DMZ web host must NOT initiate into DC/campus."""
    to_dc = _tcp_reachable("dmz-web", "172.16.50.1", 22)
    to_campus = _tcp_reachable("dmz-web", "192.168.10.1", 22)
    evidence(control="SEG-02", dmz_to_dc=to_dc, dmz_to_campus=to_campus,
             expectation="both blocked")
    assert not to_dc and not to_campus, "DMZ can pivot inward — isolation FAILED"
