"""RTR-01 — routing plane authentication is present in the live FRR config."""
from conftest import in_node


def test_ospf_md5_and_bgp_ttl(evidence):
    core = in_node("core", "vtysh", "-c", "show running-config")
    edge = in_node("edge", "vtysh", "-c", "show running-config")
    ospf_md5 = "message-digest" in core.stdout
    bgp_ttl = "ttl-security" in edge.stdout
    evidence(control="RTR-01", ospf_md5=ospf_md5, bgp_ttl=bgp_ttl)
    assert ospf_md5, "OSPF MD5 auth missing on core"
    assert bgp_ttl, "BGP ttl-security missing on edge"
