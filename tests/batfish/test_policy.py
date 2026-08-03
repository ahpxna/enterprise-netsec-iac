"""
Offline network-config policy tests with Batfish. These run in CI on every
push WITHOUT booting the lab, catching "this firewall change opens a hole"
before merge — the NetDevOps guardrail the old project only claimed to have.

Skips gracefully if pybatfish / a Batfish service isn't available, so the
suite never blocks contributors who only touch docs.
"""
import os
import pytest

pytest.importorskip("pybatfish")
from pybatfish.client.session import Session  # noqa: E402

BF_HOST = os.environ.get("BATFISH_SERVICE", "localhost")
SNAP = os.path.join(os.path.dirname(__file__), "snapshots")


@pytest.fixture(scope="module")
def bf():
    try:
        s = Session(host=BF_HOST)
        s.init_snapshot(SNAP, name="cxyz", overwrite=True)
    except Exception as e:  # no batfish service in this environment
        pytest.skip(f"Batfish service unavailable: {e}")
    return s


def test_user_vlan_cannot_reach_radius(bf):
    """The prohibited path (user VLAN -> Server1:1812) must be DENIED in config."""
    from pybatfish.datamodel.flow import HeaderConstraints
    ans = bf.q.reachability(
        pathConstraints={"startLocation": "dist1"},
        headers=HeaderConstraints(dstIps="172.16.50.1", dstPorts="1812",
                                  srcIps="192.168.10.0/24", ipProtocols="UDP"),
        actions="SUCCESS",
    ).answer().frame()
    assert ans.empty, "Config permits user VLAN -> RADIUS; segmentation regressed"


def test_no_undefined_acl_references(bf):
    refs = bf.q.undefinedReferences().answer().frame()
    assert refs.empty, f"Undefined config references: {list(refs['Struct Name'])}"
