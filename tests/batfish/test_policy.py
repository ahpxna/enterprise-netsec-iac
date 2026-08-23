"""Blocking Batfish checks for the generated campus-to-DC policy model."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

BF_HOST = os.environ.get("BATFISH_SERVICE", "localhost")
SNAPSHOT = Path(__file__).parent / "snapshots"


@pytest.fixture(scope="module")
def bf() -> Session:
    session = Session(host=BF_HOST)
    session.init_snapshot(str(SNAPSHOT), name="cxyz", overwrite=True)
    return session


def reachability(bf: Session, destination_port: int):
    return bf.q.reachability(
        pathConstraints={"startLocation": "@enter(dist1[Ethernet1])"},
        headers=HeaderConstraints(
            srcIps="192.168.10.1",
            dstIps="172.16.50.1",
            dstPorts=str(destination_port),
            ipProtocols="UDP",
        ),
        actions="SUCCESS",
    ).answer().frame()


def test_dns_positive_control_is_reachable(bf):
    """Prove the model is connected and the intended DNS exception works."""
    assert not reachability(bf, 53).empty, "DNS positive control is not reachable"


def test_user_vlan_cannot_reach_radius(bf):
    """The prohibited user-to-RADIUS path must have no successful flow."""
    assert reachability(bf, 1812).empty, "User VLAN can reach RADIUS"


def test_snapshot_has_no_parse_or_reference_errors(bf):
    parse_status = bf.q.fileParseStatus().answer().frame()
    failed = parse_status[parse_status["Status"].astype(str) != "PASSED"]
    assert failed.empty, f"Batfish parse failures:\n{failed.to_string(index=False)}"

    undefined = bf.q.undefinedReferences().answer().frame()
    assert undefined.empty, f"Undefined references:\n{undefined.to_string(index=False)}"
