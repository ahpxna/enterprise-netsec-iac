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


def reachability(bf: Session, destination_port: int, protocol: str = "UDP"):
    return bf.q.reachability(
        pathConstraints={"startLocation": "@enter(dist1[Ethernet1])"},
        headers=HeaderConstraints(
            srcIps="192.168.10.1",
            dstIps="172.16.50.1",
            dstPorts=str(destination_port),
            ipProtocols=protocol,
        ),
        actions="SUCCESS",
    ).answer().frame()


@pytest.mark.parametrize(
    ("port", "protocol", "service"),
    [
        (53, "UDP", "DNS"),
        (123, "UDP", "NTP"),
    ],
)
def test_reviewed_user_to_dc_exceptions_are_reachable(bf, port, protocol, service):
    """Positive controls prove the model is connected and intended exceptions work."""
    assert not reachability(bf, port, protocol).empty, f"{service} positive control is not reachable"


@pytest.mark.parametrize(
    ("port", "protocol", "service"),
    [
        (1812, "UDP", "RADIUS"),
        (161, "UDP", "SNMP"),
        (22, "TCP", "SSH"),
        (80, "TCP", "HTTP"),
        (443, "TCP", "HTTPS"),
    ],
)
def test_user_vlan_cannot_reach_unapproved_dc_services(bf, port, protocol, service):
    """The user VLAN must not acquire new DC reachability outside explicit ACL exceptions."""
    assert reachability(bf, port, protocol).empty, f"User VLAN can reach prohibited {service} service"


def test_snapshot_has_no_parse_or_reference_errors(bf):
    parse_status = bf.q.fileParseStatus().answer().frame()
    failed = parse_status[parse_status["Status"].astype(str) != "PASSED"]
    assert failed.empty, f"Batfish parse failures:\n{failed.to_string(index=False)}"

    undefined = bf.q.undefinedReferences().answer().frame()
    assert undefined.empty, f"Undefined references:\n{undefined.to_string(index=False)}"
