"""Canonical Path A validation node sets.

Keeping control coverage in one place prevents wording such as "everywhere"
from silently drifting away from the topology inventory.
"""

MANAGED_NODES = (
    "edge",
    "core",
    "dist1",
    "dist2",
    "fw-core",
    "fw-dmz",
    "server1",
    "pc1",
    "pc4",
    "dmz-web",
)

ENDPOINT_NODES = ("pc1", "pc4", "dmz-web")
