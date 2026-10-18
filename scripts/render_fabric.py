#!/usr/bin/env python3
"""Render Path A topology from the canonical fabric intent.

Addressing and link membership live only in intent/fabric.yaml. The rendered
containerlab file is checked in for operator visibility, while CI runs this
script with --check and rejects drift.
"""

from __future__ import annotations

import argparse
import copy
import pathlib
import sys

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
INTENT_PATH = ROOT / "intent" / "fabric.yaml"
OUTPUT_PATH = ROOT / "clab" / "companyxyz.clab.yml"

FRR_IMAGE = "quay.io/frrouting/frr@sha256:f310c2ebb3827fa03b9674ee05e70a7d5eef2123bcc3b475eb2ef14dafcb52b4"
TOOLS_IMAGE = "wbitt/network-multitool@sha256:db2810fe2c8d36db074eab5d98fbf861c8ed55e0786d648d3477b3de9135632e"


class IndentedSafeDumper(yaml.SafeDumper):
    """Emit sequence items indented beneath their mapping key for yamllint."""

    def increase_indent(self, flow: bool = False, indentless: bool = False):
        return super().increase_indent(flow, indentless=False)


def shell_commands(node: dict) -> list[str]:
    commands = []
    for index, attachment in enumerate(node.get("attachments", []), start=1):
        commands.append(
            f"sh -c 'ip address replace {attachment['address']} dev eth{index}'"
        )
    for route in node.get("routes", []):
        commands.append(
            f"sh -c 'ip route replace {route['to']} via {route['via']}'"
        )
    return commands


def management_forward_guards(node: dict, management_subnet: str) -> list[str]:
    """Reject routed data-plane traffic into the Docker management subnet.

    Containerlab management interfaces are convenient for trusted network-device
    administration, but Linux routers also forward packets.  Without an explicit
    FIB rule, a packet arriving on a data interface could be routed out eth0 into
    the OOB bridge.  Bind one fail-closed policy rule to every data interface;
    locally originated management traffic and packets addressed to the router's
    own eth0 address are unaffected.
    """
    commands: list[str] = []
    for index, _attachment in enumerate(node.get("attachments", []), start=1):
        priority = 11000 + index
        commands.append(
            "sh -c 'ip rule del pref {priority} 2>/dev/null || true; "
            "ip rule add pref {priority} iif eth{index} to {subnet} prohibit'".format(
                priority=priority, index=index, subnet=management_subnet
            )
        )
    return commands


# Firewall node -> nftables table whose SOC containment set the enforcement agent manages.
ENFORCER_TABLES = {"fw-core": "cxyz", "fw-dmz": "dmz"}
ENFORCER_PORT = 9443


def enforcer_binds(name: str) -> list[str]:
    """Public certificate, this node's own key, the CA certificate, and the agent source."""

    return [
        "../docker/enforcer/nft_enforcer.py:/opt/cxyz/nft_enforcer.py:ro",
        f"../soc/certs/enforcer-{name}.crt:/etc/cxyz/enforcer/tls.crt:ro",
        f"../soc/certs/enforcer-{name}.key:/etc/cxyz/enforcer/tls.key:ro",
        "../soc/certs/ca.crt:/etc/cxyz/enforcer/ca.crt:ro",
    ]


def enforcer_command(name: str, mgmt_ip: str) -> str:
    return (
        "sh -c 'nohup python3 /opt/cxyz/nft_enforcer.py "
        f"--listen {mgmt_ip} --port {ENFORCER_PORT} "
        "--cert /etc/cxyz/enforcer/tls.crt --key /etc/cxyz/enforcer/tls.key "
        "--client-ca /etc/cxyz/enforcer/ca.crt --allowed-client soc-response "
        f"--table {ENFORCER_TABLES[name]} --set soc_blocklist "
        ">/var/log/cxyz-enforcer.log 2>&1 &'"
    )


MANAGEMENT_TABLE = 100


def drop_management_default(node: dict, management_gateway: str) -> list[str]:
    """Routers must not forward user traffic via Docker's eth0 default.

    Docker installs `default via <mgmt gateway> dev eth0` in every container. As a
    kernel route it beats any OSPF/BGP default, so routed user traffic would leave
    through the OOB management bridge (and the host's NAT) instead of the fabric.
    Move it to a table only the router's own traffic (`iif lo`) may use, after the
    main table's specific routes, so package installs still work and forwarded
    traffic follows the routing protocol.
    """
    # Also for routers with a static fabric default (core): their own DNS and package
    # traffic needs management egress too; `del` is a no-op once the static route replaced it.
    table = MANAGEMENT_TABLE
    return [
        f"sh -c 'ip route replace default via {management_gateway} dev eth0 table {table} "
        f"&& {{ ip route del default via {management_gateway} dev eth0 2>/dev/null || true; }}'",
        "sh -c 'ip rule del pref 10900 2>/dev/null || true; ip rule del pref 10901 2>/dev/null || true; "
        f"ip rule add pref 10900 iif lo lookup main suppress_prefixlength 0 && ip rule add pref 10901 iif lo lookup {table}'",
    ]


def node_definition(name: str, node: dict, management_subnet: str, management_gateway: str = "") -> dict:
    role = node["role"]
    rendered: dict = {
        "kind": "linux",
        "mgmt-ipv4": node["mgmt_ip"],
    }
    if role in {"router", "isp"}:
        rendered["image"] = FRR_IMAGE
        rendered["binds"] = [
            f"runtime-configs/{name}.frr.conf:/etc/frr/frr.conf:ro",
            "runtime-configs/frr-daemons:/etc/frr/daemons:ro",
        ]
        rendered["exec"] = [
            "sysctl -w net.ipv4.ip_forward=1",
            *management_forward_guards(node, management_subnet),
            *shell_commands(node),
        ]
        if role == "router" and management_gateway:
            rendered["exec"].extend(drop_management_default(node, management_gateway))
        if name in {"dist1", "dist2"}:
            # FRR requires its VRRP macvlan interfaces before vrrpd starts.
            rendered["binds"].append(
                "configs/frr-vrrp-bootstrap.sh:/usr/local/bin/cxyz-frr-start:ro"
            )
            rendered["cmd"] = "bash /usr/local/bin/cxyz-frr-start"
    elif role == "firewall":
        rendered["image"] = TOOLS_IMAGE
        rendered["binds"] = [
            f"configs/{name}.nft:/etc/nftables/policy.nft:ro",
            *enforcer_binds(name),
        ]
        rendered["exec"] = [
            "apk add --no-cache python3 rsyslog rsyslog-tls nftables",
            "mkdir -p /etc/rsyslog.d /etc/ssh/sshd_config.d",
            "sysctl -w net.ipv4.ip_forward=1",
            *shell_commands(node),
            "nft -f /etc/nftables/policy.nft",
            enforcer_command(name, node["mgmt_ip"]),
        ]
    else:
        if name == "server1":
            rendered["image"] = "cxyz/server1:local"
            rendered["exec"] = shell_commands(node)
            return rendered
        packages = "python3 rsyslog rsyslog-tls netcat-openbsd"
        if name in {"pc1", "pc4"}:
            packages += " freeradius-utils"
        rendered["image"] = TOOLS_IMAGE
        rendered["exec"] = [
            f"apk add --no-cache {packages}",
            "mkdir -p /etc/rsyslog.d /etc/ssh/sshd_config.d",
            *shell_commands(node),
        ]
        # Untrusted endpoints need Docker management reachability only while
        # containerlab is executing bootstrap commands (notably apk installs).
        # Drop eth0 only after the intended data-plane address/default route
        # exist so ordinary workload traffic cannot bypass the routed firewalls.
        if node.get("disable_management_after_boot"):
            rendered["exec"].append("sh -c 'ip link set eth0 down'")
    return rendered


def render(intent: dict) -> str:
    topology: dict = {
        "name": intent["name"],
        "mgmt": {
            "network": intent["management"]["network"],
            "ipv4-subnet": intent["management"]["subnet"],
            "ipv4-gw": intent["management"]["gateway"],
        },
        "topology": {
            "nodes": {},
            "links": [],
        },
    }
    nodes = topology["topology"]["nodes"]
    links = topology["topology"]["links"]

    for name, node in intent["nodes"].items():
        nodes[name] = node_definition(name, node, intent["management"]["subnet"], intent["management"]["gateway"])

    # An isolated namespace hosts both user broadcast domains. The bridge
    # objects are created by containerlab inside this namespace.
    nodes["access-switch"] = {
        "kind": "linux",
        "image": "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
        "cmd": "sleep infinity",
    }
    for link_name, link in intent["links"].items():
        if link["kind"] == "lan":
            bridge_node = f"{link['bridge']}|access-switch"
            nodes[bridge_node] = {
                "kind": "bridge",
                "network-mode": "container:access-switch",
            }
        elif link["kind"] == "external_bridge":
            nodes[link["bridge"]] = {"kind": "bridge"}

    attachments: dict[str, list[tuple[str, int]]] = {
        name: [] for name in intent["links"]
    }
    for node_name, node in intent["nodes"].items():
        for index, attachment in enumerate(node.get("attachments", []), start=1):
            attachments[attachment["link"]].append((node_name, index))

    for link_name, link in intent["links"].items():
        members = attachments[link_name]
        if link["kind"] == "p2p":
            if len(members) != 2:
                raise ValueError(f"p2p link {link_name} has {len(members)} endpoints")
            links.append({
                "endpoints": [
                    f"{members[0][0]}:eth{members[0][1]}",
                    f"{members[1][0]}:eth{members[1][1]}",
                ]
            })
            continue

        bridge_node = (
            f"{link['bridge']}|access-switch"
            if link["kind"] == "lan"
            else link["bridge"]
        )
        for member_index, (node_name, interface_index) in enumerate(members, start=1):
            links.append({
                "endpoints": [
                    f"{node_name}:eth{interface_index}",
                    f"{bridge_node}:{link_name}-{member_index}",
                ]
            })

    header = (
        "# GENERATED by scripts/render_fabric.py from intent/fabric.yaml.\n"
        "# Do not edit addressing or links here; edit the canonical intent.\n"
        "---\n"
    )
    body = yaml.dump(
        copy.deepcopy(topology),
        Dumper=IndentedSafeDumper,
        sort_keys=False,
        default_flow_style=False,
    )
    if body.startswith("---\n"):
        body = body[4:]
    return header + body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    intent = yaml.safe_load(INTENT_PATH.read_text())
    rendered = render(intent)

    if args.check:
        current = OUTPUT_PATH.read_text() if OUTPUT_PATH.exists() else ""
        if current != rendered:
            print(
                "clab/companyxyz.clab.yml is stale; run "
                "python scripts/render_fabric.py",
                file=sys.stderr,
            )
            return 1
        print("OK: Path A topology matches canonical fabric intent")
        return 0

    OUTPUT_PATH.write_text(rendered)
    print(f"rendered {OUTPUT_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
