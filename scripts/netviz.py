#!/usr/bin/env python3
"""CompanyXYZ network explorer: a local, read-only, GNS3-style view of the whole lab.

``python scripts/netviz.py`` serves http://127.0.0.1:8088 with

* a clickable topology (every node and link shows its IPs, interfaces, zone, routing,
  firewall policy, listening services and how to reach it),
* the SOC / AI / response data-flow plane,
* the IP plan, routing, firewall, service/port, identity and control tables, and
* a live overlay (container state, firewall containment sets, index counts) when the lab runs.

Everything is *derived* from the canonical sources (``intent/fabric.yaml``, the containerlab and
FRR/nftables configs, ``docker-compose.yml``, the policies and ``compliance/controls.yaml``), so
it cannot drift from what is deployed.  The server is read-only: GET only, fixed commands, no
user input reaches a subprocess, and secrets are never read - only their names and whether they
exist.  It binds to loopback by default (use an SSH tunnel for a remote host).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pathlib
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlsplit

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
UI = ROOT / "scripts" / "netviz_ui" / "index.html"
CLAB_PREFIX = "clab-companyxyz-"
FIREWALL_TABLES = {"fw-core": "cxyz", "fw-dmz": "dmz"}
SECRET_MASK = "••••"


# ------------------------------------------------------------------------------ small helpers
def read(path: str | pathlib.Path) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def load_yaml(path: str) -> Any:
    return yaml.safe_load(read(path))


def sh(argv: list[str], timeout: float = 5.0) -> tuple[int, str]:
    """Run a FIXED argv (never user input); return (rc, stdout). Missing tools are rc 127."""

    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False, cwd=ROOT)
        return done.returncode, done.stdout if done.returncode == 0 else (done.stdout + done.stderr)
    except FileNotFoundError:
        return 127, f"{argv[0]}: command not found"
    except subprocess.TimeoutExpired:
        return 124, f"{' '.join(argv[:3])}: timed out after {timeout:.0f}s"
    except OSError as exc:
        return 126, str(exc)


def strip_mask(address: str) -> str:
    return address.split("/")[0]


# ------------------------------------------------------------------------------ FRR parser
def parse_frr(text: str) -> dict[str, Any]:
    """Structured routing view of an FRR config. Passwords/keys are masked, never copied."""

    out: dict[str, Any] = {"hostname": None, "bgp": None, "ospf": None, "vrrp": [], "static": [],
                           "route_maps": [], "prefix_lists": [], "interfaces": {}}
    block: str | None = None
    iface: str | None = None
    rmap: dict[str, Any] | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("!"):
            if not raw.startswith(" "):
                block = None if raw.strip() == "!" else block
            continue
        indented = raw.startswith(" ")
        line = raw.strip()
        if not indented:
            block, iface, rmap = None, None, None
            if line.startswith("hostname "):
                out["hostname"] = line.split(None, 1)[1]
            elif m := re.match(r"router bgp (\d+)", line):
                out["bgp"] = {"asn": int(m[1]), "router_id": None, "neighbors": {}, "networks": []}
                block = "bgp"
            elif line == "router ospf":
                out["ospf"] = {"router_id": None, "networks": [], "passive_default": False, "active": [],
                               "default_originate": False}
                block = "ospf"
            elif m := re.match(r"interface (\S+)", line):
                iface = m[1]
                out["interfaces"].setdefault(iface, {"ospf_auth": None, "vrrp": []})
                block = "interface"
            elif m := re.match(r"ip route (\S+) (\S+)", line):
                out["static"].append({"to": m[1], "via": m[2]})
            elif m := re.match(r"ip prefix-list (\S+) seq (\d+) (permit|deny) (\S+)", line):
                out["prefix_lists"].append({"name": m[1], "seq": int(m[2]), "action": m[3], "prefix": m[4]})
            elif m := re.match(r"route-map (\S+) (permit|deny) (\d+)", line):
                rmap = {"name": m[1], "action": m[2], "seq": int(m[3]), "match": []}
                out["route_maps"].append(rmap)
                block = "route-map"
            continue
        if block == "bgp" and out["bgp"] is not None:
            bgp = out["bgp"]
            if m := re.match(r"bgp router-id (\S+)", line):
                bgp["router_id"] = m[1]
            elif m := re.match(r"neighbor (\S+) remote-as (\d+)", line):
                bgp["neighbors"].setdefault(m[1], {})["remote_as"] = int(m[2])
            elif m := re.match(r"neighbor (\S+) password ", line):
                bgp["neighbors"].setdefault(m[1], {})["password"] = SECRET_MASK
            elif m := re.match(r"neighbor (\S+) ttl-security hops (\d+)", line):
                bgp["neighbors"].setdefault(m[1], {})["ttl_security_hops"] = int(m[2])
            elif m := re.match(r"neighbor (\S+) route-map (\S+) (in|out)", line):
                bgp["neighbors"].setdefault(m[1], {})[f"route_map_{m[3]}"] = m[2]
            elif m := re.match(r"network (\S+)", line):
                bgp["networks"].append(m[1])
        elif block == "ospf" and out["ospf"] is not None:
            ospf = out["ospf"]
            if m := re.match(r"ospf router-id (\S+)", line):
                ospf["router_id"] = m[1]
            elif m := re.match(r"network (\S+) area (\S+)", line):
                ospf["networks"].append({"prefix": m[1], "area": m[2]})
            elif line == "passive-interface default":
                ospf["passive_default"] = True
            elif m := re.match(r"no passive-interface (\S+)", line):
                ospf["active"].append(m[1])
            elif line.startswith("default-information originate"):
                ospf["default_originate"] = True
        elif block == "interface" and iface:
            info = out["interfaces"][iface]
            if line.startswith("ip ospf authentication message-digest"):
                info["ospf_auth"] = "md5"
            elif m := re.match(r"vrrp (\d+) version (\d+)", line):
                group = _vrrp(info, int(m[1]))
                group["version"] = int(m[2])
            elif m := re.match(r"vrrp (\d+) ip (\S+)", line):
                _vrrp(info, int(m[1]))["virtual_ip"] = m[2]
            elif m := re.match(r"vrrp (\d+) priority (\d+)", line):
                _vrrp(info, int(m[1]))["priority"] = int(m[2])
            elif m := re.match(r"vrrp (\d+) advertisement-interval (\d+)", line):
                _vrrp(info, int(m[1]))["advertisement_ms"] = int(m[2])
        elif block == "route-map" and rmap is not None and (m := re.match(r"match ip address prefix-list (\S+)", line)):
            rmap["match"].append(m[1])
    for name, info in out["interfaces"].items():
        for group in info["vrrp"]:
            out["vrrp"].append({"interface": name, **group})
    return out


def _vrrp(info: dict[str, Any], group: int) -> dict[str, Any]:
    for item in info["vrrp"]:
        if item["group"] == group:
            return item
    item = {"group": group}
    info["vrrp"].append(item)
    return item


# ------------------------------------------------------------------------------ nftables parser
def parse_nft(text: str) -> dict[str, Any]:
    """Tables, sets, chains and rules (with the human comment that precedes each rule)."""

    tables: list[dict[str, Any]] = []
    table: dict[str, Any] | None = None
    chain: dict[str, Any] | None = None
    comment: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if pending:
            pending += " " + stripped.rstrip("\\").strip()
            if stripped.endswith("\\"):
                continue
            stripped, pending = pending, ""
        elif stripped.endswith("\\"):
            pending = stripped.rstrip("\\").strip()
            continue
        if not stripped or stripped.startswith("#!"):
            continue
        if stripped.startswith("#"):
            comment.append(stripped.lstrip("# ").rstrip())
            continue
        if m := re.match(r"table (\S+) (\S+) \{", stripped):
            table = {"family": m[1], "name": m[2], "sets": [], "counters": [], "chains": []}
            tables.append(table)
            chain, comment = None, []
        elif table is None:
            continue
        elif chain is None and (m := re.match(r"set (\S+)\s*\{(.*)\}", stripped)):
            body = m[2]
            elements = re.search(r"elements = \{([^}]*)\}", body)
            table["sets"].append({
                "name": m[1],
                "type": (re.search(r"type (\S+?);", body) or [None, None])[1],
                "flags": (re.search(r"flags (\S+?);", body) or [None, None])[1],
                "elements": [e.strip() for e in elements[1].split(",")] if elements else [],
                "comment": " ".join(comment),
            })
            comment = []
        elif chain is None and (m := re.match(r"counter (\S+)\s*\{", stripped)):
            table["counters"].append(m[1])
        elif m := re.match(r"chain (\S+) \{", stripped):
            chain = {"name": m[1], "hook": None, "priority": None, "policy": None, "rules": []}
            table["chains"].append(chain)
            comment = []
        elif chain is not None and (m := re.match(r"type (\S+) hook (\S+) priority (\S+); policy (\S+);", stripped)):
            chain.update(type=m[1], hook=m[2], priority=m[3], policy=m[4])
        elif stripped == "}":
            if chain is not None:
                chain = None
            else:
                table = None
            comment = []
        elif chain is not None:
            verdict = re.search(r"\b(accept|drop|reject)\s*$", stripped)
            chain["rules"].append({
                "text": re.sub(r"\s+", " ", stripped),
                "verdict": verdict[1] if verdict else None,
                "comment": " ".join(comment),
                "log": (re.search(r'log prefix "([^"]+)"', stripped) or [None, None])[1],
            })
            comment = []
    return {"tables": tables}


# ------------------------------------------------------------------------------ curated knowledge
NODE_INFO: dict[str, dict[str, Any]] = {
    "isp1": {"label": "ISP 1", "kind": "isp", "tier": "internet", "pos": [420, 60],
             "desc": "Simulated upstream provider (AS 65010). eBGP to the edge router; only the lab's aggregate is accepted.",
             "services": [("179", "tcp", "BGP", "eBGP session with edge (password + TTL-security)")]},
    "isp2": {"label": "ISP 2", "kind": "isp", "tier": "internet", "pos": [700, 60],
             "desc": "Second simulated upstream provider (AS 65020) for dual-homed edge routing.",
             "services": [("179", "tcp", "BGP", "eBGP session with edge (password + TTL-security)")]},
    "edge": {"label": "Edge router", "kind": "router", "tier": "edge", "pos": [560, 200],
             "desc": "Internet edge (AS 65001). Dual-ISP BGP with GTSM and an outbound route-map so internal routes never leak.",
             "services": [("179", "tcp", "BGP", "eBGP to ISP1/ISP2")]},
    "fw-core": {"label": "Core firewall", "kind": "firewall", "tier": "firewall", "pos": [700, 360],
                "desc": "Default-deny perimeter firewall (nftables). Zones: outside (edge), campus (core), dc (servers). "
                        "Holds the SOC containment set the response plane writes to.",
                "services": [("22", "tcp", "SSH", "only from the management VLAN 192.168.40.0/24"),
                             ("9443", "tcp", "SOC enforcement agent", "mTLS API on the OOB mgmt net (10.1.1.0/24) - soc_blocklist only"),
                             ("6514", "tcp", "rsyslog TLS", "ships firewall logs to syslog-relay 172.16.50.11")]},
    "fw-dmz": {"label": "DMZ firewall", "kind": "firewall", "tier": "firewall", "pos": [180, 360],
               "desc": "Isolates the DMZ web segment; the DMZ can never initiate into internal zones.",
               "services": [("9443", "tcp", "SOC enforcement agent", "mTLS API on the OOB mgmt net - soc_blocklist only"),
                            ("6514", "tcp", "rsyslog TLS", "ships firewall logs to syslog-relay")]},
    "core": {"label": "Core router", "kind": "router", "tier": "core", "pos": [700, 520],
             "desc": "OSPF backbone (area 0, MD5 auth) between the firewall and the two distribution routers.",
             "services": [("89", "ospf", "OSPF", "MD5-authenticated adjacencies with dist1/dist2")]},
    "dist1": {"label": "Distribution 1", "kind": "router", "tier": "dist", "pos": [560, 680],
              "desc": "VRRP master (priority 150) for VLAN 10 and VLAN 40 gateways; OSPF to core.",
              "services": [("112", "vrrp", "VRRPv3", "VIPs 192.168.10.254 / 192.168.40.254")]},
    "dist2": {"label": "Distribution 2", "kind": "router", "tier": "dist", "pos": [860, 680],
              "desc": "VRRP backup (priority 100) for VLAN 10 and VLAN 40; takes over when dist1 fails.",
              "services": [("112", "vrrp", "VRRPv3", "backup for the same VIPs")]},
    "pc1": {"label": "PC1 (user)", "kind": "endpoint", "tier": "access", "pos": [500, 990],
            "desc": "Untrusted user workstation on VLAN 10. Source of the controlled 'prohibited scan'. "
                    "In Path B it runs a Wazuh agent with the isolation Active Response (the one isolatable host).",
            "services": []},
    "pc4": {"label": "PC4 (admin)", "kind": "endpoint", "tier": "access", "pos": [920, 990],
            "desc": "Administrative station on the management VLAN 40; the only VLAN allowed SSH to the DC.",
            "services": []},
    "server1": {"label": "Server1 (DNS/RADIUS/NTP)", "kind": "server", "tier": "dc", "pos": [1260, 520],
                "desc": "DC infrastructure server. Protected: the response plane must never block it.",
                "services": [("53", "udp", "DNS", "campus + management"), ("123", "udp", "NTP (NTS upstream)", "campus + management"),
                             ("1812", "udp", "RADIUS auth", "management VLAN only"),
                             ("1813", "udp", "RADIUS accounting", "management VLAN only"),
                             ("22", "tcp", "SSH", "management VLAN only")]},
    "dmz-web": {"label": "DMZ web", "kind": "server", "tier": "dmz", "pos": [180, 520],
                "desc": "Web server in the DMZ (195.1.1.160/29). Cannot initiate connections inward.",
                "services": [("80", "tcp", "HTTP", "published via the ZTNA gateway")]},
}

BRIDGE_INFO = {
    "vlan10": {"label": "VLAN 10 switch", "pos": [500, 840], "zone": "campus-user",
               "purpose": "User VLAN 10: untrusted workstations; gateway = VRRP VIP .254"},
    "vlan40": {"label": "VLAN 40 switch", "pos": [920, 840], "zone": "campus-mgmt",
               "purpose": "Management/admin VLAN 40: SSH/RADIUS/syslog/NTP/DNS to the DC; gateway = VRRP VIP .254"},
    "br-cxyz-dc": {"label": "DC bridge (br-cxyz-dc)", "pos": [1260, 360], "zone": "dc",
                   "purpose": "One shared L2 segment for the DC: fw-core, server1 and the Docker services (cxyz_dc network)"},
}

LINK_INFO = {
    "isp1_edge": ("ISP transit", "outside"), "isp2_edge": ("ISP transit", "outside"),
    "edge_fwcore": ("Edge to core firewall (outside)", "outside"), "fwcore_core": ("Core firewall to core (campus)", "campus"),
    "core_dist1": ("Core to dist1 routed /31", "campus"), "core_dist2": ("Core to dist2 routed /31", "campus"),
    "edge_fwdmz": ("Edge to DMZ firewall (outside)", "outside"),
    "vlan10": ("User VLAN 10 (untrusted workstations)", "campus"), "vlan40": ("Management/admin VLAN 40", "campus"),
    "dc": ("Data-centre segment (servers + Docker services)", "dc"), "dmz": ("DMZ web segment", "dmz"),
}

# Docker services that live on the DC bridge appear in the topology; all others only in the SOC plane.
DC_ATTACHED = {"syslog-relay": [1100, 680], "wazuh.manager": [1260, 680], "wireguard": [1420, 680],
               "wazuh-indexer": [1180, 830], "wazuh.dashboard": [1340, 830]}

# DMZ deception lab: Compose services that join dmz-web's network namespace (they share its address).
DMZ_LAB = {"dmz-vuln": {"pos": [60, 680], "ports": "tcp/3000"}, "dmz-honeypot": {"pos": [310, 680], "ports": "tcp/2222,2223"}}
DMZ_WEB_IP = "195.1.1.161"

SERVICE_INFO: dict[str, dict[str, Any]] = {
    "syslog-relay": ("Authenticated mTLS syslog relay: the only log ingress for firewalls, routers and servers.",
                     [("6514", "tcp", "syslog over TLS", "mTLS; client cert required")]),
    "wazuh.manager": ("Wazuh manager: HIDS, FIM, static rules and the Active Response engine.",
                      [("1514", "tcp", "agent channel", "agents on campus workstations"), ("1515", "tcp", "enrolment", "registration password"),
                       ("55000", "tcp", "Wazuh API", "response orchestrator only (least-privilege user)")]),
    "wazuh-indexer": ("OpenSearch-based Wazuh indexer (internal).", [("9200", "tcp", "indexer", "Wazuh components only")]),
    "wazuh.dashboard": ("Wazuh dashboard.", [("5601", "tcp", "HTTPS UI", "published on 127.0.0.1 only")]),
    "wireguard": ("WireGuard gateway: the only remote-admin path (no management port on the Internet).",
                  [("51820", "udp", "WireGuard", "published on the host; peers 10.13.13.0/24")]),
    "suricata": ("Suricata IDS (host network, sees the bridge span); writes EVE JSON.", []),
    "elasticsearch": ("Elasticsearch: all SOC streams (raw, events, features, ai, response, deadletter). Never published.",
                      [("9200", "tcp", "HTTPS API", "TLS + per-service least-privilege users")]),
    "logstash": ("Logstash ingestion: reads source files read-only, normalizes to ECS, routes parser failures to dead-letter.",
                 [("9600", "tcp", "monitoring API", "loopback in the container")]),
    "kibana": ("Kibana: four read-only dashboards. No response controls.", [("5601", "tcp", "HTTPS UI", "published on 127.0.0.1:5602")]),
    "soc-ai-api": ("Inference API: serves only the independently approved model; mTLS; no Elasticsearch credential.",
                   [("8443", "tcp", "inference API", "enrichment worker client certificate only")]),
    "soc-feature-worker": ("Builds closed 5-minute feature vectors into soc-features-*.", []),
    "soc-enrichment-worker": ("Pulls vectors, scores them over mTLS, writes soc-ai-* through a durable outbox.", []),
    "soc-decision": ("Decision runner: anomaly + independent signal -> Ed25519-signed command. Holds the only signing key.", []),
    "soc-response": ("Orchestrator: verifies, applies, verifies again, expires; append-only audit.",
                     [("8443", "tcp", "command intake", "mTLS; decision runner only")]),
    "traefik": ("ZTNA gateway: forward-auth through Authentik to the protected app.",
                [("80", "tcp", "HTTP", "redirect"), ("443", "tcp", "HTTPS", "published")]),
    "authentik-server": ("Authentik identity provider (SSO).", []),
    "authentik-worker": ("Authentik background worker.", []),
    "authentik-postgres": ("Authentik database (internal network only).", []),
    "ztna-demo-app": ("Protected demo application behind the ZTNA gateway.", []),
    "vpn-probe": ("Synthetic external WireGuard client used only by the VPN-01 test.", []),
    "dmz-vuln": ("OWASP Juice Shop: a deliberately vulnerable web application (OWASP flagship). Shares dmz-web's network namespace, "
                 "so it sits in the DMZ behind fw-dmz; it can never reach internal zones (pivot deny). Disposable; lab only.",
                 [("3000", "tcp", "Juice Shop HTTP", "Internet/campus through fw-dmz; every new connection is logged (CXYZ-DMZLAB-VULN)")]),
    "dmz-honeypot": ("Cowrie SSH/Telnet honeypot. Shares dmz-web's network namespace; every interaction is hostile by construction and its "
                     "JSON log is shipped read-only to Logstash as dataset cowrie.honeypot.",
                     [("2222", "tcp", "Cowrie SSH", "Internet/campus through fw-dmz; logged (CXYZ-DMZLAB-HONEYPOT)"),
                      ("2223", "tcp", "Cowrie Telnet", "same")]),
}

SOC_LAYOUT: dict[str, list[int]] = {
    "server1": [80, 200], "fw-dmz": [80, 360], "fw-core": [80, 520], "wazuh-agent-pc1": [80, 720],
    "suricata": [380, 160], "syslog-relay": [380, 360], "wazuh.manager": [380, 600],
    "logstash": [700, 360], "elasticsearch": [1020, 360], "kibana": [1020, 120], "analyst": [1340, 120],
    "soc-feature-worker": [860, 600], "soc-enrichment-worker": [1180, 600], "soc-ai-api": [1500, 600],
    "soc-decision": [860, 840], "soc-response": [1180, 840], "vyos-api": [1500, 840], "dmz-honeypot": [380, 800],
}

SOC_FLOWS: list[dict[str, str]] = [
    {"src": "fw-core", "dst": "syslog-relay", "proto": "6514/tcp", "auth": "mTLS", "data": "firewall logs (CXYZ-* drop prefixes)"},
    {"src": "fw-dmz", "dst": "syslog-relay", "proto": "6514/tcp", "auth": "mTLS", "data": "DMZ firewall logs"},
    {"src": "server1", "dst": "syslog-relay", "proto": "6514/tcp", "auth": "mTLS", "data": "RADIUS outcomes (no passwords)"},
    {"src": "syslog-relay", "dst": "logstash", "proto": "file (ro volume)", "auth": "read-only mount", "data": "/var/log/cxyz/soc-remote.log"},
    {"src": "suricata", "dst": "logstash", "proto": "file (ro volume)", "auth": "read-only mount", "data": "eve.json"},
    {"src": "wazuh.manager", "dst": "logstash", "proto": "file (ro volume)", "auth": "read-only mount", "data": "alerts.json"},
    {"src": "dmz-honeypot", "dst": "logstash", "proto": "file (ro volume)", "auth": "read-only mount", "data": "cowrie.json (dataset cowrie.honeypot; passwords dropped)"},
    {"src": "logstash", "dst": "elasticsearch", "proto": "9200/tcp", "auth": "TLS + cxyz_logstash role", "data": "soc-raw / events / deadletter (create-only raw)"},
    {"src": "kibana", "dst": "elasticsearch", "proto": "9200/tcp", "auth": "TLS + kibana_system", "data": "dashboards read events, ai, response"},
    {"src": "analyst", "dst": "kibana", "proto": "5602/tcp", "auth": "TLS + user login", "data": "127.0.0.1 only"},
    {"src": "soc-feature-worker", "dst": "elasticsearch", "proto": "9200/tcp", "auth": "feature_engine role", "data": "reads events, writes soc-features-*"},
    {"src": "soc-enrichment-worker", "dst": "elasticsearch", "proto": "9200/tcp", "auth": "ai_event_writer role", "data": "reads features, writes soc-ai-*"},
    {"src": "soc-enrichment-worker", "dst": "soc-ai-api", "proto": "8443/tcp", "auth": "mTLS (dedicated client CA)", "data": "feature vector -> score"},
    {"src": "soc-decision", "dst": "elasticsearch", "proto": "9200/tcp", "auth": "decision_engine role", "data": "reads soc-ai + alerts (Suricata, Wazuh, honeypot) + auth, writes decisions"},
    {"src": "soc-decision", "dst": "soc-response", "proto": "8443/tcp", "auth": "mTLS + Ed25519 signature", "data": "signed containment command"},
    {"src": "soc-response", "dst": "elasticsearch", "proto": "9200/tcp", "auth": "response_orchestrator role", "data": "append-only audit"},
    {"src": "soc-response", "dst": "fw-core", "bend": "-0.3", "proto": "9443/tcp", "auth": "mTLS (CN soc-response)", "data": "add/remove/contains soc_blocklist"},
    {"src": "soc-response", "dst": "fw-dmz", "bend": "-0.22", "proto": "9443/tcp", "auth": "mTLS (CN soc-response)", "data": "add/remove/contains soc_blocklist"},
    {"src": "soc-response", "dst": "wazuh.manager", "bend": "-0.2", "proto": "55000/tcp", "auth": "TLS + scoped API user", "data": "isolate/restore Active Response (Path B)"},
    {"src": "wazuh.manager", "dst": "wazuh-agent-pc1", "proto": "1514/tcp", "auth": "agent key", "data": "Active Response command (Path B)"},
    {"src": "soc-response", "dst": "vyos-api", "proto": "443/tcp", "auth": "TLS + API key", "data": "SOC_BLOCKLIST address-group (Path B)"},
]

SOC_NODE_NOTES = {
    "analyst": ("Analyst", "person", "Browser on the lab host: https://127.0.0.1:5602 (Kibana)."),
    "wazuh-agent-pc1": ("Wazuh agent on pc1", "agent", "Path B only: runs the cxyz-isolate/restore-endpoint Active Response."),
    "vyos-api": ("VyOS HTTPS API (fw-core/fw-dmz)", "api", "Path B only: enabled by ansible role vyos_response_api; OOB mgmt address."),
}

ES_INDEX_FAMILIES = {
    "soc-raw-*": "exact received payload, create-only (14 d)", "soc-network-*": "normalized network telemetry (30 d)",
    "soc-endpoint-*": "normalized endpoint telemetry (30 d)", "soc-auth-*": "normalized authentication events (30 d)",
    "soc-alerts-*": "Suricata/Wazuh alerts (30 d)", "soc-features-*": "5-minute feature vectors (30 d)",
    "soc-ai-*": "model scores, identity and latency (90 d)", "soc-response-*": "decisions + append-only response audit (365 d)",
    "soc-deadletter-*": "parser failures with the original (14 d)",
}


# ------------------------------------------------------------------------------ model builder
def _clab() -> dict[str, Any]:
    return load_yaml("clab/companyxyz.clab.yml")


def _interface_map(intent: dict[str, Any], clab: dict[str, Any]) -> dict[tuple[str, str], str]:
    """(node, intent link) -> interface name, from the containerlab link list."""

    links = intent["links"]
    attached: dict[str, set[str]] = {}
    for node, spec in intent["nodes"].items():
        for item in spec.get("attachments", []):
            attached.setdefault(item["link"], set()).add(node)
    bridge_of = {spec.get("bridge"): name for name, spec in links.items() if spec.get("bridge")}
    out: dict[tuple[str, str], str] = {}
    for entry in clab["topology"]["links"]:
        ends = []
        for endpoint in entry["endpoints"]:
            node, _, iface = endpoint.rpartition(":")
            bridge = node.split("|")[0] if "|" in node else (node if node in bridge_of else None)
            ends.append({"node": node, "iface": iface, "bridge": bridge})
        bridged = [e for e in ends if e["bridge"]]
        if bridged:
            link = bridge_of.get(bridged[0]["bridge"])
            for end in ends:
                if not end["bridge"] and link:
                    out[(end["node"], link)] = end["iface"]
        else:
            a, b = ends
            for name, members in attached.items():
                if {a["node"], b["node"]} <= members and links[name]["kind"] == "p2p":
                    out[(a["node"], name)] = a["iface"]
                    out[(b["node"], name)] = b["iface"]
    return out


def _routing(intent: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for node in intent["nodes"]:
        path = ROOT / "clab" / "configs" / f"{node}.frr.conf"
        if path.is_file():
            result[node] = parse_frr(path.read_text(encoding="utf-8"))
            result[node]["config_file"] = f"clab/configs/{node}.frr.conf"
    adjacencies = []
    ospf_nodes = [n for n, r in result.items() if r.get("ospf")]
    shared = {}
    for node, spec in intent["nodes"].items():
        for item in spec.get("attachments", []):
            shared.setdefault(item["link"], []).append(node)
    for link, members in shared.items():
        pair = [m for m in members if m in ospf_nodes]
        for i, a in enumerate(pair):
            for b in pair[i + 1:]:
                if intent["links"][link]["kind"] == "p2p":
                    adjacencies.append({"protocol": "OSPF", "a": a, "b": b, "link": link, "area": "0", "auth": "md5"})
    seen_bgp: set[frozenset[str]] = set()
    for node, routing in result.items():
        bgp = routing.get("bgp")
        if not bgp:
            continue
        for neighbor, info in bgp["neighbors"].items():
            for other, spec in intent["nodes"].items():
                pair = frozenset((node, other))
                if other != node and pair not in seen_bgp and any(strip_mask(item["address"]) == neighbor for item in spec.get("attachments", [])):
                    seen_bgp.add(pair)
                    adjacencies.append({"protocol": "BGP", "a": node, "b": other, "link": None, "asn_a": bgp["asn"],
                                        "asn_b": info.get("remote_as"), "ttl_security": info.get("ttl_security_hops")})
    return {"nodes": result, "adjacencies": adjacencies}


def _firewalls() -> dict[str, Any]:
    result = {}
    for node, table in FIREWALL_TABLES.items():
        path = ROOT / "clab" / "configs" / f"{node}.nft"
        parsed = parse_nft(path.read_text(encoding="utf-8"))
        parsed["config_file"] = f"clab/configs/{node}.nft"
        parsed["soc_table"] = table
        result[node] = parsed
    return result


def _compose() -> dict[str, Any]:
    compose = load_yaml("docker-compose.yml")
    services = []
    for name, spec in compose["services"].items():
        nets = spec.get("networks")
        networks: list[dict[str, Any]] = []
        if isinstance(nets, dict):
            networks = [{"name": k, "ip": (v or {}).get("ipv4_address")} for k, v in nets.items()]
        elif isinstance(nets, list):
            networks = [{"name": k, "ip": None} for k in nets]
        ports = []
        for item in spec.get("ports", []) or []:
            text = str(item)
            m = re.match(r"(?:(?P<host>[\d.]+):)?(?P<pub>[^:]+):(?P<ctr>[^:/]+)(?:/(?P<proto>\w+))?$", text)
            if m:
                ports.append({"host": m["host"] or "0.0.0.0", "published": re.sub(r"\$\{[^:}]+:-(\d+)\}", r"\1", m["pub"]),
                              "container": re.sub(r"\$\{[^:}]+:-(\d+)\}", r"\1", m["ctr"]), "proto": m["proto"] or "tcp"})
        info = SERVICE_INFO.get(name, ("", []))
        services.append({
            "name": name, "profiles": spec.get("profiles", []), "image": str(spec.get("image", "")).split("@")[0],
            "networks": networks, "network_mode": spec.get("network_mode"), "ports": ports,
            "read_only": bool(spec.get("read_only")), "user": str(spec["user"]) if spec.get("user") else None,
            "description": info[0], "listens": [{"port": p, "proto": pr, "name": n, "who": w} for p, pr, n, w in info[1]],
            "credential_volume": next((v.split(":")[0] for v in spec.get("volumes", []) if str(v).startswith("soc_run_")), None),
        })
    networks = []
    for name, spec in (compose.get("networks") or {}).items():
        networks.append({"name": name, "internal": bool((spec or {}).get("internal")),
                         "external": bool((spec or {}).get("external")), "subnet": "172.16.50.0/24" if name == "cxyz_dc" else None})
    return {"services": services, "networks": networks}


def _mask_secret_names(env_file: pathlib.Path) -> list[dict[str, str]]:
    """Names of secrets and whether each is set - never a value."""

    rows = []
    if not env_file.is_file():
        return rows
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.split("  #")[0].strip().strip("'\"")
        if re.search(r"PASSWORD|SECRET|KEY|CRYPT|CREDENTIALS|TOKEN", key):
            state = "missing" if not value else "placeholder" if value.startswith("CHANGE_ME") else "set"
            rows.append({"name": key, "state": state})
    return rows


def _identity() -> dict[str, Any]:
    cert_dir = ROOT / "soc" / "certs"
    certs = sorted(p.name for p in cert_dir.glob("*.crt")) if cert_dir.is_dir() else []
    roles = []
    for path in sorted((ROOT / "soc" / "elasticsearch").glob("*-role.json")):
        body = json.loads(path.read_text(encoding="utf-8"))
        roles.append({"role": path.stem.replace("-role", ""), "file": f"soc/elasticsearch/{path.name}",
                      "indices": [{"names": grant["names"], "privileges": grant["privileges"]} for grant in body.get("indices", [])]})
    return {
        "env_secrets": _mask_secret_names(ROOT / ".env"), "soc_certificates_present": certs,
        "elasticsearch_roles": roles,
        "pki": [
            {"name": "SOC CA", "files": "soc/certs/ca.crt (+ca.key stays on the host)", "signs": "Elasticsearch, Kibana, Logstash, soc-ai-api, soc-response, enforcement agents, VyOS API"},
            {"name": "AI client CA", "files": "soc/certs/ai-client-ca.crt", "signs": "the only client allowed to call the inference API (enrichment worker)"},
            {"name": "Decision CA", "files": "soc/certs/decision-ca.crt", "signs": "the only client allowed to submit commands to the orchestrator (decision runner)"},
            {"name": "Decision signing key", "files": "soc/certs/decision/decision-key-1.{key,pub}", "signs": "Ed25519 response commands; only the .pub reaches the orchestrator"},
            {"name": "Wazuh PKI", "files": "docker/wazuh/certs/*", "signs": "Wazuh indexer, manager, dashboard (hostname-verified)"},
            {"name": "ZTNA TLS", "files": "docker/zero-trust-gateway/certs/*", "signs": "Traefik public listener"},
        ],
    }


def _policy() -> dict[str, Any]:
    policy = load_yaml("response/policies/default.yaml")
    defaults = policy["defaults"]
    deployments = {}
    for path in sorted((ROOT / "response" / "deployments").glob("*/*.yaml")):
        body = yaml.safe_load(path.read_text(encoding="utf-8"))
        deployments.setdefault(path.parent.name, {})[path.stem] = {"mode": body.get("mode"), "file": str(path.relative_to(ROOT))}
    return {
        "protected_ips": defaults["protections"]["protected_ips"], "protected_networks": defaults["protections"]["protected_networks"],
        "protected_hosts": defaults["protections"]["protected_hosts"],
        "allowed_isolation_hosts": defaults["protections"]["allowed_isolation_hosts"],
        "rate_limit": defaults["rate_limit"], "dedup_seconds": defaults["dedup_seconds"],
        "evidence_max_age_seconds": defaults["evidence_max_age_seconds"],
        "policies": [{"id": p["id"], "action": p["action"], "ttl_seconds": p["ttl_seconds"], "when": p["when"]} for p in policy["policies"]],
        "deployments": deployments,
        "thresholds": {"store_only": "score < 0.75", "alert": "0.75 <= score < 0.90",
                       "eligible": "score >= 0.90 AND an independent second signal"},
    }


def _model_registry() -> dict[str, Any]:
    meta = ROOT / "ai" / "registry" / "active" / "metadata.json"
    if not meta.is_file():
        return {"present": False, "note": "no approved model yet (make soc-ai-promote or scripts/demo_registry.py)"}
    body = json.loads(meta.read_text(encoding="utf-8"))
    return {"present": True, "model_id": body.get("model_id"), "algorithm": body.get("algorithm"), "status": body.get("status"),
            "feature_schema": (body.get("feature_schema") or {}).get("id"), "threshold": body.get("threshold"),
            "created_at": body.get("created_at")}


def _controls() -> list[dict[str, Any]]:
    catalog = load_yaml("compliance/controls.yaml")
    latest: dict[str, str] = {}
    runs = sorted((ROOT / "evidence" / "runs").glob("*")) if (ROOT / "evidence" / "runs").is_dir() else []
    for run in runs:
        for item in sorted(run.glob("*.json")):
            try:
                body = json.loads(item.read_text(encoding="utf-8"))
                if isinstance(body, dict) and "control_id" in body and "result" in body:
                    latest[body["control_id"]] = f"{body['result']} ({run.name})"
            except (OSError, ValueError):
                continue
    rows = []
    for control in catalog["controls"]:
        rows.append({
            "id": control["id"], "severity": control.get("severity"), "objective": control.get("objective"),
            "frameworks": control.get("framework"), "path_a_test": control.get("verified_by"),
            "path_b_test": control.get("verified_by_path_b"),
            "profiles": control.get("applicable_profiles", ["path-a", "path-b"]),
            "latest": latest.get(control["id"], "UNVERIFIED"),
        })
    for control in catalog.get("planned_controls", []):
        rows.append({"id": control["id"], "severity": None, "objective": control["objective"], "frameworks": [],
                     "path_a_test": None, "path_b_test": None, "profiles": [], "latest": "PLANNED",
                     "blocker": control.get("blocker")})
    return rows


def _git() -> dict[str, str]:
    out = {}
    for key, argv in (("branch", ["git", "rev-parse", "--abbrev-ref", "HEAD"]), ("commit", ["git", "rev-parse", "--short", "HEAD"])):
        rc, text = sh(argv, 3)
        out[key] = text.strip() if rc == 0 else "unknown"
    return out


def build_model() -> dict[str, Any]:
    intent = load_yaml("intent/fabric.yaml")
    clab = _clab()
    iface = _interface_map(intent, clab)
    links_cfg = intent["links"]
    routing = _routing(intent)
    firewalls = _firewalls()
    compose = _compose()

    nodes: list[dict[str, Any]] = []
    addresses: dict[str, list[dict[str, Any]]] = {}
    for name, spec in intent["nodes"].items():
        info = NODE_INFO[name]
        clab_node = clab["topology"]["nodes"].get(name, {})
        attachments = []
        for item in spec.get("attachments", []):
            link = links_cfg[item["link"]]
            attachments.append({"interface": iface.get((name, item["link"]), "?"), "address": item["address"], "ip": strip_mask(item["address"]),
                                "link": item["link"], "network": link["network_name"], "cidr": link["cidr"], "zone": item.get("zone"),
                                "peer": None})
            addresses.setdefault(item["link"], []).append({"node": name, "interface": attachments[-1]["interface"], "ip": strip_mask(item["address"])})
        nodes.append({
            "id": name, "label": info["label"], "kind": info["kind"], "tier": info["tier"], "pos": info["pos"],
            "role": spec["role"], "description": info["desc"], "mgmt_ip": spec["mgmt_ip"],
            "image": str(clab_node.get("image", "")).split("@")[0], "container": CLAB_PREFIX + name,
            "attachments": attachments, "routes": spec.get("routes", []),
            "listens": [{"port": p, "proto": pr, "name": n, "who": w} for p, pr, n, w in info["services"]],
            "routing": routing["nodes"].get(name), "firewall": firewalls.get(name),
            "config_file": (f"clab/configs/{name}.frr.conf" if name in routing["nodes"] else
                            f"clab/configs/{name}.nft" if name in firewalls else None),
            "path_b": {"management": spec.get("path_b_management", True), "proxy": spec.get("path_b_proxy"),
                       "detached_after_boot": bool(spec.get("disable_management_after_boot"))},
            "commands": [f"docker exec -it {CLAB_PREFIX}{name} sh", f"ssh admin@{spec['mgmt_ip']}   # Path B / mgmt net"],
        })
    node_ids = {n["id"] for n in nodes}

    bridges = []
    for name, spec in links_cfg.items():
        bridge = spec.get("bridge")
        if not bridge:
            continue
        binfo = BRIDGE_INFO[bridge]
        bridges.append({"id": bridge, "label": binfo["label"], "kind": "switch", "tier": "l2", "pos": binfo["pos"], "link": name,
                        "cidr": spec["cidr"], "zone": binfo["zone"], "description": binfo["purpose"],
                        "vrrp": spec.get("vrrp"), "network": spec["network_name"], "members": addresses.get(name, [])})

    links = []
    for name, spec in links_cfg.items():
        members = addresses.get(name, [])
        purpose, zone = LINK_INFO[name]
        base = {"link": name, "network": spec["network_name"], "cidr": spec["cidr"], "kind": spec["kind"], "purpose": purpose,
                "zone": zone, "vrrp": spec.get("vrrp")}
        if spec.get("bridge"):
            for m in members:
                links.append({**base, "id": f"{name}:{m['node']}", "a": {"node": m["node"], "iface": m["interface"], "ip": m["ip"]},
                              "b": {"node": spec["bridge"], "iface": None, "ip": None}})
        elif len(members) == 2:
            a, b = members
            links.append({**base, "id": name, "a": {"node": a["node"], "iface": a["interface"], "ip": a["ip"]},
                          "b": {"node": b["node"], "iface": b["interface"], "ip": b["ip"]}})
    # fill peers
    for node in nodes:
        for att in node["attachments"]:
            peers = [m for m in addresses[att["link"]] if m["node"] != node["id"]]
            att["peers"] = peers

    docker_nodes = []
    for svc in compose["services"]:
        ip = next((n["ip"] for n in svc["networks"] if n.get("ip")), None)
        entry = {"id": svc["name"], "label": svc["name"], "kind": "service", "tier": "docker", "ip": ip, **svc,
                 "pos": DC_ATTACHED.get(svc["name"])}
        docker_nodes.append(entry)
    for svc in docker_nodes:
        lab = DMZ_LAB.get(svc["id"])
        if lab:
            svc["pos"], svc["ip"], svc["shares_netns_with"] = lab["pos"], DMZ_WEB_IP, "dmz-web"
            links.append({"id": f"netns:{svc['id']}", "link": "dmz", "network": "cxyz-fwdmz-dmzweb", "cidr": f"shares dmz-web's netns · {DMZ_WEB_IP}",
                          "kind": "netns", "purpose": "Compose service joined to the dmz-web network namespace (profile dmzlab)", "zone": "dmz", "vrrp": None,
                          "a": {"node": svc["id"], "iface": lab["ports"], "ip": DMZ_WEB_IP}, "b": {"node": "dmz-web", "iface": None, "ip": None}})
    for svc in docker_nodes:
        if svc["pos"] and not svc.get("shares_netns_with"):
            for net in svc["networks"]:
                if net["name"] == "cxyz_dc" and net["ip"]:
                    links.append({"id": f"dc:{svc['id']}", "link": "dc", "network": "cxyz-dc", "cidr": "172.16.50.0/24", "kind": "lan",
                                  "purpose": "Docker service on the DC bridge", "zone": "dc", "vrrp": None,
                                  "a": {"node": svc["id"], "iface": "eth0", "ip": net["ip"]}, "b": {"node": "br-cxyz-dc", "iface": None, "ip": None}})
    dc_members = addresses.get("dc", []) + [{"node": s["id"], "interface": "eth0", "ip": s["ip"]} for s in docker_nodes if s["pos"]]
    for b in bridges:
        if b["id"] == "br-cxyz-dc":
            b["members"] = dc_members
            b["members"].append({"node": "docker host gateway", "interface": "br-cxyz-dc", "ip": "172.16.50.253"})

    ipplan = _ipplan(intent, nodes, bridges, docker_nodes)
    ports = _ports(nodes, docker_nodes, firewalls)
    return {
        "meta": {"name": intent["name"], "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "git": _git(),
                 "sources": ["intent/fabric.yaml", "clab/companyxyz.clab.yml", "clab/configs/*", "docker-compose.yml",
                             "response/policies/default.yaml", "compliance/controls.yaml"],
                 "paths": {"A": "containerlab + FRR/nftables + Docker Compose", "B": "Terraform/libvirt + VyOS VMs + Docker Compose",
                           "C": "Kubernetes security plane over the Path A/B fabric"}},
        "topology": {"nodes": nodes, "bridges": bridges, "links": links, "docker": docker_nodes,
                     "management": {"network": intent["management"]["network"], "subnet": intent["management"]["subnet"],
                                    "gateway": intent["management"]["gateway"]}},
        "ipplan": ipplan, "routing": routing, "firewalls": firewalls, "ports": ports,
        "soc": {"flows": SOC_FLOWS, "layout": SOC_LAYOUT, "notes": {k: list(v) for k, v in SOC_NODE_NOTES.items()},
                "indices": [{"pattern": k, "purpose": v} for k, v in ES_INDEX_FAMILIES.items()],
                "docker_networks": compose["networks"], "model": _model_registry(), "policy": _policy()},
        "identity": _identity(), "controls": _controls(), "docker": compose,
        "access": _access(), "commands": _commands(), "limits": _limits(),
        "validation": _validation(intent, nodes, bridges),
    }


def _ipplan(intent: dict[str, Any], nodes: list[dict[str, Any]], bridges: list[dict[str, Any]], docker_nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name, spec in intent["links"].items():
        purpose, zone = LINK_INFO[name]
        members = []
        for node in nodes:
            for att in node["attachments"]:
                if att["link"] == name:
                    members.append({"who": node["id"], "interface": att["interface"], "ip": att["ip"]})
        if name == "dmz":
            members += [{"who": f"{s['id']} (shares dmz-web)", "interface": "eth1 (shared netns)", "ip": s["ip"]} for s in docker_nodes
                        if s.get("shares_netns_with")]
        if name == "dc":
            members += [{"who": s["id"], "interface": "eth0", "ip": s["ip"]} for s in docker_nodes
                        if s["pos"] and s["ip"] and not s.get("shares_netns_with")]
            members.append({"who": "docker host gateway", "interface": "br-cxyz-dc", "ip": "172.16.50.253"})
        vrrp = spec.get("vrrp")
        rows.append({"cidr": spec["cidr"], "name": spec["network_name"], "kind": spec["kind"], "zone": zone, "purpose": purpose,
                     "gateway": strip_mask(vrrp["virtual_ip"]) if vrrp else None, "vrrp": vrrp, "members": members})
    mgmt = intent["management"]
    rows.append({"cidr": mgmt["subnet"], "name": mgmt["network"], "kind": "oob", "zone": "management",
                 "purpose": "Out-of-band management (containerlab bridge). Protected from automatic containment; never routed from the data plane.",
                 "gateway": mgmt["gateway"], "vrrp": None,
                 "members": [{"who": n["id"], "interface": "eth0", "ip": n["mgmt_ip"]} for n in nodes]})
    rows.append({"cidr": "10.13.13.0/24", "name": "wireguard peers", "kind": "vpn", "zone": "vpn",
                 "purpose": "WireGuard tunnel addresses for remote administrators", "gateway": None, "vrrp": None, "members": []})
    rows.append({"cidr": "10.255.0.0/16", "name": "infrastructure aggregate", "kind": "summary", "zone": "infra",
                 "purpose": "Covers every routed transit /30 and /31", "gateway": None, "vrrp": None, "members": []})
    rows.append({"cidr": "195.1.1.0/24", "name": "public aggregate (BGP)", "kind": "summary", "zone": "public",
                 "purpose": "The only prefix originated to the ISPs (route-map ONLY-OURS)", "gateway": None, "vrrp": None, "members": []})
    return rows


def _ports(nodes: list[dict[str, Any]], docker_nodes: list[dict[str, Any]], firewalls: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for node in nodes:
        for item in node["listens"]:
            rows.append({"where": node["id"], "ip": node["mgmt_ip"] if item["port"] in {"22", "9443"} else None, "port": item["port"],
                         "proto": item["proto"], "service": item["name"], "who": item["who"], "exposure": "lab network"})
    for svc in docker_nodes:
        published = {p["container"]: p for p in svc["ports"]}
        for item in svc["listens"]:
            pub = published.get(item["port"])
            exposure = (f"host {pub['host']}:{pub['published']}/{pub['proto']}" if pub else
                        f"via {svc['shares_netns_with']} {svc['ip']} through fw-dmz" if svc.get("shares_netns_with") else "container network only")
            rows.append({"where": svc["id"], "ip": svc["ip"], "port": item["port"], "proto": item["proto"], "service": item["name"],
                         "who": item["who"], "exposure": exposure})
    return rows


def _access() -> list[dict[str, Any]]:
    return [
        {"name": "Kibana (SOC dashboards)", "url": "https://127.0.0.1:5602", "who": "analyst", "auth": "Elastic user; password = ELASTIC_PASSWORD in .env",
         "note": "trust soc/certs/ca.crt; never copy ca.key anywhere"},
        {"name": "Wazuh dashboard", "url": "https://127.0.0.1:5601", "who": "analyst", "auth": "WAZUH_DASHBOARD_PASSWORD in .env"},
        {"name": "ZTNA protected app", "url": "https://app.companyxyz.lab (via Traefik 443)", "who": "users", "auth": "Authentik SSO redirect"},
        {"name": "WireGuard", "url": "udp/51820 on the host", "who": "remote admins", "auth": "peer keys in wireguard/config (ignored by Git)"},
        {"name": "Network explorer (this page)", "url": "http://127.0.0.1:8088", "who": "operator", "auth": "none - loopback only, read-only"},
        {"name": "Lab node shell", "url": "docker exec -it clab-companyxyz-<node> sh", "who": "operator", "auth": "docker group / sudo"},
    ]


def _commands() -> list[dict[str, Any]]:
    return [
        {"group": "Bring-up", "items": [("make secrets", "generate .env, RADIUS hashes, WireGuard keys and the SOC PKI"),
                                        ("make up", "fabric + security plane (Path A)"), ("make configure", "Ansible hardening roles"),
                                        ("make soc-up && make soc-smoke", "SOC analytics plane + ingestion proof"),
                                        ("make soc-ai-up", "AI + response services (observe mode)")]},
        {"group": "Inspect", "items": [("containerlab inspect -t clab/companyxyz.clab.yml", "node names, mgmt IPs, state"),
                                       ("docker compose --profile soc --profile soc-ai ps", "Compose services"),
                                       ("make soc-status", "per-stream document counts"), ("make soc-ai-status", "AI/response service state"),
                                       ("make urls", "service URLs")]},
        {"group": "Packet-level", "items": [("docker exec clab-companyxyz-fw-core nft list ruleset", "live firewall ruleset"),
                                            ("docker exec clab-companyxyz-fw-core nft list set inet cxyz soc_blocklist", "active containment on fw-core"),
                                            ("docker exec clab-companyxyz-fw-dmz nft list set inet dmz soc_blocklist", "active containment on fw-dmz"),
                                            ("docker exec clab-companyxyz-edge vtysh -c 'show ip bgp summary'", "BGP sessions"),
                                            ("docker exec clab-companyxyz-core vtysh -c 'show ip ospf neighbor'", "OSPF adjacencies"),
                                            ("docker exec clab-companyxyz-dist1 vtysh -c 'show vrrp'", "VRRP state")]},
        {"group": "Test", "items": [("make soc-ai-contracts", "offline gates"), ("make validate", "live segmentation/hardening checks"),
                                    ("make attack", "attack-chain replay"), ("make soc-ai-validate", "live SOC/AI/response verifiers"),
                                    ("make report", "strict compliance report")]},
        {"group": "Tear-down", "items": [("make soc-ai-down && make soc-down", "stop SOC services (volumes kept)"), ("make down", "everything")]},
    ]


def _limits() -> list[str]:
    return [
        "Everything here is verified offline only; live controls stay UNVERIFIED until the lab validation targets have run.",
        "No model is trained on real telemetry; a demo model (scripts/demo_registry.py) uses synthetic data and proves wiring only.",
        "Network-fidelity gate (OPNsense HA/CARP, Core SPAN, VLAN 30/40/50/99) is not implemented; RESP-04 stays planned.",
        "VyOS has no per-element timeout: Path B expiry rests on the orchestrator's TTL sweep; a reboot clears containment.",
        "Path C cannot isolate endpoints until the Wazuh API certificate carries the in-cluster name.",
        "The FRR image is single-platform linux/amd64: Path A runs only on an x86-64 Linux host.",
    ]


def _validation(intent: dict[str, Any], nodes: list[dict[str, Any]], bridges: list[dict[str, Any]]) -> dict[str, Any]:
    """Self-checks that the derived model is internally consistent (surfaced in the UI)."""

    problems: list[str] = []
    mgmt = ipaddress.ip_network(intent["management"]["subnet"])
    for node in nodes:
        if ipaddress.ip_address(node["mgmt_ip"]) not in mgmt:
            problems.append(f"{node['id']}: mgmt IP outside {mgmt}")
        for att in node["attachments"]:
            if ipaddress.ip_address(att["ip"]) not in ipaddress.ip_network(att["cidr"], strict=False):
                problems.append(f"{node['id']}:{att['interface']} {att['ip']} outside {att['cidr']}")
            if att["interface"] == "?":
                problems.append(f"{node['id']}: no interface mapped for link {att['link']}")
    seen: dict[str, str] = {}
    for node in nodes:
        for ip in [node["mgmt_ip"]] + [a["ip"] for a in node["attachments"]]:
            owner = seen.setdefault(ip, node["id"])
            if owner != node["id"]:
                problems.append(f"duplicate IP {ip}: {owner} and {node['id']}")
    return {"ok": not problems, "problems": problems}


# ------------------------------------------------------------------------------ live probes
def _parse_labels(text: str) -> dict[str, str]:
    result = {}
    for part in text.split(","):
        key, sep, value = part.partition("=")
        if sep:
            result[key] = value
    return result


def live_status() -> dict[str, Any]:
    """Container state, firewall containment sets and index counts. Every probe fails soft."""

    live: dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "docker": {"ok": False}, "nodes": {},
                            "services": {}, "networks": [], "blocklists": {}, "indices": {}, "errors": []}
    rc, out = sh(["docker", "ps", "-a", "--format", "{{json .}}"], 6)
    if rc != 0:
        live["errors"].append(f"docker: {out.strip().splitlines()[0] if out.strip() else 'unavailable'}")
        return live
    live["docker"] = {"ok": True}
    services: dict[str, dict[str, Any]] = {}
    for line in out.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        labels = _parse_labels(row.get("Labels", ""))
        status = row.get("Status", "")
        state = {"state": row.get("State", ""), "status": status, "health": "healthy" if "(healthy)" in status else "unhealthy" if "(unhealthy)" in status else None,
                 "image": row.get("Image", "").split("@")[0], "name": row.get("Names", "")}
        if row.get("Names", "").startswith(CLAB_PREFIX):
            live["nodes"][row["Names"][len(CLAB_PREFIX):]] = state
        service = labels.get("com.docker.compose.service")
        if service:
            services[service] = state
    live["services"] = services
    rc, out = sh(["docker", "network", "ls", "--format", "{{.Name}}"], 5)
    names = [n for n in out.split() if "cxyz" in n] if rc == 0 else []
    if names:
        rc, out = sh(["docker", "network", "inspect", *names], 6)
        if rc == 0:
            try:
                for net in json.loads(out):
                    live["networks"].append({"name": net["Name"], "internal": net.get("Internal", False),
                                             "subnets": [c.get("Subnet") for c in (net.get("IPAM") or {}).get("Config") or []],
                                             "containers": {v["Name"]: v.get("IPv4Address") for v in (net.get("Containers") or {}).values()}})
            except (ValueError, KeyError):
                live["errors"].append("docker network inspect: unparsable")
    for firewall, table in FIREWALL_TABLES.items():
        if firewall not in live["nodes"] or live["nodes"][firewall]["state"] != "running":
            continue
        rc, out = sh(["docker", "exec", CLAB_PREFIX + firewall, "nft", "-j", "list", "set", "inet", table, "soc_blocklist"], 5)
        if rc != 0:
            live["blocklists"][firewall] = {"error": out.strip()[:160]}
            continue
        elements = []
        try:
            for item in json.loads(out).get("nftables", []):
                for element in (item.get("set") or {}).get("elem", []) or []:
                    if isinstance(element, dict) and "elem" in element:
                        elements.append({"ip": element["elem"].get("val"), "expires": element["elem"].get("expires")})
                    else:
                        elements.append({"ip": element, "expires": None})
        except ValueError:
            pass
        live["blocklists"][firewall] = {"elements": elements}
    es = services.get("elasticsearch")
    if es and es["state"] == "running":
        rc, out = sh(["docker", "exec", es["name"], "bash", "-ec",
                      'curl -s --max-time 4 --cacert config/certs/ca.crt --user "elastic:${ELASTIC_PASSWORD}" '
                      '"https://localhost:9200/_cat/indices/soc-*?h=index,docs.count&format=json"'], 8)
        if rc == 0:
            try:
                for row in json.loads(out):
                    family = re.sub(r"\d{4}\.\d{2}\.\d{2}$", "*", row["index"])
                    live["indices"][family] = live["indices"].get(family, 0) + int(row.get("docs.count") or 0)
            except (ValueError, KeyError):
                live["errors"].append("elasticsearch: indices unparsable")
        else:
            live["errors"].append("elasticsearch: " + out.strip()[:120])
    return live


# ------------------------------------------------------------------------------ server
class Cache:
    def __init__(self, ttl: float, build: Callable[[], Any]) -> None:
        self.ttl, self.build, self._value, self._at, self._lock = ttl, build, None, 0.0, threading.Lock()

    def get(self, fresh: bool = False) -> Any:
        with self._lock:
            if fresh or self._value is None or time.monotonic() - self._at > self.ttl:
                self._value, self._at = self.build(), time.monotonic()
            return self._value


def make_handler(allowed_hosts: set[str] | None, model: Cache, live: Cache) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "netviz"

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet
            return

        def _send(self, status: int, body: bytes, kind: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                                                        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            if allowed_hosts is not None and self.headers.get("Host", "").rsplit(":", 1)[0].strip("[]") not in allowed_hosts:
                self._send(403, b"forbidden host", "text/plain")        # blocks DNS-rebinding to the loopback listener
                return
            parts = urlsplit(self.path)
            try:
                if parts.path in {"/", "/index.html"}:
                    self._send(200, UI.read_bytes(), "text/html; charset=utf-8")
                elif parts.path == "/api/model":
                    self._send(200, json.dumps(model.get(fresh="refresh=1" in parts.query)).encode(), "application/json")
                elif parts.path == "/api/live":
                    self._send(200, json.dumps(live.get()).encode(), "application/json")
                elif parts.path == "/healthz":
                    self._send(200, b"ok", "text/plain")
                else:
                    self._send(404, b"not found", "text/plain")
            except Exception as exc:  # never leak a traceback to the browser
                self._send(500, json.dumps({"error": type(exc).__name__}).encode(), "application/json")

        def do_POST(self) -> None:  # noqa: N802
            self._send(405, b"read-only", "text/plain")

        do_PUT = do_DELETE = do_PATCH = do_POST

    return Handler


def serve(host: str, port: int) -> int:
    loopback = host in {"127.0.0.1", "localhost", "::1"}
    allowed = {"127.0.0.1", "localhost", "::1"} if loopback else None
    model, live = Cache(5.0, build_model), Cache(3.0, live_status)
    model.get()                                                     # fail fast on a broken source file
    server = ThreadingHTTPServer((host, port), make_handler(allowed, model, live))
    shown = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    print(f"network explorer: http://{shown}:{port}   (read-only; Ctrl-C to stop)", flush=True)
    if not loopback:
        print("WARNING: bound to a non-loopback address with no authentication; prefer an SSH tunnel.", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default=os.environ.get("NETVIZ_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("NETVIZ_PORT", "8088")))
    parser.add_argument("--print-model", action="store_true", help="print the derived model as JSON and exit")
    parser.add_argument("--check", action="store_true", help="build the model, report inconsistencies, exit non-zero on any")
    args = parser.parse_args(argv)
    if args.print_model:
        print(json.dumps(build_model(), indent=2))
        return 0
    if args.check:
        result = build_model()["validation"]
        print("OK: derived network model is consistent" if result["ok"] else "INCONSISTENT:\n  " + "\n  ".join(result["problems"]))
        return 0 if result["ok"] else 1
    return serve(args.host, args.port)


if __name__ == "__main__":
    raise SystemExit(main())
