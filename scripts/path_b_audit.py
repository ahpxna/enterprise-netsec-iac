#!/usr/bin/env python3
"""Live, fail-closed semantic audit for Path B (Terraform/libvirt + VyOS).

Unlike tests/validation, this runner never uses containerlab node exec.  It
connects to the real VM management plane with strict SSH host-key validation,
probes the real data plane from the Linux/VyOS guests, exercises a VRRP master
failure through libvirt, and emits one evidence artifact per Path B control.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shlex
import subprocess
import time
import uuid
from datetime import datetime, timezone
from typing import Callable

import yaml

from compliance.provenance import current_provenance
from env_exec import parse_dotenv

ROOT = pathlib.Path(__file__).resolve().parent.parent
INTENT = yaml.safe_load((ROOT / "intent" / "fabric.yaml").read_text())
NODES = INTENT["nodes"]
KNOWN_HOSTS = ROOT / "ansible" / "inventory" / "known_hosts"
EVIDENCE_DIR = ROOT / os.environ.get("EVIDENCE_DIR", "evidence/runs/path-b-adhoc")
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
ENV = parse_dotenv(ROOT / ".env") if (ROOT / ".env").exists() else {}
SSH_BASE = [
    "ssh",
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
    "-o", "ConnectTimeout=7",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run(argv: list[str], *, timeout: int = 30, check: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed rc={result.returncode}: {result.stderr.strip()[:300]}")
    return result


def mgmt_ip(node: str) -> str:
    return str(NODES[node]["mgmt_ip"])


def ssh_argv(node: str, user: str, command: str) -> list[str]:
    return [*SSH_BASE, f"{user}@{mgmt_ip(node)}", command]


def linux(node: str, command: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return run(ssh_argv(node, "ansible", f"bash -lc {shlex.quote(command)}"), timeout=timeout)


def vyos(node: str, command: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    # VyOS operational commands require vbash aliases/functions.
    remote = f"/bin/vbash -ic {shlex.quote(command)}"
    return run(ssh_argv(node, "vyos", remote), timeout=timeout)


def vyos_shell(node: str, command: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    remote = f"bash -lc {shlex.quote(command)}"
    return run(ssh_argv(node, "vyos", remote), timeout=timeout)


def compose_exec(service: str, command: str, *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return run(["docker", "compose", "exec", "-T", service, "sh", "-c", command], timeout=timeout)


def tcp_from_linux(node: str, address: str, port: int) -> bool:
    return linux(node, f"nc -z -w 3 {shlex.quote(address)} {port}", timeout=8).returncode == 0


def require_secret(name: str, minimum: int = 24) -> str:
    value = os.environ.get(name) or ENV.get(name, "")
    if len(value) < minimum or value.startswith("CHANGE_ME"):
        raise RuntimeError(f"{name} is missing or weak; run make secrets")
    return value


def config(node: str) -> str:
    result = vyos(node, "show configuration commands", timeout=20)
    if result.returncode != 0:
        raise RuntimeError(f"{node}: cannot read running VyOS configuration: {result.stderr.strip()}")
    return result.stdout


def normalized_config(text: str) -> str:
    """Normalize VyOS show-configuration quoting without weakening token checks."""
    return re.sub(r"[\"']", "", text)


def wazuh_rule_count(rule_id: int) -> int:
    result = compose_exec(
        "wazuh.manager",
        f"grep -Ec '\"id\"[[:space:]]*:[[:space:]]*\"{rule_id}\"' /var/ossec/logs/alerts/alerts.json 2>/dev/null || true",
    )
    text = result.stdout.strip().splitlines()
    return int(text[-1]) if text and text[-1].isdigit() else 0


def wait_for_count(rule_id: int, before: int, seconds: int = 25) -> int:
    deadline = time.monotonic() + seconds
    current = before
    while time.monotonic() < deadline:
        current = wazuh_rule_count(rule_id)
        if current > before:
            return current
        time.sleep(1)
    return current


def _safe_name(test_id: str) -> str:
    return test_id.replace("/", "__").replace("::", "__")


def emit(control: str, test_id: str, result: str, assertion: str, observed: dict, started: str, failure: str | None = None) -> None:
    payload = {
        "schema_version": 1,
        "control_id": control,
        "test_id": test_id,
        "result": result,
        "assertion": assertion,
        "observed": observed,
        "failure": failure,
        "started_at": started,
        "ended_at": utc_now(),
        "run_id": os.environ.get("EVIDENCE_RUN_ID", EVIDENCE_DIR.name),
        **current_provenance(),
        "environment": "path-b",
    }
    (EVIDENCE_DIR / f"{_safe_name(test_id)}.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def execute(control: str, function: Callable[[], tuple[str, dict]]) -> bool:
    started = utc_now()
    test_id = f"path_b_audit.py::{function.__name__}"
    try:
        assertion, observed = function()
        emit(control, test_id, "PASS", assertion, observed, started)
        print(f"PASS {control}: {assertion}")
        return True
    except AssertionError as exc:
        emit(control, test_id, "FAIL", str(exc), {}, started, str(exc))
        print(f"FAIL {control}: {exc}")
        return False
    except Exception as exc:  # fail closed: infrastructure/tool errors are not policy failures
        emit(control, test_id, "ERROR", "Path B audit step completed without an executable result", {}, started, repr(exc))
        print(f"ERROR {control}: {exc}")
        return False


def test_seg01() -> tuple[str, dict]:
    listeners = linux("server1", "ss -H -lntup").stdout
    radius_ready = ":1812" in listeners
    dns_ready = ":53" in listeners
    ssh_ready = ":22" in listeners
    mgmt_ssh = tcp_from_linux("pc4", "172.16.50.1", 22)
    user_ssh = tcp_from_linux("pc1", "172.16.50.1", 22)

    pc4_secret = require_secret("RADIUS_SECRET_PC4")
    positive_cmd = (
        "printf '%s\\n' 'User-Name = cxyztest' 'User-Password = deliberately-invalid' | "
        f"radclient -r 1 -t 2 172.16.50.1 auth {shlex.quote(pc4_secret)}"
    )
    positive = linux("pc4", positive_cmd, timeout=8)
    radius_mgmt_response = "Access-Reject" in (positive.stdout + positive.stderr)

    pc1_secret = require_secret("RADIUS_SECRET_PC1_PROBE")
    blocked_cmd = (
        "printf '%s\\n' 'User-Name = cxyztest' 'User-Password = deliberately-invalid' | "
        f"radclient -r 1 -t 2 172.16.50.1 auth {shlex.quote(pc1_secret)}"
    )
    blocked = linux("pc1", blocked_cmd, timeout=8)
    radius_user_response = "Access-Accept" in (blocked.stdout + blocked.stderr) or "Access-Reject" in (blocked.stdout + blocked.stderr)

    dns = linux("pc1", "dig +time=2 +tries=1 @172.16.50.1 server1.companyxyz.lab A")
    dns_allowed = dns.returncode == 0 and "172.16.50.1" in dns.stdout
    observed = {
        "radius_listener": radius_ready,
        "dns_listener": dns_ready,
        "ssh_listener": ssh_ready,
        "management_ssh_positive": mgmt_ssh,
        "management_radius_positive": radius_mgmt_response,
        "user_dns_positive": dns_allowed,
        "user_ssh_reachable": user_ssh,
        "user_radius_received_response": radius_user_response,
    }
    assert radius_ready and dns_ready and ssh_ready, "SEG-01 DC service preconditions are not healthy"
    assert mgmt_ssh and radius_mgmt_response, "SEG-01 management positive controls failed"
    assert dns_allowed, "SEG-01 approved user DNS path failed"
    assert not user_ssh and not radius_user_response, "SEG-01 user VLAN reached prohibited SSH/RADIUS service"
    return "healthy DC services; user DNS allowed; user SSH/RADIUS denied on real VyOS fw-core", observed


def test_seg02() -> tuple[str, dict]:
    local_web = linux("dmz-web", "curl -fsS http://127.0.0.1/ >/dev/null")
    routed_web = tcp_from_linux("pc1", "195.1.1.161", 80)
    pivot_ssh = tcp_from_linux("dmz-web", "172.16.50.1", 22)
    observed = {
        "dmz_web_local_health": local_web.returncode == 0,
        "routed_http_positive": routed_web,
        "dmz_to_dc_ssh_reachable": pivot_ssh,
    }
    assert local_web.returncode == 0 and routed_web, "SEG-02 DMZ positive-control web path failed"
    assert not pivot_ssh, "SEG-02 DMZ host pivoted into the DC"
    return "real DMZ web service is reachable where allowed and cannot initiate a DC SSH pivot", observed


def test_det01() -> tuple[str, dict]:
    before = wazuh_rule_count(100204)
    probe = linux("pc1", "nmap -sT -Pn -p 22,23,80 172.16.50.1", timeout=20)
    after = wait_for_count(100204, before)
    observed = {"nmap_rc": probe.returncode, "wazuh_rule_100204_delta": after - before}
    assert after > before, "DET-01 denied Path B scan did not create a Wazuh Path B firewall alert"
    return "denied user-to-DC scan on VyOS is ingested and alerted by Wazuh", observed


def test_det02() -> tuple[str, dict]:
    required = (
        "set system syslog host 172.16.50.11 protocol tcp",
        "set system syslog host 172.16.50.11 port 6514",
        "set system syslog host 172.16.50.11 tls auth-mode name",
    )
    configured: dict[str, bool] = {}
    for node in ("edge", "core", "dist1", "dist2", "fw-core", "fw-dmz"):
        running = normalized_config(config(node))
        configured[node] = all(token in running for token in required) and "tls certificate" in running and "tls ca-certificate" in running

    marker = f"CXYZ-DET02-TLS-MARKER-{uuid.uuid4()}"
    submitted = vyos_shell("core", f"logger -p local0.notice -t cxyz-det02 {shlex.quote(marker)}")
    relay_seen = False
    alert_seen = False
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        relay_seen = compose_exec("syslog-relay", f"grep -Fq {shlex.quote(marker)} /var/log/cxyz/remote.log").returncode == 0
        alert_seen = compose_exec("wazuh.manager", f"grep -Fq {shlex.quote(marker)} /var/ossec/logs/alerts/alerts.json").returncode == 0
        if relay_seen and alert_seen:
            break
        time.sleep(1)
    observed = {
        "all_vyos_tls_configured": all(configured.values()),
        "configured_nodes": configured,
        "marker_submitted": submitted.returncode == 0,
        "relay_received": relay_seen,
        "wazuh_alert_received": alert_seen,
    }
    assert all(configured.values()), "DET-02 one or more VyOS nodes are not configured for authenticated TLS syslog"
    assert submitted.returncode == 0 and relay_seen and alert_seen, "DET-02 mTLS marker did not traverse relay into Wazuh"
    return "VyOS devices use mTLS syslog/6514 and a live marker reaches the relay and Wazuh", observed


def test_idm01() -> tuple[str, dict]:
    content = linux("server1", "cat /etc/freeradius/3.0/mods-config/files/authorize").stdout
    cleartext = "Cleartext-Password" in content
    crypts = re.findall(r"Crypt-Password\s*:=\s*\"(\$6\$[^\"]+)\"", content)
    observed = {"cleartext_attribute_present": cleartext, "sha512_crypt_verifier_count": len(crypts)}
    assert not cleartext and len(crypts) >= 2, "IDM-01 RADIUS credential store is not SHA-512-crypt-only"
    return "FreeRADIUS stores salted SHA-512-crypt verifiers and no cleartext password attribute", observed


def test_idm02() -> tuple[str, dict]:
    content = linux("server1", "cat /etc/freeradius/3.0/clients.conf").stdout
    secrets = re.findall(r"(?m)^\s*secret\s*=\s*(\S+)\s*$", content)
    weak = [value for value in secrets if len(value) < 24 or value.startswith("CHANGE_ME")]
    observed = {
        "client_secret_count": len(secrets),
        "weak_secret_count": len(weak),
        "all_unique": len(secrets) == len(set(secrets)),
    }
    assert len(secrets) >= 5 and not weak and len(secrets) == len(set(secrets)), "IDM-02 RADIUS client secrets are missing, weak, or reused"
    return "every configured RADIUS client has a unique non-placeholder secret of at least 24 characters", observed


def test_hrd01() -> tuple[str, dict]:
    linux_nodes: dict[str, bool] = {}
    for node in ("pc1", "pc4", "server1", "dmz-web"):
        out = linux(node, "sshd -T 2>/dev/null | grep -E '^(clientaliveinterval|clientalivecountmax) '").stdout
        interval = re.search(r"clientaliveinterval\s+(\d+)", out)
        count = re.search(r"clientalivecountmax\s+(\d+)", out)
        linux_nodes[node] = bool(interval and int(interval.group(1)) <= 300 and count and int(count.group(1)) == 0)
    vyos_nodes: dict[str, bool] = {}
    for node in ("edge", "core", "dist1", "dist2", "fw-core", "fw-dmz"):
        running = normalized_config(config(node))
        vyos_nodes[node] = "set system login timeout 300" in running and "set service ssh client-keepalive-interval 300" in running
    observed = {"linux_nodes": linux_nodes, "vyos_nodes": vyos_nodes}
    assert all(linux_nodes.values()) and all(vyos_nodes.values()), "HRD-01 idle/session timeout is missing on a Path B node"
    return "Linux and VyOS management sessions enforce a 300-second idle/session timeout", observed


def test_hrd02() -> tuple[str, dict]:
    linux_telnet: dict[str, bool] = {}
    for node in ("pc1", "pc4", "server1", "dmz-web"):
        probe = linux(node, "ss -H -ltn | grep -E ':23([[:space:]]|$)' || true")
        linux_telnet[node] = bool(probe.stdout.strip())
    vyos_telnet: dict[str, bool] = {}
    ssh_hardened: dict[str, bool] = {}
    for node in ("edge", "core", "dist1", "dist2", "fw-core", "fw-dmz"):
        running = normalized_config(config(node))
        vyos_telnet[node] = "set service telnet" in running
        ssh_hardened[node] = "set service ssh disable-password-authentication" in running and f"set service ssh listen-address {mgmt_ip(node)}" in running
    observed = {
        "linux_telnet_listeners": linux_telnet,
        "vyos_telnet_configured": vyos_telnet,
        "vyos_key_only_management_ssh": ssh_hardened,
    }
    assert not any(linux_telnet.values()) and not any(vyos_telnet.values()), "HRD-02 Telnet is enabled/listening on Path B"
    assert all(ssh_hardened.values()), "HRD-02 VyOS SSH is not key-only and management-bound"
    return "Telnet is disabled and VyOS exposes key-only SSH solely on the OOB management address", observed


def test_time01() -> tuple[str, dict]:
    cfg = linux("server1", "cat /etc/chrony/chrony.conf").stdout
    tracking = linux("server1", "chronyc tracking")
    sources = [line for line in cfg.splitlines() if line.strip().startswith("server ") and " nts" in line]
    observed = {"nts_source_count": len(sources), "chronyc_tracking_rc": tracking.returncode}
    assert len(sources) >= 2 and tracking.returncode == 0, "TIME-01 NTS configuration/runtime health is incomplete"
    return "server1 chrony uses at least two NTS upstreams and answers runtime tracking", observed


def test_rtr01() -> tuple[str, dict]:
    version = vyos("edge", "show version")
    edge_cfg = normalized_config(config("edge"))
    core_cfg = normalized_config(config("core"))
    dist1_cfg = normalized_config(config("dist1"))
    dist2_cfg = normalized_config(config("dist2"))
    summary = vyos("edge", "show ip bgp summary")
    neighbors = vyos("core", "show ip ospf neighbor")
    if summary.returncode != 0 or neighbors.returncode != 0:
        raise RuntimeError("unable to query live BGP/OSPF state")
    expected = {"198.10.10.1", "197.10.10.1"}
    established = {
        fields[0]
        for line in summary.stdout.splitlines()
        if (fields := line.split()) and fields[0] in expected and fields[-1].isdigit()
    }
    ospf_full = sum("Full" in line for line in neighbors.stdout.splitlines())
    bgp_auth = len(re.findall(r"^set protocols bgp neighbor \S+ password \S+", edge_cfg, re.MULTILINE)) >= 2
    gtsm = edge_cfg.count("ttl-security hops 1") >= 2
    ospf_auth = all("authentication md5" in cfg or "authentication md5 key-id" in cfg for cfg in (core_cfg, dist1_cfg, dist2_cfg))
    secrets = [require_secret(name) for name in ("BGP_ISP1_SECRET", "BGP_ISP2_SECRET", "OSPF_MD5_SECRET")]
    observed = {
        "vyos_1_4_runtime": version.returncode == 0 and "1.4." in version.stdout,
        "bgp_established": len(established),
        "ospf_full_neighbors": ospf_full,
        "bgp_password_present": bgp_auth,
        "bgp_gtsm_present": gtsm,
        "ospf_md5_present": ospf_auth,
        "routing_secrets_strong_unique": len(set(secrets)) == 3,
    }
    assert observed["vyos_1_4_runtime"], "RTR-01 running image is not the reviewed VyOS 1.4.x config target"
    assert len(established) == 2 and ospf_full >= 2, "RTR-01 live routing adjacencies are unhealthy"
    assert bgp_auth and gtsm and ospf_auth and len(set(secrets)) == 3, "RTR-01 routing authentication/GTSM is incomplete or uses reused material"
    return "VyOS 1.4.x has 2/2 BGP peers, OSPF Full adjacencies, MD5/password auth, and GTSM", observed


def _reply_timestamps(text: str) -> list[float]:
    values: list[float] = []
    for line in text.splitlines():
        match = re.match(r"\[([0-9.]+)\]", line)
        if match and "bytes from" in line:
            values.append(float(match.group(1)))
    return values


def test_ha01() -> tuple[str, dict]:
    d1 = vyos("dist1", "show vrrp")
    d2 = vyos("dist2", "show vrrp")
    if d1.returncode != 0 or d2.returncode != 0:
        raise RuntimeError("cannot query VyOS VRRP state")
    assert "MASTER" in d1.stdout.upper() and "BACKUP" in d2.stdout.upper(), "HA-01 expected DIST1 master / DIST2 backup precondition failed"

    ping_cmd = "ping -D -i 0.2 -c 45 192.168.10.254"
    proc = subprocess.Popen(
        ssh_argv("pc1", "ansible", f"bash -lc {shlex.quote(ping_cmd)}"),
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    uri = os.environ.get("LIBVIRT_URI", "qemu:///system")
    suspended = False
    try:
        time.sleep(1.2)
        result = run(["virsh", "-c", uri, "suspend", "cxyz-dist1"], timeout=10)
        if result.returncode != 0:
            raise RuntimeError(f"cannot suspend VRRP master: {result.stderr.strip()}")
        suspended = True
        time.sleep(3.0)
        result = run(["virsh", "-c", uri, "resume", "cxyz-dist1"], timeout=10)
        if result.returncode != 0:
            raise RuntimeError(f"cannot resume VRRP master: {result.stderr.strip()}")
        suspended = False
        output, _ = proc.communicate(timeout=15)
    finally:
        if suspended:
            run(["virsh", "-c", uri, "resume", "cxyz-dist1"], timeout=10)
        if proc.poll() is None:
            proc.kill()
            output, _ = proc.communicate(timeout=5)
    timestamps = _reply_timestamps(output)
    max_gap = max((b - a for a, b in zip(timestamps, timestamps[1:])), default=999.0)
    observed = {"reply_count": len(timestamps), "max_reply_gap_seconds": round(max_gap, 3)}
    assert len(timestamps) >= 20 and max_gap < 2.0, f"HA-01 measured VRRP failover gap is {max_gap:.3f}s"
    return "suspending the real DIST1 VyOS master preserves the VIP with a measured reply gap below 2 seconds", observed


def test_vpn01() -> tuple[str, dict]:
    ssh_ready = tcp_from_linux("pc4", "172.16.50.1", 22)
    wan = vyos_shell("isp1", "timeout 4 bash -c 'exec 3<>/dev/tcp/172.16.50.1/22'", timeout=8)
    wg = compose_exec("wireguard", "wg show interfaces")
    compose = (ROOT / "docker-compose.yml").read_text()
    forbidden_publish = any(token in compose for token in ('"55000:55000"', '"1515:1515"', '"1514:1514"', '"8081:8080"'))
    observed = {
        "dc_ssh_positive": ssh_ready,
        "wan_ssh_reachable": wan.returncode == 0,
        "wireguard_ready": wg.returncode == 0 and bool(wg.stdout.strip()),
        "forbidden_management_publish_present": forbidden_publish,
    }
    assert ssh_ready, "VPN-01 healthy DC SSH positive control failed"
    assert wan.returncode != 0, "VPN-01 routed ISP reached DC management SSH"
    assert observed["wireguard_ready"] and not forbidden_publish, "VPN-01 WireGuard is not ready or a management/backend port is host-published"
    return "WireGuard is operational while the routed ISP cannot reach DC SSH and no management/backend port is published", observed


def test_ztna01() -> tuple[str, dict]:
    domain = os.environ.get("ORG_DOMAIN") or ENV.get("ORG_DOMAIN", "companyxyz.lab")
    host = f"app.{domain}"
    response = run([
        "curl", "--silent", "--show-error", "--insecure",
        "--output", "/dev/null", "--dump-header", "-",
        "--resolve", f"{host}:443:127.0.0.1", f"https://{host}/",
    ], timeout=15)
    status = re.search(r"^HTTP/\S+\s+(\d{3})", response.stdout, re.MULTILINE)
    location = re.search(r"^location:\s*(.+)$", response.stdout, re.MULTILINE | re.IGNORECASE)
    code = int(status.group(1)) if status else None
    target = location.group(1).strip() if location else ""
    redirect = code in {301, 302, 303, 307, 308} and ("sso." in target or "/if/flow/" in target)
    bypass = run(["curl", "--silent", "--max-time", "3", "http://127.0.0.1:8081/"], timeout=5)
    observed = {
        "gateway_curl_rc": response.returncode,
        "status_code": code,
        "redirects_to_authentik": redirect,
        "direct_backend_8081_reachable": bypass.returncode == 0,
    }
    assert response.returncode == 0 and redirect, "ZTNA-01 unauthenticated app request was not redirected to Authentik"
    assert bypass.returncode != 0, "ZTNA-01 direct backend bypass remains reachable on host port 8081"
    return "unauthenticated traffic is redirected to Authentik and the former direct backend bypass is closed", observed


CONTROLS: list[tuple[str, Callable[[], tuple[str, dict]]]] = [
    ("RTR-01", test_rtr01),
    ("SEG-01", test_seg01),
    ("SEG-02", test_seg02),
    ("DET-01", test_det01),
    ("DET-02", test_det02),
    ("IDM-01", test_idm01),
    ("IDM-02", test_idm02),
    ("HRD-01", test_hrd01),
    ("HRD-02", test_hrd02),
    ("TIME-01", test_time01),
    ("HA-01", test_ha01),
    ("VPN-01", test_vpn01),
    ("ZTNA-01", test_ztna01),
]


def main() -> int:
    if not KNOWN_HOSTS.is_file() or not KNOWN_HOSTS.stat().st_size:
        raise SystemExit("missing verified ansible/inventory/known_hosts")
    failures = sum(not execute(control, function) for control, function in CONTROLS)
    print(f"Path B audit complete: {len(CONTROLS) - failures} PASS, {failures} non-PASS; evidence={EVIDENCE_DIR}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
