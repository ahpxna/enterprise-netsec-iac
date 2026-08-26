"""Live identity, hardening, time, logging, and remote-access controls."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

from conftest import in_node
from tests.validation.node_sets import MANAGED_NODES

ROOT = Path(__file__).resolve().parents[2]


def _local_secret(name: str) -> str:
    if os.environ.get(name):
        return os.environ[name]
    env_file = ROOT / ".env"
    if not env_file.exists():
        return ""
    for raw in env_file.read_text().splitlines():
        key, separator, value = raw.partition("=")
        if separator and key == name:
            return value.strip().strip('"').strip("'")
    return ""


def test_no_cleartext_radius_password(evidence):
    result = in_node(
        "server1",
        "sh",
        "-c",
        "cat /etc/freeradius/3.0/mods-config/files/authorize 2>/dev/null",
    )
    hits = [line for line in result.stdout.splitlines() if "Cleartext-Password" in line]
    sha512_crypt = bool(re.search(r'Crypt-Password\s*:=\s*"\$6\$', result.stdout))
    secret = _local_secret("RADIUS_SECRET_PC4")
    password = _local_secret("RADIUS_TEST_PASSWORD")
    assert secret and password, "local RADIUS integration credentials are unavailable"
    accepted = in_node(
        "pc4", "sh", "-c",
        "printf '%%s\\n' 'User-Name = cxyztest' 'User-Password = %s' | "
        "radclient -x 172.16.50.1 auth '%s'" % (password, secret),
    )
    rejected = in_node(
        "pc4", "sh", "-c",
        "printf '%%s\\n' 'User-Name = cxyztest' 'User-Password = incorrect-password' | "
        "radclient -x 172.16.50.1 auth '%s'" % secret,
    )
    accept = "Access-Accept" in (accepted.stdout + accepted.stderr)
    reject = "Access-Reject" in (rejected.stdout + rejected.stderr)
    evidence(
        control="IDM-01",
        assertion="RADIUS stores only SHA-512-crypt verifier and accepts only the controlled credential",
        observed={
            "cleartext_hits": hits,
            "sha512_crypt_present": sha512_crypt,
            "access_accept": accept,
            "access_reject": reject,
        },
        enforcement_node="server1",
    )
    assert not hits, f"cleartext credential found: {hits}"
    assert sha512_crypt, "salted SHA-512-crypt RADIUS verifier is missing"
    assert accept and reject, "RADIUS credential verification did not enforce both outcomes"


def test_radius_shared_secret_strength(evidence):
    result = in_node("server1", "sh", "-c", "cat /etc/freeradius/3.0/clients.conf 2>/dev/null")
    secrets = re.findall(r"secret\s*=\s*(\S+)", result.stdout)
    weak = [secret for secret in secrets if len(secret) < 24 or secret.lower() in {"testing123", "cisco", "racisco"}]
    unique = len(secrets) == len(set(secrets))
    evidence(
        control="IDM-02",
        assertion="every RADIUS client has a unique non-dictionary secret of at least 24 characters",
        observed={"secret_count": len(secrets), "weak_count": len(weak), "all_unique": unique},
    )
    assert len(secrets) >= 4, "expected explicit secrets for all RADIUS clients"
    assert not weak, f"weak RADIUS secret(s): {weak}"
    assert unique, "RADIUS shared secret is reused across clients"


def test_syslog_transport_is_tls(evidence):
    result = in_node("server1", "sh", "-c", "cat /etc/rsyslog.d/*.conf 2>/dev/null")
    tls = all(token in result.stdout for token in ("gtls", 'port="6514"', 'StreamDriverMode="1"', 'StreamDriverAuthMode="x509/name"'))
    cleartext = 'port="514"' in result.stdout
    relay_cfg = subprocess.run(
        ["docker", "compose", "exec", "-T", "syslog-relay", "cat", "/etc/rsyslog.conf"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    relay_mutual_tls = (
        relay_cfg.returncode == 0
        and 'StreamDriver.AuthMode="x509/name"' in relay_cfg.stdout
        and "PermittedPeer" in relay_cfg.stdout
    )
    marker = f"CXYZ-DET02-TLS-MARKER-{uuid.uuid4()}"
    submitted = in_node("server1", "logger", "-p", "local0.notice", "-t", "cxyz-det02", marker)
    relay_received = False
    wazuh_alert_received = False
    for _ in range(10):
        relay = subprocess.run(
            ["docker", "compose", "exec", "-T", "syslog-relay", "grep", "-F", marker, "/var/log/cxyz/remote.log"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        alert = subprocess.run(
            ["docker", "compose", "exec", "-T", "wazuh.manager", "sh", "-c", f"grep -Fq '{marker}' /var/ossec/logs/alerts/alerts.json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        relay_received = relay.returncode == 0
        wazuh_alert_received = alert.returncode == 0
        if relay_received and wazuh_alert_received:
            break
        time.sleep(1)
    evidence(
        control="DET-02",
        assertion="unique marker traverses authenticated TLS syslog relay and creates a Wazuh alert",
        observed={
            "tls_configured": tls,
            "relay_mutual_tls": relay_mutual_tls,
            "cleartext_514": cleartext,
            "marker_submitted": submitted.returncode == 0,
            "relay_received": relay_received,
            "wazuh_alert_received": wazuh_alert_received,
        },
        enforcement_node="server1,syslog-relay,wazuh.manager",
    )
    assert tls and relay_mutual_tls and not cleartext, "device-to-relay logging is not mutually authenticated TLS-only"
    assert submitted.returncode == 0, "unable to submit DET-02 marker"
    assert relay_received and wazuh_alert_received, "TLS marker did not reach relay and Wazuh"


def test_ssh_idle_timeout(evidence):
    observed = {}
    for name in MANAGED_NODES:
        timeout_result = in_node(
            name, "sh", "-c",
            "cat /etc/profile.d/cxyz-timeout.sh 2>/dev/null || true",
        )
        tmout = re.search(r"TMOUT=(\d+)", timeout_result.stdout)
        sshd = in_node(name, "sh", "-c", "command -v sshd >/dev/null 2>&1")
        effective = {}
        if sshd.returncode == 0:
            config = in_node(name, "sshd", "-T")
            for raw in config.stdout.splitlines():
                fields = raw.split(None, 1)
                if len(fields) == 2:
                    effective[fields[0].lower()] = fields[1].strip().lower()
        observed[name] = {
            "shell_tmout": int(tmout.group(1)) if tmout else None,
            "sshd_installed": sshd.returncode == 0,
            "client_alive_interval": int(effective["clientaliveinterval"]) if effective.get("clientaliveinterval", "").isdigit() else None,
            "client_alive_count_max": int(effective["clientalivecountmax"]) if effective.get("clientalivecountmax", "").isdigit() else None,
            "permit_root_login": effective.get("permitrootlogin"),
        }

    evidence(
        control="HRD-01",
        assertion="interactive shell timeout is <=300s everywhere and effective sshd policy is hardened wherever SSH is installed",
        observed=observed,
    )
    assert all(item["shell_tmout"] is not None and item["shell_tmout"] <= 300 for item in observed.values())
    for name, item in observed.items():
        if not item["sshd_installed"]:
            continue
        assert item["client_alive_interval"] is not None and item["client_alive_interval"] <= 300, f"{name}: effective ClientAliveInterval is not hardened"
        assert item["client_alive_count_max"] == 0, f"{name}: effective ClientAliveCountMax must be 0"
        assert item["permit_root_login"] == "no", f"{name}: effective PermitRootLogin must be no"


def test_telnet_disabled(evidence):
    listeners = {}
    for name in MANAGED_NODES:
        result = in_node(name, "sh", "-c", "ss -H -tlnp 2>/dev/null | grep ':23 ' || true")
        listeners[name] = result.stdout.strip()
    evidence(control="HRD-02", assertion="no managed Path A node listens on Telnet/23", observed={"listeners": listeners})
    assert not any(listeners.values()), f"Telnet listener found: {listeners}"

def test_ntp_authenticated(evidence):
    result = subprocess.run(
        [sys.executable, "scripts/host_time_status.py", "--json"],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=20,
    )
    try:
        status = json.loads(result.stdout)
    except json.JSONDecodeError:
        status = {
            "ok": False,
            "observed": {"raw_stdout": result.stdout, "raw_stderr": result.stderr},
            "errors": ["host time verifier returned invalid JSON"],
        }
    evidence(
        control="TIME-01",
        assertion="the Linux host kernel clock inherited by Path A containers is synchronized to an authenticated NTS source within 1 second",
        observed={**status.get("observed", {}), "errors": status.get("errors", [])},
        enforcement_node="path-a-linux-host",
    )
    assert result.returncode == 0 and status.get("ok") is True, f"Path A host NTS verification failed: {status.get('errors')}"

def test_no_mgmt_exposed_to_internet(evidence):
    service = in_node("server1", "sh", "-c", "ss -H -tln | grep -E ':22([[:space:]]|$)'")
    before = in_node("fw-core", "nft", "list", "counter", "inet", "cxyz", "vpn01_wan_ssh_drop")
    before_match = re.search(r"packets\s+(\d+)", before.stdout)
    assert before.returncode == 0 and before_match, "VPN-01 firewall counter is unavailable"
    negative = in_node("isp1", "nc", "-z", "-w", "3", "172.16.50.1", "22")
    after = in_node("fw-core", "nft", "list", "counter", "inet", "cxyz", "vpn01_wan_ssh_drop")
    after_match = re.search(r"packets\s+(\d+)", after.stdout)
    assert after.returncode == 0 and after_match, "VPN-01 firewall counter cannot be read"
    wg_if = subprocess.run(
        ["docker", "compose", "exec", "-T", "wireguard", "wg", "show", "interfaces"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    wg_peers = subprocess.run(
        ["docker", "compose", "exec", "-T", "wireguard", "wg", "show", "all", "peers"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    wg_handshakes = subprocess.run(
        ["docker", "compose", "exec", "-T", "wireguard", "wg", "show", "all", "latest-handshakes"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    now = int(time.time())
    handshake_ages = []
    recent_handshake = False
    if wg_handshakes.returncode == 0:
        for line in wg_handshakes.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[-1].isdigit() and int(fields[-1]) > 0:
                age = now - int(fields[-1])
                handshake_ages.append(age)
                if 0 <= age <= 600:
                    recent_handshake = True
    peer_count = len([line for line in wg_peers.stdout.splitlines() if line.strip()]) if wg_peers.returncode == 0 else 0
    wg_ready = wg_if.returncode == 0 and bool(wg_if.stdout.strip())
    probe_route = subprocess.run(
        ["docker", "compose", "exec", "-T", "vpn-probe", "ip", "route", "get", "172.16.50.1"],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=10,
    )
    probe_admin = subprocess.run(
        ["docker", "compose", "exec", "-T", "vpn-probe", "bash", "-lc",
         "timeout 4 bash -lc 'exec 3<>/dev/tcp/172.16.50.1/22'"],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=10,
    )
    probe_tunnel_route = probe_route.returncode == 0 and "wg0" in probe_route.stdout
    probe_admin_reachable = probe_admin.returncode == 0
    compose_text = (ROOT / "docker-compose.yml").read_text()
    forbidden_publishes = [
        token for token in ("55000:55000", "1515:1515", "1514:1514", "6514:6514", "8081:8080")
        if token in compose_text
    ]
    counter_delta = int(after_match.group(1)) - int(before_match.group(1))
    evidence(
        control="VPN-01",
        assertion="a real WireGuard peer reaches the approved DC SSH target through wg0 while routed WAN is denied",
        observed={
            "ssh_service_healthy": service.returncode == 0,
            "wireguard_ready": wg_ready,
            "wireguard_peer_count": peer_count,
            "recent_wireguard_handshake": recent_handshake,
            "handshake_ages_seconds": handshake_ages,
            "vpn_probe_route": probe_route.stdout.strip(),
            "vpn_probe_route_uses_wg0": probe_tunnel_route,
            "vpn_probe_admin_ssh_reachable": probe_admin_reachable,
            "wan_ssh_reachable": negative.returncode == 0,
            "wan_deny_counter_delta": counter_delta,
            "forbidden_host_publishes": forbidden_publishes,
        },
        enforcement_node="fw-core",
        counter_before=int(before_match.group(1)),
        counter_after=int(after_match.group(1)),
    )
    assert service.returncode == 0, "DC SSH positive precondition failed"
    assert wg_ready and peer_count > 0, "WireGuard has no operational interface/configured peer"
    assert recent_handshake, "WireGuard requires at least one real peer handshake within the last 10 minutes"
    assert probe_tunnel_route and probe_admin_reachable, "WireGuard peer cannot route to and reach the approved DC SSH target"
    assert negative.returncode != 0 and counter_delta > 0, "WAN SSH was not denied by fw-core"
    assert not forbidden_publishes, f"management/backend ports are published on the host: {forbidden_publishes}"


def test_ztna_redirects_unauthenticated_request(evidence):
    """ZTNA-01: a browser without a session must be sent to Authentik."""
    domain = _local_secret("ORG_DOMAIN") or "companyxyz.lab"
    host = f"app.{domain}"
    response = subprocess.run(
        [
            "curl", "--silent", "--show-error",
            "--cacert", str(ROOT / "docker/zero-trust-gateway/certs/ca.crt"),
            "--output", "/dev/null", "--dump-header", "-",
            "--resolve", f"{host}:443:127.0.0.1", f"https://{host}/",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    status = re.search(r"^HTTP/\S+\s+(\d{3})", response.stdout, re.MULTILINE)
    location = re.search(r"^location:\s*(.+)$", response.stdout, re.MULTILINE | re.IGNORECASE)
    status_code = int(status.group(1)) if status else None
    redirect_target = location.group(1).strip() if location else ""
    is_redirect = status_code in {301, 302, 303, 307, 308}
    to_authentik = "sso." in redirect_target or "/if/flow/" in redirect_target
    direct = subprocess.run(
        ["curl", "--silent", "--max-time", "3", "http://127.0.0.1:8081/"],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=5,
    )
    direct_backend_reachable = direct.returncode == 0
    evidence(
        control="ZTNA-01",
        assertion="a CA-verified unauthenticated HTTPS request is redirected by declaratively bootstrapped Traefik/Authentik before reaching the ZTNA demo app",
        observed={
            "curl_returncode": response.returncode,
            "status_code": status_code,
            "redirect_target": redirect_target,
            "redirects_to_authentik": to_authentik,
            "tls_ca_verified": response.returncode == 0,
            "direct_backend_8081_reachable": direct_backend_reachable,
        },
        enforcement_node="traefik,authentik-server",
    )
    assert response.returncode == 0, f"ZTNA endpoint unavailable: {response.stderr}"
    assert is_redirect and to_authentik, "unauthenticated request was not redirected to Authentik"
    assert not direct_backend_reachable, "protected backend is still directly reachable on host port 8081"
