"""Live identity, hardening, time, logging, and remote-access controls."""

from __future__ import annotations

import re
import subprocess
import os
import time
import uuid
from pathlib import Path

from conftest import in_node

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
    nodes = ("pc1", "pc4", "server1")
    observed = {}
    for name in nodes:
        result = in_node(name, "sh", "-c", "cat /etc/ssh/sshd_config.d/10-cxyz-hardening.conf /etc/profile.d/cxyz-timeout.sh 2>/dev/null")
        interval = re.search(r"ClientAliveInterval\s+(\d+)", result.stdout)
        tmout = re.search(r"TMOUT=(\d+)", result.stdout)
        observed[name] = {
            "client_alive_interval": int(interval.group(1)) if interval else None,
            "shell_tmout": int(tmout.group(1)) if tmout else None,
        }
    evidence(control="HRD-01", assertion="SSH and interactive shell idle limits are configured <=300s", observed=observed)
    assert all(item["client_alive_interval"] is not None and item["client_alive_interval"] <= 300 for item in observed.values())
    assert all(item["shell_tmout"] is not None and item["shell_tmout"] <= 300 for item in observed.values())


def test_telnet_disabled(evidence):
    nodes = ("edge", "core", "dist1", "dist2", "fw-core", "fw-dmz", "server1")
    listeners = {}
    for name in nodes:
        result = in_node(name, "sh", "-c", "ss -H -tlnp 2>/dev/null | grep ':23 ' || true")
        listeners[name] = result.stdout.strip()
    evidence(control="HRD-02", assertion="no managed node listens on Telnet/23", observed={"listeners": listeners})
    assert not any(listeners.values()), f"Telnet listener found: {listeners}"


def test_ntp_authenticated(evidence):
    config = in_node("server1", "sh", "-c", "cat /etc/chrony/chrony.conf 2>/dev/null")
    tracking = in_node("server1", "chronyc", "tracking")
    nts_sources = [line for line in config.stdout.splitlines() if line.strip().startswith("server ") and " nts" in line]
    evidence(control="TIME-01", assertion="chronyd runs with at least two NTS upstreams", observed={"nts_source_count": len(nts_sources), "chronyc_tracking_rc": tracking.returncode})
    assert len(nts_sources) >= 2, "fewer than two NTS sources configured"
    assert tracking.returncode == 0, "chronyd runtime health check failed"


def test_no_mgmt_exposed_to_internet(evidence):
    service = in_node("server1", "sh", "-c", "ss -H -tln | grep -E ':22([[:space:]]|$)'")
    before = in_node("fw-core", "nft", "list", "counter", "inet", "cxyz", "vpn01_wan_ssh_drop")
    before_match = re.search(r"packets\s+(\d+)", before.stdout)
    assert before.returncode == 0 and before_match, "VPN-01 firewall counter is unavailable"
    negative = in_node("isp1", "nc", "-z", "-w", "3", "172.16.50.1", "22")
    after = in_node("fw-core", "nft", "list", "counter", "inet", "cxyz", "vpn01_wan_ssh_drop")
    after_match = re.search(r"packets\s+(\d+)", after.stdout)
    assert after.returncode == 0 and after_match, "VPN-01 firewall counter cannot be read"
    positive = subprocess.run(
        ["docker", "compose", "exec", "-T", "wireguard", "wg", "show", "interfaces"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    wg_ready = positive.returncode == 0 and bool(positive.stdout.strip())
    compose_text = (ROOT / "docker-compose.yml").read_text()
    forbidden_publishes = [
        token for token in ("55000:55000", "1515:1515", "1514:1514", "6514:6514", "8081:8080")
        if token in compose_text
    ]
    counter_delta = int(after_match.group(1)) - int(before_match.group(1))
    evidence(
        control="VPN-01",
        assertion="WireGuard service is operational; routed WAN cannot reach the healthy DC SSH service",
        observed={
            "ssh_service_healthy": service.returncode == 0,
            "wireguard_ready": wg_ready,
            "wan_ssh_reachable": negative.returncode == 0,
            "wan_deny_counter_delta": counter_delta,
            "forbidden_host_publishes": forbidden_publishes,
        },
        enforcement_node="fw-core",
        counter_before=int(before_match.group(1)),
        counter_after=int(after_match.group(1)),
    )
    assert service.returncode == 0, "DC SSH positive precondition failed"
    assert wg_ready, "WireGuard positive control failed"
    assert negative.returncode != 0 and counter_delta > 0, "WAN SSH was not denied by fw-core"
    assert not forbidden_publishes, f"management/backend ports are published on the host: {forbidden_publishes}"


def test_ztna_redirects_unauthenticated_request(evidence):
    """ZTNA-01: a browser without a session must be sent to Authentik."""
    domain = _local_secret("ORG_DOMAIN") or "companyxyz.lab"
    host = f"app.{domain}"
    response = subprocess.run(
        [
            "curl", "--silent", "--show-error", "--insecure",
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
        assertion="unauthenticated HTTPS request is redirected by Traefik/Authentik before reaching the app",
        observed={
            "curl_returncode": response.returncode,
            "status_code": status_code,
            "redirect_target": redirect_target,
            "redirects_to_authentik": to_authentik,
            "direct_backend_8081_reachable": direct_backend_reachable,
        },
        enforcement_node="traefik,authentik-server",
    )
    assert response.returncode == 0, f"ZTNA endpoint unavailable: {response.stderr}"
    assert is_redirect and to_authentik, "unauthenticated request was not redirected to Authentik"
    assert not direct_backend_reachable, "protected backend is still directly reachable on host port 8081"
