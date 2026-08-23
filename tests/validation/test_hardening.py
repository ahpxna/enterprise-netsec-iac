"""Live identity, hardening, time, logging, and remote-access controls."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from conftest import in_node

ROOT = Path(__file__).resolve().parents[2]


def test_no_cleartext_radius_password(evidence):
    result = in_node(
        "server1",
        "sh",
        "-c",
        "cat /etc/freeradius/3.0/mods-config/files/authorize 2>/dev/null",
    )
    hits = [line for line in result.stdout.splitlines() if "Cleartext-Password" in line]
    sha512_crypt = bool(re.search(r'Crypt-Password\s*:=\s*"\$6\$', result.stdout))
    evidence(
        control="IDM-01",
        assertion="RADIUS user store uses SHA-512-crypt and contains no cleartext password attribute",
        observed={"cleartext_hits": hits, "sha512_crypt_present": sha512_crypt},
    )
    assert not hits, f"cleartext credential found: {hits}"
    assert sha512_crypt, "salted SHA-512-crypt RADIUS verifier is missing"


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
    tls = all(token in result.stdout for token in ("gtls", 'port="6514"', 'StreamDriverMode="1"'))
    cleartext = 'port="514"' in result.stdout
    evidence(control="DET-02", assertion="rsyslog forwards with authenticated TLS/6514 only", observed={"tls_configured": tls, "cleartext_514": cleartext})
    assert tls and not cleartext, "device-to-relay logging is not TLS-only"


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
    negative = in_node("isp1", "nc", "-z", "-w", "3", "10.1.1.10", "22")
    positive = subprocess.run(
        ["docker", "compose", "exec", "-T", "wireguard", "wg", "show", "interfaces"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    wg_ready = positive.returncode == 0 and bool(positive.stdout.strip())
    evidence(control="VPN-01", assertion="WireGuard is operational and Internet cannot reach management SSH", observed={"wireguard_ready": wg_ready, "internet_mgmt_ssh": negative.returncode == 0})
    assert wg_ready, "WireGuard positive control failed"
    assert negative.returncode != 0, "management SSH is reachable from Internet"
