"""
IDM/HRD/TIME/DET-02/VPN controls. These read the *rendered* live config or
service state from the running nodes/containers — not a static file we hope
matches reality.
"""
import re
import pytest
from conftest import in_node


def test_no_cleartext_radius_password(evidence):
    """IDM-01: the RADIUS users db must contain zero Cleartext-Password lines."""
    r = in_node("server1", "sh", "-c",
                "grep -ri 'Cleartext-Password' /etc/ 2>/dev/null || true")
    hits = [l for l in r.stdout.splitlines() if l.strip()]
    evidence(control="IDM-01", cleartext_hits=hits, expectation="empty")
    assert not hits, f"Cleartext credential found: {hits}"


def test_radius_shared_secret_strength(evidence):
    r = in_node("server1", "sh", "-c",
                "cat /etc/freeradius/3.0/clients.conf 2>/dev/null || true")
    secrets = re.findall(r'secret\s*=\s*(\S+)', r.stdout)
    weak = [s for s in secrets if len(s) < 24 or s in ("testing123", "cisco", "racisco")]
    evidence(control="IDM-02", secret_count=len(secrets), weak=weak)
    assert not weak, f"Weak RADIUS shared secret(s): {weak}"


def test_syslog_transport_is_tls(evidence):
    """DET-02: rsyslog forwards over TLS (omfwd StreamDriver gtls), not plain 514."""
    r = in_node("server1", "sh", "-c",
                "cat /etc/rsyslog.d/*.conf 2>/dev/null || true")
    tls = "gtls" in r.stdout or "StreamDriverMode=\"1\"" in r.stdout
    evidence(control="DET-02", tls_configured=tls)
    assert tls, "Syslog transport is not TLS — cleartext logs (CYB-240 finding)"


def test_ssh_idle_timeout(evidence):
    r = in_node("pc4", "sh", "-c",
                "grep -E 'ClientAliveInterval' /etc/ssh/sshd_config 2>/dev/null || true")
    m = re.search(r'ClientAliveInterval\s+(\d+)', r.stdout)
    val = int(m.group(1)) if m else 99999
    evidence(control="HRD-01", client_alive_interval=val, expectation="<=300")
    assert val <= 300, "SSH idle timeout > 5 min (CIS 1.8)"


def test_telnet_disabled(evidence):
    r = in_node("server1", "sh", "-c",
                "ss -tlnp 2>/dev/null | grep ':23 ' || true")
    evidence(control="HRD-02", telnet_listeners=r.stdout.strip())
    assert not r.stdout.strip(), "Telnet (23) is listening — must be disabled"


def test_ntp_authenticated(evidence):
    r = in_node("server1", "sh", "-c",
                "grep -E 'nts|key' /etc/chrony/chrony.conf 2>/dev/null || true")
    evidence(control="TIME-01", chrony_auth_lines=r.stdout.strip())
    assert r.stdout.strip(), "NTP not authenticated (NTS/keys) — time can be spoofed"


def test_no_mgmt_exposed_to_internet(evidence):
    """VPN-01: from the ISP vantage point, edge mgmt SSH must be unreachable."""
    from conftest import in_node as _n
    r = _n("isp1", "nc", "-z", "-w", "3", "10.1.1.10", "22")
    evidence(control="VPN-01", mgmt_ssh_from_internet=(r.returncode == 0),
             expectation="unreachable")
    assert r.returncode != 0, "Management SSH reachable from Internet vantage"
