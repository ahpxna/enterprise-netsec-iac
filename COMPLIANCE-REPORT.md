# CompanyXYZ-NG — Compliance & Control Validation Report

_Evidence run: `none` · Git SHA: `unknown`._

> PASS requires a schema-valid artifact with an explicit `result: PASS`. File presence alone never grants PASS.

**Summary:** 0 passed · 0 failed · 0 error · 12 unverified (of 12 controls)

| Control | Framework | Severity | Verified by | Status | Evidence |
|---------|-----------|----------|-------------|--------|----------|
| SEG-01 | NIST-800-41r1, ISO-27002-8.22 | high | `test_segmentation.py::test_user_vlan_blocked_from_radius` | ⚪ UNVERIFIED | `none` |
| SEG-02 | NIST-800-41r1, ISO-27002-8.22 | high | `test_segmentation.py::test_dmz_cannot_pivot_internal` | ⚪ UNVERIFIED | `none` |
| DET-01 | NIST-800-92, NIST-800-53-AU-6, ISO-27002-8.15 | high | `attack_chain.sh::step2_scan_detected` | ⚪ UNVERIFIED | `none` |
| DET-02 | NIST-800-92, ISO-27002-8.15 | high | `test_hardening.py::test_syslog_transport_is_tls` | ⚪ UNVERIFIED | `none` |
| IDM-01 | NIST-800-63B, NIST-800-53r5-IA-5(1) | critical | `test_hardening.py::test_no_cleartext_radius_password` | ⚪ UNVERIFIED | `none` |
| IDM-02 | NIST-800-53r5-IA-5(1), NIST-800-53r5-SC-12 | high | `test_hardening.py::test_radius_shared_secret_strength` | ⚪ UNVERIFIED | `none` |
| HRD-01 | NIST-800-53r5-AC-12 | moderate | `test_hardening.py::test_ssh_idle_timeout` | ⚪ UNVERIFIED | `none` |
| HRD-02 | NIST-800-53r5-CM-7, NIST-800-53r5-SC-8 | moderate | `test_hardening.py::test_telnet_disabled` | ⚪ UNVERIFIED | `none` |
| TIME-01 | NIST-800-92, NIST-800-53r5-AU-8, NIST-800-53r5-SC-45, ISO-27002-8.17 | moderate | `test_hardening.py::test_ntp_authenticated` | ⚪ UNVERIFIED | `none` |
| RTR-01 | NIST-SP-800-189, NIST-800-53r5-SC-23 | high | `test_routing.py::test_ospf_md5_and_bgp_ttl` | ⚪ UNVERIFIED | `none` |
| HA-01 | NIST-800-53-CP-10 | moderate | `attack_chain.sh::step5_vrrp_failover` | ⚪ UNVERIFIED | `none` |
| VPN-01 | NIST-800-53-AC-17, ISO-27002-6.7 | high | `test_hardening.py::test_no_mgmt_exposed_to_internet` | ⚪ UNVERIFIED | `none` |
