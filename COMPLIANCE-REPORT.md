# CompanyXYZ-NG — Compliance & Control Validation Report

_Generated from `compliance/controls.yaml` against evidence run `none`._

> Every PASS below is backed by a machine-generated evidence file in `evidence/runs/`. Controls with no evidence are shown as UNVERIFIED — this project does not let a control be marked compliant on prose alone.

**Summary:** 0 passed · 0 failed · 12 unverified (of 12 controls)

| Control | Framework | Severity | Verified by | Status |
|---------|-----------|----------|-------------|--------|
| SEG-01 | NIST-800-41r1, ISO-27002-8.22 | high | `test_segmentation.py::test_user_vlan_blocked_from_radius` | ⚪ UNVERIFIED |
| SEG-02 | NIST-800-41r1, ISO-27002-8.22 | high | `test_segmentation.py::test_dmz_cannot_pivot_internal` | ⚪ UNVERIFIED |
| DET-01 | NIST-800-92, NIST-800-53-AU-6, ISO-27002-8.15 | high | `attack_chain.sh::step2_scan_detected` | ⚪ UNVERIFIED |
| DET-02 | NIST-800-92, ISO-27002-8.15 | high | `test_hardening.py::test_syslog_transport_is_tls` | ⚪ UNVERIFIED |
| IDM-01 | NIST-800-63B | critical | `test_hardening.py::test_no_cleartext_radius_password` | ⚪ UNVERIFIED |
| IDM-02 | NIST-800-63B, CIS-1.4 | high | `test_hardening.py::test_radius_shared_secret_strength` | ⚪ UNVERIFIED |
| HRD-01 | CIS-1.8 | moderate | `test_hardening.py::test_ssh_idle_timeout` | ⚪ UNVERIFIED |
| HRD-02 | CIS-1.6.2 | moderate | `test_hardening.py::test_telnet_disabled` | ⚪ UNVERIFIED |
| TIME-01 | NIST-800-92, CIS-1.9.1, ISO-27002-8.17 | moderate | `test_hardening.py::test_ntp_authenticated` | ⚪ UNVERIFIED |
| RTR-01 | NIST-800-81-2 | high | `test_routing.py::test_ospf_md5_and_bgp_ttl` | ⚪ UNVERIFIED |
| HA-01 | NIST-800-53-CP-10 | moderate | `attack_chain.sh::step5_vrrp_failover` | ⚪ UNVERIFIED |
| VPN-01 | NIST-800-53-AC-17, ISO-27002-6.7 | high | `test_hardening.py::test_no_mgmt_exposed_to_internet` | ⚪ UNVERIFIED |

## How to reproduce
```bash
make up        # build fabric + security services
make configure # push hardened config with Ansible
make audit     # batfish + live validation + attack chain + this report
```