# [REDACTED:ORG_NAME]-NG — Compliance & Control Validation Report

_Profile: `path-a` · Evidence run: `20261018T025804Z` · Git SHA: `unknown`._

> PASS requires a schema-valid artifact with an explicit `result: PASS` from the selected deployment profile. Path A evidence can never substitute for Path B evidence.

**Summary:** 12 passed · 1 failed · 0 error · 13 unverified (of 26 controls applicable to this profile)

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
| ZTNA-01 | NIST-800-53r5-AC-3 | high | `test_hardening.py::test_ztna_redirects_unauthenticated_request` | ⚪ UNVERIFIED | `none` |
| LOG-01 | NIST-800-92, NIST-800-53r5-AU-3, ISO-27002-8.15 | high | `test_soc_ai.py::test_log01_multi_source_ingestion` | ✅ PASS | `tests/validation/test_soc_ai.py::test_log01_multi_source_ingestion` |
| LOG-02 | NIST-800-92, NIST-800-53r5-AU-9, ISO-27002-8.15 | high | `test_soc_ai.py::test_log02_ecs_normalization_preserves_raw` | ✅ PASS | `tests/validation/test_soc_ai.py::test_log02_ecs_normalization_preserves_raw` |
| LOG-03 | NIST-800-53r5-AU-5, NIST-800-92, ISO-27002-8.15 | high | `test_soc_ai.py::test_log03_ingestion_failure_is_accounted` | ✅ PASS | `tests/validation/test_soc_ai.py::test_log03_ingestion_failure_is_accounted` |
| AI-01 | NIST-AI-RMF-MEASURE, NIST-800-53r5-SI-4 | high | `test_soc_ai.py::test_ai01_feature_to_inference_event` | ❌ FAIL | `tests/validation/test_soc_ai.py::test_ai01_feature_to_inference_event` |
| AI-02 | NIST-AI-RMF-GOVERN, NIST-800-53r5-SA-10 | high | `test_soc_ai.py::test_ai02_model_provenance_is_bound_to_serving` | ✅ PASS | `tests/validation/test_soc_ai.py::test_ai02_model_provenance_is_bound_to_serving` |
| AI-03 | NIST-AI-RMF-MEASURE, NIST-800-53r5-SI-10 | moderate | `test_soc_ai.py::test_ai03_schema_mismatch_is_rejected` | ✅ PASS | `tests/validation/test_soc_ai.py::test_ai03_schema_mismatch_is_rejected` |
| AI-04 | NIST-AI-RMF-MEASURE | moderate | `test_soc_ai.py::test_ai04_five_detector_comparison_is_carried` | ✅ PASS | `tests/validation/test_soc_ai.py::test_ai04_five_detector_comparison_is_carried` |
| COR-01 | NIST-800-53r5-SI-4, NIST-AI-RMF-MANAGE | high | `test_soc_ai.py::test_cor01_anomaly_alone_never_requests_containment` | ✅ PASS | `tests/validation/test_soc_ai.py::test_cor01_anomaly_alone_never_requests_containment` |
| RESP-01 | NIST-800-53r5-IR-4, NIST-800-53r5-SC-7 | high | `test_soc_ai.py::test_resp01_firewall_containment_is_applied_and_verified` | ✅ PASS | `tests/validation/test_soc_ai.py::test_resp01_firewall_containment_is_applied_and_verified` |
| RESP-03 | NIST-800-53r5-IR-4, NIST-800-53r5-AU-9 | high | `test_soc_ai.py::test_resp03_safeguards_ttl_rate_limit_and_audit` | ✅ PASS | `tests/validation/test_soc_ai.py::test_resp03_safeguards_ttl_rate_limit_and_audit` |
| SOC-01 | NIST-800-53r5-AU-6, NIST-800-53r5-SI-4 | moderate | `test_soc_ai.py::test_soc01_dashboards_show_the_attack_trace` | ✅ PASS | `tests/validation/test_soc_ai.py::test_soc01_dashboards_show_the_attack_trace` |
| SOC-02 | NIST-800-53r5-IR-5 | moderate | `test_soc_ai.py::test_soc02_timing_is_derived_from_immutable_records` | ✅ PASS | `tests/validation/test_soc_ai.py::test_soc02_timing_is_derived_from_immutable_records` |
| SOC-03 | NIST-800-53r5-AU-10, NIST-800-53r5-AU-12 | high | `test_soc_ai.py::test_soc03_audit_chain_links_alert_to_rollback` | ✅ PASS | `tests/validation/test_soc_ai.py::test_soc03_audit_chain_links_alert_to_rollback` |

Not applicable to `path-a` (the path physically lacks the subject; verified on the other profile only): RESP-02
