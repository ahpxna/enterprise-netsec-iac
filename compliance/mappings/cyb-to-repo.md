# Control remediation map

This table maps each security finding to its implementation and executable
verification. It describes the repository as it exists; it does not attribute
authorship or rely on prose as evidence.

| Finding | Implemented by | Proven by |
|---|---|---|
| RADIUS credential stored cleartext | `radius_secure` (salted SHA-512-crypt verifier) | `test_no_cleartext_radius_password` |
| Weak or reused RADIUS client secret | `radius_secure` (unique per-client secrets) | `test_radius_shared_secret_strength` |
| Syslog plaintext over 514 | `syslog_tls` (rsyslog TLS/6514) | `test_syslog_transport_is_tls` |
| Missing firewall detection correlation | nftables counters and Wazuh rules | `attack_chain.sh::step2_scan_detected` |
| NTP authentication missing | `ntp_secure` (chrony NTS) | `test_ntp_authenticated` |
| Telnet exposed | `common_hardening` | `test_telnet_disabled` |
| Console/SSH timeout too long | `common_hardening` | `test_ssh_idle_timeout` |
| User-to-DC segmentation failure | `fw-core.nft` default-deny | `test_user_vlan_blocked_from_radius` and Batfish |
| DMZ inward pivot | `fw-dmz.nft` | `test_dmz_cannot_pivot_internal` |
| Routing-control authentication missing | FRR/VyOS routing configs | `test_ospf_md5_and_bgp_ttl` |
| Gateway failover unavailable | DIST1/DIST2 VRRP | `attack_chain.sh::step5_vrrp_failover` |

| Multi-source ingestion, normalization and loss accounting | `soc/logstash/pipelines`, `schemas/ecs` | `test_log01_multi_source_ingestion`, `test_log02_ecs_normalization_preserves_raw`, `test_log03_ingestion_failure_is_accounted` |
| AI inference, provenance, input contract, evaluation | `ai/`, `soc/workers` | `test_ai01_feature_to_inference_event` .. `test_ai04_five_detector_comparison_is_carried` |
| AI score alone must not contain | `response/decision.py` | `test_cor01_anomaly_alone_never_requests_containment` |
| Reversible, verified, audited containment | `response/` (orchestrator, transports, adapters) | `test_resp01_firewall_containment_is_applied_and_verified`, `test_resp03_safeguards_ttl_rate_limit_and_audit`; endpoint isolation on Path B only (`path_b_audit.py::test_resp02`) |
| Analyst dashboards, timing, audit chain | `soc/kibana`, `response/orchestrator/audit.py` | `test_soc01_dashboards_show_the_attack_trace`, `test_soc02_timing_is_derived_from_immutable_records`, `test_soc03_audit_chain_links_alert_to_rollback` |

The SOC rows are proven by `make soc-ai-validate` (Path A) and `make vm-audit` (Path B); both stay `UNVERIFIED`
until run. OPNsense HA failover (RESP-04) has no executable proof and remains a *planned* control.

Every result is derived from a test outcome and its machine-readable evidence,
not from the existence of a report or configuration file.
