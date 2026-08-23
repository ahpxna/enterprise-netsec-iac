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

Every result is derived from a test outcome and its machine-readable evidence,
not from the existence of a report or configuration file.
