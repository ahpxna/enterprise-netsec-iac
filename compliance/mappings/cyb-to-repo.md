# From the old CYB-240 / CYB-300 papers to this repo

This table is the honest bridge: it takes each *finding* the two academic
papers described (many of which were asserted rather than demonstrated) and
shows where it is now (a) implemented in code and (b) proven by a test.

| Old paper finding | Was it actually shown before? | Now implemented by | Now proven by |
|-------------------|-------------------------------|--------------------|---------------|
| RADIUS admin password stored cleartext | Described, `cat` output quoted | `radius_secure` (PBKDF2 hashes) | `test_no_cleartext_radius_password` + `attack_chain step4` |
| Weak/reused RADIUS shared secret | Asserted | `radius_secure` (per-deploy 24+ char secret from .env) | `test_radius_shared_secret_strength` |
| Weak LOCAL fallback password (`cisco`) | "would succeed" (never run) | strong unique local creds via `common_hardening` | `attack_chain step3` (wordlist fails) |
| Syslog plaintext over 514 | Described | `syslog_tls` (rsyslog gtls → 6514) | `test_syslog_transport_is_tls` |
| Missing log timestamp / device-id | Described | nftables log prefixes carry device + ts; Wazuh decoders | `attack_chain step2` (drop log captured) |
| NTP authentication missing | Described | `ntp_secure` (chrony NTS) | `test_ntp_authenticated` |
| SSHv2 not enforced / Telnet | Described | `common_hardening` | `test_telnet_disabled` |
| Console/SSH timeout too long | Described | `common_hardening` (ClientAliveInterval 300) | `test_ssh_idle_timeout` |
| Segmentation blocks prohibited scan | Asserted (no packet) | `fw-core.nft` default-deny | `test_user_vlan_blocked_from_radius` + Batfish |
| DMZ can't pivot inward | Not tested | `fw-dmz.nft` | `test_dmz_cannot_pivot_internal` |
| OSPF MD5 / BGP TTL-security | Described | `edge.frr.conf`, `core.frr.conf` | `test_ospf_md5_and_bgp_ttl` |
| VRRP gateway failover | "1-2 packets lost" (no capture) | `dist1/dist2.frr.conf` | `attack_chain step5` (measured loss) |

## The one-line difference
Old: *"a dictionary attack would succeed."*
New: the dictionary attack **runs**, and either succeeds (control missing) or
fails (control present) — and either way an evidence file records what happened.
