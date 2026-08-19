# Architecture

## Text diagram (paste into draw.io as a starting sketch)

```
                              INTERNET
                                 |
                 +---------------+---------------+
                 |                               |
             [ ISP1 ]                        [ ISP2 ]         AS65010 / AS65020
             198.10.10.1                     197.10.10.1
                 \                               /
                  \        BGP (MD5 pw +        /
                   \       ttl-security 1)     /
                    \                          /
                     +--------[ EDGE ]--------+            vIOS-EDGE-I -> FRR
                              195.1.1.2                    - dual-homed BGP
                              /        \                   - outbound route filter
                             /          \                    (advertise only /24)
                            /            \
                   +-------+              +--------+
                   |                               |
           [ FW-CORE ]                        [ FW-DMZ ]     ASAv -> nftables
           default-deny                       default-deny   (default-deny, logged)
           logs every DROP                    only 80/443 in
                   |                               |
            OSPF (MD5)                         [ DMZ-WEB ]    195.1.1.161
                   |                            (public app)  no inward pivot
              [ CORE ]  vIOS-Core -> FRR
              passive-int on user VLANs
              /          \
       [ DIST1 ]        [ DIST2 ]      Arista vEOS -> FRR
       VRRP master      VRRP backup    virtual gw .254, failover < 2s
       (prio 150)       (prio 100)
          |                 |
       [ PC1 ]           [ PC4 ]
       VLAN10 user       VLAN40 mgmt
       (untrusted)       (admin station)

                    DATA CENTER  172.16.50.0/24
                    +------------------------------+
                    | [ SERVER1 ]  DNS DHCP NTP    |
                    |  - RADIUS (PBKDF2 hashes)    |
                    |  - NTP via NTS (authenticated)|
                    |  - rsyslog -> TLS 6514       |
                    +---------------+--------------+
                                    |
                    SECURITY PLANE (docker-compose)
                    +------------------------------+
                    | Wazuh SIEM (rules: DET-01/02)|
                    | Suricata IDS (span monitor)  |
                    | Traefik + Authentik (ZTNA)   |
                    | WireGuard (remote admin)     |
                    +------------------------------+
```

## Data flow (three journeys)

1. **North-south user traffic.** PC1 (VLAN10) → DIST (VRRP gw .254) → CORE
   (OSPF) → FW-CORE (default-deny; egress to Internet allowed) → EDGE → ISP.
   Return traffic is stateful (`ct state established`).

2. **A prohibited internal scan (the CYB-240 chain, now real).** PC1 runs
   `nmap` at Server1:22/23/80. FW-CORE has no allow rule for user-VLAN→DC on
   those ports, so packets hit the logged `drop`. The `CXYZ-FWCORE-FWD-DROP`
   log line is shipped to Wazuh, which fires rule `100201` (level 10, MITRE
   T1046). **Protect** (blocked) and **Detect** (alert) are both proven, with
   an evidence file, not a sentence.

3. **DMZ isolation.** Internet → FW-DMZ: only 80/443 reach DMZ-WEB. If the web
   host is popped and tries to reach 172.16/192.168, FW-DMZ hits
   `CXYZ-FWDMZ-PIVOT-DROP` → Wazuh rule `100202` (level 12, T1210). The DMZ
   cannot pivot inward, and the attempt is alerted.

## How SIEM + IDS interact
- **SIEM (Wazuh)** is log-centric: it ingests firewall DROP logs and device
  syslog (over TLS), decodes the `CXYZ-*` prefixes, and correlates them into
  alerts (`docker/siem/rules/cxyz_rules.xml`).
- **IDS (Suricata)** is packet-centric: it watches the span/host interface and
  raises signature alerts (SSH-to-DC, Telnet, RADIUS probe, SYN-scan). Its EVE
  JSON is also read by Wazuh, providing a unified monitoring view.
