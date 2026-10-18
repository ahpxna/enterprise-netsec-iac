# try-on-linux report (full)

- started: 2026-10-18T02:52:29+00:00
- git: 

| stage | status | time | note |
|---|---|---|---|
| fabric-up | PASS | 16s |  |
| fabric-verify | PASS | 1s | 12/12 nodes running, containment sets present, enforcement agents listening |
| security-up | PASS | 9s |  |
| soc-up | PASS | 12s |  |
| soc-smoke | PASS | 11s |  |
| demo-model | PASS | 0s |  |
| soc-ai-up | PASS | 58s |  |
| dmzlab-up | PASS | 1s |  |
| dmzlab-verify | PASS | 33s | Juice Shop 200 + SSH honeypot banner via fw-dmz; DMZ host cannot reach internal zones; fw-dmz counters vuln=1 honeypot=1 |
| configure | FAIL | 116s | make target 'configure' failed at Makefile:84 (exit 2) |
| validate | FAIL | 8s | make target 'vpn-probe' failed at Makefile:245 (exit 1) |
| attack | FAIL | 60s | make target 'attack' failed at Makefile:258 (exit 1) |
| soc-validate | FAIL | 2338s | make target 'soc-ai-validate' failed at Makefile:194 (exit 1) |
| report | WARN | 5s | Summary: 12 passed · 1 failed · 0 error · 13 unverified (of 26 controls applicable to this profile)  -> evidence/COMPLIANCE-REPORT.md; not p |

## configure: FAIL

- command: `make configure`
- log: `logs/try-linux/20261018T025229Z/10-configure.log`
- where: make target 'configure' failed at Makefile:84 (exit 2)
- cause: TIME-01 needs the HOST clock disciplined by authenticated NTS
  - fix: `configure chrony from host/chrony-cxyz.sources.example, then `make host-time-check``

```
changed: [clab-companyxyz-fw-core]
changed: [clab-companyxyz-fw-dmz]
PLAY RECAP *********************************************************************
clab-companyxyz-core       : ok=6    changed=2    unreachable=0    failed=1    skipped=2    rescued=0    ignored=0   
clab-companyxyz-dist1      : ok=6    changed=2    unreachable=0    failed=1    skipped=2    rescued=0    ignored=0   
clab-companyxyz-dist2      : ok=6    changed=2    unreachable=0    failed=1    skipped=2    rescued=0    ignored=0   
clab-companyxyz-dmz-web    : ok=5    changed=2    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0   
clab-companyxyz-edge       : ok=6    changed=2    unreachable=0    failed=1    skipped=2    rescued=0    ignored=0   
clab-companyxyz-fw-core    : ok=13   changed=7    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0   
clab-companyxyz-fw-dmz     : ok=13   changed=7    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0   
clab-companyxyz-pc1        : ok=5    changed=2    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0   
clab-companyxyz-pc4        : ok=5    changed=2    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0   
clab-companyxyz-server1    : ok=28   changed=14   unreachable=0    failed=0    skipped=2    rescued=0    ignored=0   
make: *** [Makefile:84: configure] Error 2
```

## validate: FAIL

- command: `make validate`
- log: `logs/try-linux/20261018T025229Z/11-validate.log`
- where: make target 'vpn-probe' failed at Makefile:245 (exit 1)
- where: python: pathlib.py:1311 in mkdir -> PermissionError: [Errno 13] Permission denied: '/home/phan/Documents/enterprise-netsec-iac-main/wireguard/probe'

```
FileNotFoundError: [Errno 2] No such file or directory: '/home/phan/Documents/enterprise-netsec-iac-main/wireguard/probe/wg_confs'
During handling of the above exception, another exception occurred:
Traceback (most recent call last):
  File "/home/phan/Documents/enterprise-netsec-iac-main/scripts/prepare_vpn_probe.py", line 67, in <module>
    raise SystemExit(main())
                     ^^^^^^
  File "/home/phan/Documents/enterprise-netsec-iac-main/scripts/prepare_vpn_probe.py", line 59, in main
    DEST.parent.mkdir(parents=True, exist_ok=True)
  File "/home/phan/.local/share/uv/python/cpython-3.12.15-linux-x86_64-gnu/lib/python3.12/pathlib.py", line 1315, in mkdir
    self.parent.mkdir(parents=True, exist_ok=True)
  File "/home/phan/.local/share/uv/python/cpython-3.12.15-linux-x86_64-gnu/lib/python3.12/pathlib.py", line 1311, in mkdir
    os.mkdir(self, mode)
PermissionError: [Errno 13] Permission denied: '/home/phan/Documents/enterprise-netsec-iac-main/wireguard/probe'
make: *** [Makefile:245: vpn-probe] Error 1
```

## attack: FAIL

- command: `make attack`
- log: `logs/try-linux/20261018T025229Z/12-attack.log`
- where: make target 'attack' failed at Makefile:258 (exit 1)

```
EVIDENCE_DIR=evidence/runs/20261018T025704Z bash scripts/attack_chain.sh
FAIL[DET-01]: enforcement-to-Wazuh correlation failed
% Can't open configuration file /etc/frr/vtysh.conf due to 'No such file or directory'.
Configuration file[/etc/frr/frr.conf] processing failure: 11
attack replay complete: 1 critical failure(s); evidence=evidence/runs/20261018T025704Z
make: *** [Makefile:258: attack] Error 1
```

## soc-validate: FAIL

- command: `make soc-ai-validate`
- log: `logs/try-linux/20261018T025229Z/13-soc-validate.log`
- where: make target 'soc-ai-validate' failed at Makefile:194 (exit 1)
- where: pytest failed: tests/validation/test_soc_ai.py::test_ai01_feature_to_inference_event

```
 Container cxyz-security-elasticsearch-1  Waiting
 Container cxyz-security-elasticsearch-1  Healthy
 Container cxyz-security-soc-service-init-1  Starting
 Container cxyz-security-soc-service-init-1  Started
 Container cxyz-security-soc-service-init-1  Waiting
 Container cxyz-security-soc-service-init-1  Waiting
 Container cxyz-security-soc-service-init-1  Exited
 Container cxyz-security-soc-decision-1  Starting
 Container cxyz-security-soc-service-init-1  Exited
 Container cxyz-security-soc-response-1  Starting
 Container cxyz-security-soc-decision-1  Started
 Container cxyz-security-soc-response-1  Started
make[1]: Leaving directory '/home/phan/Documents/enterprise-netsec-iac-main'
make: *** [Makefile:194: soc-ai-validate] Error 1
```
