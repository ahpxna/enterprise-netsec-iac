# Response policies

[`default.yaml`](default.yaml) is the declarative policy set shared by the
Decision Engine and Orchestrator. It is fail-closed: unknown keys, disabled
policies, action types outside `block_ip` / `isolate_host`, thresholds below
0.90, empty independent-signal requirements, invalid CIDRs, and out-of-range
TTLs are rejected at load time.

```yaml
when:
  ai_score_gte: 0.90
  require_any:
    - type: suricata
      min_severity: 2
    - type: authentication
      min_count: 20
```

`require_any` is always a non-AI signal. The engine adds the AI anomaly itself
to the correlation record, so a caller cannot turn one model result into two
signals. A policy can create only `block_ip` or `isolate_host`; the former maps
to the fixed OPNsense `SOC_BLOCKLIST` adapter and the latter maps to the
controlled Wazuh isolate/restore adapter.

`protections` are evaluated twice, first by Decision Engine and again by
Orchestrator. Declare OOB/VLAN 99/SOC ranges in `protected_networks`,
DNS/NTP/RADIUS/SOC addresses in `protected_ips`, SOC and management identities
in `protected_hosts`, and never-auto-contain targets in the explicit allowlist.
Endpoint isolation is deny-by-default until a host is listed in
`allowed_isolation_hosts`.

Policy values are canonicalized and SHA-256 hashed into every decision command.
Changing YAML comments does not alter a semantic policy hash; changing an
action, threshold, TTL, or safeguard does. A command referencing an older hash
is rejected by the Orchestrator.

The effective per-policy hash includes normalized target protections, rate
limits, dedup duration, command lifetime and evidence freshness. Changing any
of these safeguards invalidates commands signed under the previous catalog;
formatting and comments do not change the semantic hash.

Custom catalogs must explicitly set `defaults.evidence_max_age_seconds` to an
integer between 30 and 86400. The default is 900 seconds. Decision Engine
compares original observation times with its current time and permits at most
60 seconds of future clock skew. Expired/future evidence cannot request an
automatic action, even if the numeric thresholds match.

## Overlays

| File | Purpose | Differs from `default.yaml` only by |
|---|---|---|
| `default.yaml` | shipped policy (Paths A and C) | - |
| `lab-path-b.yaml` | Path B lab | `allowed_isolation_hosts: [pc1]` (the one enrolled endpoint) |
| `lab-validation.yaml` | `make soc-ai-validate`, Path A | TTL of 60 s (the schema minimum) |
| `lab-validation-path-b.yaml` | `make soc-ai-validate`, Path B | `pc1` enrolled and a TTL of 60 s |

`tests/soc/test_deployment_configs.py` enforces that overlays never relax a safeguard
(protected targets, rate limit, dedup, freshness) and that validation overlays are never
the shipped default; the Kubernetes mirror carries `default.yaml` only.

## Honeypot corroboration

`COR-001` accepts `type: honeypot` with `min_severity: 5`: a Cowrie event (dataset `cowrie.honeypot` in `soc-alerts-*`) from the
anomalous source address within the evidence window, at the level of a login attempt or worse (`cowrie.session.connect` is 3, failed
login 5, successful login 8, command 9, file transfer 10). The decision runner folds every honeypot event of that source into ONE signal
(worst severity, event count), so a noisy attacker cannot look like several independent observations. It never makes a protected target
containable: the routed transit `10.255.0.0/16` is protected in every policy because campus traffic reaches the DMZ NATed to fw-core's
outside address, and blocking that address would cut the whole campus, not contain one host.
