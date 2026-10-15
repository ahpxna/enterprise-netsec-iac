# Response plane

The response plane owns the privileged half of the closed loop:

```text
AI anomaly -> Decision Engine -> signed response command -> Orchestrator
           -> constrained adapter -> verify -> append-only audit
```

It intentionally has no `AI -> firewall` path. A model score alone is never an
action request: a policy must find an independently observed Suricata, Wazuh,
authentication, threat-intelligence, or protected-asset signal first.

## Components

- [`decision.py`](decision.py) evaluates the versioned policy, rechecks target
  protections, emits a correlation event, and signs an internal command. It
  imports no adapters and holds no firewall or Wazuh credentials.
- [`signing.py`](signing.py) is the Ed25519 command authenticator. The Decision
  Engine holds the only private key; the Orchestrator and auditors hold public
  keys (a key ring named by `key_id`), so a compromised orchestrator can verify
  commands but never forge one. The HMAC authenticator in `decision.py` remains
  only as a unit-test reference.
- [`policies/`](policies/) is a small declarative vocabulary: AI threshold,
  independent-signal conditions, action, TTL, dedup/rate limits, and protected
  targets. It cannot encode commands, URLs, aliases, or secrets.
- [`orchestrator/`](orchestrator/) accepts only a valid signed command, audits
  `REQUESTED`, then separately applies, verifies, expires, or rolls back the
  constrained action.
- [`adapters/`](adapters/) exposes only `SOC_BLOCKLIST` membership on every
  firewall peer (nftables, VyOS, OPNsense) and named Wazuh isolate/restore
  operations. No adapter has an arbitrary firewall-config or shell method.
- [`transports/`](transports/) are the mutually authenticated clients behind those
  adapters, plus the durable *ownership ledger* that guarantees a revert can
  never remove an entry the response plane did not add.
- [`service/`](service/) turns the library into two long-running processes:
  the decision runner and the orchestrator service (see below).
- [`deployments/`](deployments/) names files and endpoints per path
  (`path-a`, `path-b`, `path-c`); it never contains a credential.
- [`schemas/`](schemas/) defines the signed handoff and immutable audit event.

## Services

```bash
python -m response.service decision     --config /etc/soc/decision.yaml
python -m response.service orchestrator --config /etc/soc/response.yaml
```

**Decision runner** reads `soc-ai-*` anomalies (`is_anomaly` and score >= the
configured floor, never below 0.90) in a durable order, gathers the independent
evidence stored by Logstash (`soc-alerts-*`, `soc-auth-*`, `soc-endpoint-*`,
`soc-network-*`), asks the pure engine for a verdict, appends the correlation
decision to `soc-response-*`, and - only in `enforce` mode - delivers the signed
command over mTLS. An anomaly without a second signal produces *no* decision
record and no request. It holds the signing key and an Elasticsearch identity
limited to reading telemetry and creating response documents.

**Orchestrator service** exposes `POST /v1/commands` (mTLS, 16 KiB cap),
`GET /v1/responses/{id}`, `/health`, `/ready` and `/metrics`. A scheduler loop
applies, verifies, expires and recovers, then exports the append-only audit to
`soc-response-*`; an Elasticsearch outage never stops containment lifecycle work
and the export resumes from the durable journal.

### Modes and the validation override

Both services ship in `mode: observe`: the runner records what it *would* have
requested as an analyst alert, and the orchestrator accepts no command and
applies nothing. `enforce` is a deliberate lab action. The environment variable
`SOC_MODE` (from the gitignored `.env`) overrides the reviewed file *only* so
that `make soc-ai-validate` can enable enforcement without editing tracked files;
it accepts exactly `observe` or `enforce` and the shipped examples never set it.
The validation overlays `policies/lab-validation*.yaml` differ from their base
policy only by a 60-second TTL (enforced by a unit test).

### Firewall backends

| Path | Backend | Reached through | Expiry backstop |
|---|---|---|---|
| A | nftables on `fw-core`/`fw-dmz` | `docker/enforcer/nft_enforcer.py` (3 operations, mTLS, mgmt network only) | nft element `timeout` |
| B | VyOS `SOC_BLOCKLIST` address-group | VyOS HTTPS API (key file; `ansible/roles/vyos_response_api`) | orchestrator TTL sweep |
| C | nftables (Path A fabric) | as Path A, from a Kubernetes Deployment | nft element `timeout` |
| - | OPNsense alias | OPNsense API (contract-tested only; no lab) | alias entries |

## Lifecycle and evidence

```text
REQUESTED -> APPLIED -> VERIFIED -> EXPIRED
                   \-> ROLLED_BACK
                   \-> FAILED
```

`APPLIED` means only that an adapter accepted the request. It is never
containment success. Only `VERIFIED` carries evidence that enforcement was
observed. Verification failure triggers a best-effort rollback and is recorded
as `ROLLED_BACK` with failure metadata; adapter errors become `FAILED`, never
a false success.

Every transition is a separate `response-audit-event-v1` document destined for
`soc-response-*`. `SQLiteResponseStore` persists the local audit and response
state atomically, including dedup identities, rate-limit timestamps and pending
operation intents. The owning service must invoke recovery and TTL sweeps;
see `orchestrator/README.md`. Multi-host coordination, real transport ownership
tracking and external audit delivery are not supplied by the local store.

## Security boundary

- Both Decision Engine and Orchestrator evaluate the current protected-target
  policy; a stale `allowlist_checked` field cannot bypass it.
- Block targets must be valid, non-special IP addresses and cannot overlap an
  allowlist, protected DNS/NTP/RADIUS/SOC hosts, current OOB management
  network, or other declared SOC/management networks. The default can also
  reject all private targets.
- Host isolation is deny-by-default until an endpoint is explicitly listed in
  `allowed_isolation_hosts`; SOC and management hosts remain protected.
- Commands have a policy hash, TTL, idempotency key, short authorization
  lifetime, and an Ed25519 signature; the verification key ring is mounted into
  the orchestrator, the private key only into the decision runner.
- No source file carries credentials, disables TLS validation, uses `curl -k`,
  or gives an AI component adapter access. `scripts/check_soc_ai_static.py`
  enforces these rules, the import boundaries (the AI plane cannot import
  `response`/`soc`; the response plane cannot import model code) and, for
  Kubernetes, one Secret per workload and egress to firewalls for the
  orchestrator only.

## Verification status

Offline: the decision runner, signing, orchestrator, audit export, every
transport (against in-process TLS servers), the enforcement agent, and the
Wazuh Active Response script have unit/integration tests (`make soc-ai-contracts`).
Live: `make soc-ai-validate` (Path A) and the Path B audit run the shared verifiers
in `tests/validation/soc_live.py` for controls COR-01 and RESP-01/02/03; until
they are run on lab hosts those controls are `UNVERIFIED` in the compliance report.
Not implemented: OPNsense HA/CARP failover (control RESP-04 stays *planned*).

## Correlation input contract

`DecisionEngine.evaluate` requires an explicit `target: {type, value}` in the
anomaly and in every independent signal, matching the requested target. A
missing or mismatched binding is rejected. IP representations are normalized;
host names are trimmed and lowercased consistently with the protection policy.
Callers must extract these bindings from trusted telemetry, not copy the
requested target onto unrelated evidence. This library does not fetch or
authenticate the referenced source events itself.

Use the original observation time for `observed_at`; for windowed AI evidence,
use `feature_vector.window_end`, not the later inference/delivery timestamp.
All evidence must be within `defaults.evidence_max_age_seconds` (900 seconds
in the default catalog), allowing at most 60 seconds of future clock skew.
Evidence outside that range produces an alert/store-only decision with no
signed command. A stale optional signal must be removed before reevaluating.
The anomaly flag must agree with its score and model threshold, and a source
reference can appear only once, including across different signal types and
the AI event itself. Counts and severities must be finite, nonnegative integers.

Signal order, equivalent timestamp/IP spellings, and a different tracing
`correlation_id` do not create a new containment idempotency key. Different
trace labels may still appear in the returned records; persist the first
accepted record for each stable identity.

Existing callers must supply evidence target bindings and add the freshness
setting to custom catalogs. Effective policy hashes now include the shared
safeguards, so previously signed commands must be reevaluated and reissued.
