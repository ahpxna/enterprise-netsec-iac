# ADR 0006 — Adopt a correlation-gated SOC/AI closed loop

## Status

Accepted. Phase 1 contracts are implemented; runtime components remain gated
by their delivery phases.

## Context

The repository already supplies segmented network paths, Suricata, Wazuh,
RADIUS, VPN, ZTNA, validation, and evidence. The next objective is a research-
grade SOC that ingests heterogeneous telemetry, evaluates anomaly models, and
can perform reversible containment without granting a probabilistic model
direct control of privileged infrastructure.

Wazuh and Elasticsearch also have distinct responsibilities. Treating one as
an undefined substitute for the other would duplicate or obscure data flows,
while training only on Wazuh alerts would bias the AI dataset toward events
already selected by static rules.

## Decision

- Elasticsearch, Logstash, and Kibana are the primary SOC analytics plane.
- Wazuh Manager remains the endpoint HIDS, FIM, rules, and Active Response
  engine. Its `alerts.json` is ingested through Logstash.
- Suricata, OPNsense, RADIUS, and network-device logs enter Logstash directly.
- All sources normalize to a versioned ECS-compatible event contract before
  feature extraction.
- Isolation Forest is the first model. LSTM autoencoder follows only after the
  full feature, inference, provenance, and evaluation pipeline is reproducible.
- Model output is evidence, not authority. Only the decision engine may create
  a response request, and a score of at least 0.90 requires a second independent
  signal before automatic response is eligible.
- A separate response orchestrator owns narrowly scoped OPNsense and Wazuh
  adapters and enforces allowlists, TTL, rollback, rate limits, deduplication,
  verification, and response audit.

## Options considered

### A. Let the AI service block directly

Rejected. It couples inference failures and false positives to privileged
changes, bypasses policy, and prevents a trustworthy verification/rollback
lifecycle.

### B. Use correlation-gated reversible response

Accepted. It preserves model experimentation while making containment
deterministic, explainable, rate-limited, and auditable.

### C. Keep the platform alert-only

Safe for the ingestion and model phases, and required until their gates pass,
but insufficient as the final architecture because it cannot measure verified
containment time or HA response continuity.

## Consequences

### Positive

- Static, AI, and hybrid detectors can be evaluated on the same normalized
  corpus without static-rule preselection bias.
- AI credentials and response credentials remain separated by a policy
  boundary.
- Every containment can be reproduced, verified, expired, and reverted.
- OPNsense HA and Wazuh endpoint actions become testable response adapters
  instead of hidden model side effects.

### Negative

- The platform has more services, identities, schemas, and lifecycle gates.
- Keeping Wazuh's native storage while also retaining events in Elasticsearch
  may duplicate selected data and must be capacity-managed.
- ECS mapping, timestamp normalization, duplicate detection, DLQ handling, and
  model provenance become mandatory engineering work before runtime claims.

## Action items

1. Build the TLS-protected ELK ingestion MVP with no public Elasticsearch port.
2. Add source-specific ECS parser contracts and malformed/DLQ tests.
3. Build reproducible window features and Isolation Forest inference without
   automatic response.
4. Implement temporal evaluation and provenance manifests.
5. Add the decision engine and separately authenticated response adapters.
6. Extend compliance wiring with LOG, AI, COR, RESP, and SOC controls only as
   live evidence-producing tests become available.
