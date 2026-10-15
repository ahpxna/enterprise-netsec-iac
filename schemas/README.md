# SOC contracts

These schemas are the versioned boundaries between ingestion, feature
engineering, AI inference, and privileged response. Producers may add ECS
fields to normalized events, but feature and response payloads are intentionally
closed so drift fails tests instead of silently changing model behavior.

- `ecs/soc-event.schema.json`: normalized multi-source telemetry.
- `features/network-window-v1.schema.json`: strict five-minute source-IP
  network vector; it must not be mixed with endpoint features.
- `features/endpoint-window-v1.schema.json`: strict five-minute host endpoint
  vector.
- `events/anomaly-event-v1.schema.json`: separate AI score event that only
  references a feature vector; it cannot overwrite raw telemetry.
- `events/correlation-decision-event-v1.schema.json`: AI plus independent
  signal correlation boundary. Automatic response requires both.
- `events/dataset-manifest-v1.schema.json`: metadata-only temporal/session
  split dataset provenance.
- `events/model-provenance-v1.schema.json`: hash, source, seed, threshold,
  hyperparameter, and evaluation record for a model artifact.
- `response/action-request.schema.json`: correlation-gated request contract,
  strengthened to require a decision policy and independent signal.
- `response/`: strict adapter-bound command and append-only response audit
  schemas live with the response implementation.

## Contract index

| Schema | Used by |
|---|---|
| `ecs/soc-event.schema.json` | normalized events (LOG-02 verifier) |
| `features/{network,endpoint}-window-v1.schema.json` | feature vectors; their digest binds datasets, models and APIs |
| `events/anomaly-event-v1`, `correlation-decision-event-v1` | `soc-ai-*` and the decision records in `soc-response-*` |
| `events/model-provenance-v1`, `dataset-manifest-v1` | model registry and dataset builder |
| `response/action-request.schema.json`, `../response/schemas/*` | signed command and append-only audit event |

`evaluation-binding-v1`, `labels-v1`, `scenarios-v1`, `partition-membership-v1`, `promotion-policy-v1` and
`benchmark-comparison-v1` are small closed documents validated in code (`ai/training`, `ai/evaluation`).
