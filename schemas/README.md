# SOC contracts

These schemas are the versioned boundaries between ingestion, feature
engineering, AI inference, and privileged response. Producers may add ECS
fields to normalized events, but feature and response payloads are intentionally
closed so drift fails tests instead of silently changing model behavior.

- `ecs/soc-event.schema.json`: normalized multi-source telemetry.
- `features/feature-vector.schema.json`: model-ready entity/window features.
- `response/action-request.schema.json`: correlation-gated response request.
