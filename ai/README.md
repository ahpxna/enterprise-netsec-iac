# AI plane

The AI plane consumes versioned feature vectors and produces new scored evidence.
It never overwrites `soc-raw-*`, holds no Elasticsearch credential, and has no
firewall or endpoint-response credential or import path (`scripts/check_soc_ai_static.py`
fails the build if `ai/` imports `response`, `soc` or an HTTP client).

```text
normalized events -> features/ (5-minute vectors) -> models/ (Isolation Forest | LSTM autoencoder)
                  -> api/ (mTLS, approved model only) -> soc-ai-* evidence (written by soc/workers)
training/ + evaluation/ produce a CANDIDATE; promote.py turns it into an APPROVED registry
```

| Directory | Contents |
|---|---|
| [`features/`](features/README.md) | deterministic `network-window-v1` / `endpoint-window-v1` extraction and window sequences |
| [`models/`](models/README.md) | `SocIsolationForest` (joblib), `SocLstmAutoencoder` (safetensors) and the provenance-gated loader |
| [`api/`](api/README.md) | FastAPI inference service and the mTLS-only launcher |
| [`evaluation/`](evaluation/README.md) | labels, detectors, threshold selection, metrics, five-detector comparison |
| [`training/`](training/README.md) | dataset builder, candidate trainers, governed promotion |
| [`registry/`](registry/README.md) | the approved-model directory contract |

The services around it live outside this package: `soc/workers/` runs the continuous
feature worker (`features.py`), the enrichment worker (`enrichment.py`, an SQLite outbox
that calls the API over mTLS and writes `soc-ai-*`) and the dataset capture
(`export_events.py`).

## Trust model

A model is loadable only when all of these hold: its metadata is `approved`; the SHA-256
of the metadata bytes equals `SOC_AI_METADATA_SHA256`, supplied *independently of the
registry* (`.env` / a ConfigMap, never stored next to the model); the artifact hash and
size match provenance; and the feature-schema digest in the repository, the registry copy
and the model itself agree. Joblib is deserialised only after the artifact digest has been
verified; the LSTM artifact is `safetensors`, which cannot carry code at all.

## Honest limits

- No model shipped in this repository was trained on real telemetry. The test suite trains
  on deterministic synthetic data to prove the *machinery* (leakage-safe datasets,
  artifact-bound evaluation, promotion gates); those numbers are unit-test artifacts, not
  research results.
- An anomaly score is evidence for correlation, never an action: the response plane
  additionally requires an independent corroborating signal.
