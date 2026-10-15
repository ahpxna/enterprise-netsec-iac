# Inference API

`main.py` implements `/health`, `/ready`, `/model`, `/metrics`, and
`/v1/infer`. It only loads an approved, hash-verified local model registry (either family)
and rejects a mismatched schema (`FEATURE_SCHEMA_MISMATCH`), an unknown or missing feature
(`require_exact_features`), or a wrong history length (`HISTORY_LENGTH_MISMATCH`) with HTTP
422 and no score. Sequence models take the preceding windows in `history` (oldest first,
`null` = no telemetry in that window).

The API holds no Elasticsearch, OPNsense, Wazuh, Decision Engine, or Response
Orchestrator credential. Its response is scored evidence—not a firewall or
endpoint action—and a missing/tampered model degrades safely with 503 while
static SOC detection remains independent.

The supported secure launcher is `python -m ai.api.serve`. It requires
`SOC_AI_SERVER_CERT`, `SOC_AI_SERVER_KEY`, `SOC_AI_CLIENT_CA` and
`SOC_AI_METADATA_SHA256` (the independently approved metadata digest). Bind is
loopback by default; only an explicit private/loopback IP is accepted. Clients
must present a certificate trusted by the dedicated client CA. Do not substitute
a plaintext uvicorn launch for this production path.

Approval of metadata must happen outside the writable model registry: changing
both a binary and its adjacent hash is not sufficient. The deployment-provided
digest binds the exact metadata bytes before joblib deserialization.

Offline tests cover the loader, the endpoints and the mTLS launcher (wrong CA, missing client
certificate). Controls AI-01..03 verify the deployed API live (`make soc-ai-validate`);
until that has run, the running service is `UNVERIFIED`.
