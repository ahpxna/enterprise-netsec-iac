# Offline capture → features → inference → append-only anomaly delivery

Source implementation only; no service, training, test or delivery has been run.
This is a bounded JSONL capture workflow, not a continuous Elasticsearch reader.
The feature exporter holds a capture in memory: use appropriately sized captures.

1. Export normalized events with `python -m ai.features.export INPUT.jsonl
   --schema network-window-v1 --git-sha REVISION`, retaining stdout as an ignored
   vector artifact. Do not modify the raw capture.
2. Import with `python -m soc.workers.enrichment --outbox soc/runtime/outbox/jobs.db
   import VECTORS.jsonl --metadata-sha256 APPROVED_METADATA_DIGEST`.
3. Configure the environment below, then use the same outbox path with `drain`.
   Each invocation processes a bounded batch; no scheduler is installed.
4. Inspect `status`. Exit code 2 from drain means pending/scored/deadletter work
   remains, not successful completion. Correct permanent failures before
   explicitly invoking `requeue JOB_ID`.

Required delivery configuration (never commit actual keys):

| Variable | Purpose |
| --- | --- |
| SOC_AI_URL | Private HTTPS origin of the inference service |
| SOC_AI_CA | CA for inference server verification |
| SOC_AI_CLIENT_CERT / SOC_AI_CLIENT_KEY | Dedicated worker mTLS identity |
| SOC_ES_URL / SOC_ES_CA | Private Elasticsearch HTTPS origin and trusted CA |
| SOC_AI_ES_API_KEY_FILE | Secret file containing an ES API key scoped to the AI writer role |

The inference service receives none of the worker's ES credentials and no firewall
credentials. API-key provisioning is still an operator step; role descriptors
alone do not create a usable key. TLS verification is mandatory; proxies and
redirects are disabled. Use distinct identities and dedicated client CAs.

SQLite persists validated input and the first successful anomaly event. Delivery
retries reuse that event and its timestamp instead of rescoring. ES writes use
`_create` on `soc-ai-*`, never raw/normalized documents. Transient failures back
off; permanent failures stay visible in the local deadletter state. Monitor disk
space/backlog and back up the private outbox including WAL safely. No automatic
retention cleanup or background drain is implemented.

The parent directory and database/lock must be worker-owned and private.
Same-UID malicious access is outside this file-permission boundary; deploy each
worker under a dedicated identity. Live TLS rejection, crash/retry behavior,
Elasticsearch privileges and dashboard visibility remain UNVERIFIED.
