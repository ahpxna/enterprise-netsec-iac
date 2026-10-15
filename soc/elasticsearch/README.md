# Elasticsearch

Bootstrap installs versioned templates and a least-privilege
`cxyz_logstash_writer` role. HTTP and transport TLS are mandatory, data is
persistent, and Elasticsearch has no host-published port. ILM retains
normalized telemetry for 30 days, append-only raw telemetry for 14 days, and
dead-letter investigation data for 14 days by default. Versioned mappings and
retention also reserve separate `soc-features-*`, `soc-ai-*`, and
`soc-response-*` streams. Logstash cannot write AI or response indices;
feature, AI-event-writer, decision, and response roles are separate and bounded
before their service users are introduced. The future inference API receives no
Elasticsearch credential: a separate enrichment worker may assume only the
`cxyz_ai_event_writer_role` role, which reads `soc-features-*` and create-only writes
to `soc-ai-*`. Saved-object import uses a separate temporary
`kibana_admin` identity instead of the Elasticsearch superuser; a backend-only
job deletes that identity immediately after the import succeeds.
