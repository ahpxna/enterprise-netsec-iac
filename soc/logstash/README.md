# Logstash

The eight ordered files under `pipelines/` tail Suricata, Wazuh alerts, Wazuh
archives (decoded endpoint events), and the authenticated network relay. Every payload is cloned into append-only
`soc-raw-*` before parsing. The normalized copy receives ECS fields,
deterministic identity, and zone/VLAN enrichment while `event.original`
remains unchanged. Parser failures are tagged `_parse_failure` and written to
`soc-deadletter-*`. Persistent queue and DLQ storage survive container
recreation.

Logstash does not train or call models and its Elasticsearch role cannot write
`soc-ai-*` or `soc-response-*`.
