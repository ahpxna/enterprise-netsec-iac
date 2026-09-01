# SOC analytics plane

Phase 1 skeleton for Logstash ingestion, Elasticsearch storage, and Kibana SOC
views. Runtime services begin in Phase 2. Elasticsearch is not a replacement
for Wazuh Manager: Wazuh retains endpoint rules/FIM/response and exports alerts
into this analytics plane.
