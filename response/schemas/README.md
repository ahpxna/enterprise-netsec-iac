# Response payload contracts

`response-command-v1.schema.json` is the signed, internal handoff from the
Decision Engine to the Response Orchestrator. It carries no firewall or Wazuh
credential and cannot express arbitrary device configuration.

`response-audit-event-v1.schema.json` is the append-only lifecycle record for
the response orchestrator. A decision may request an action, but adapters only
receive validated orchestrator requests. Every request, apply, verification,
expiry, rollback, and failure is emitted as a separate immutable event into
`soc-response-*`.

`APPLIED` must never be rendered as successful containment. A response reaches
success only at `VERIFIED`, with enforcement evidence. The schema contains no
credential fields; adapter credentials remain outside event payloads.
