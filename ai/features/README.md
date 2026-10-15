# Feature pipeline

Extraction is deterministic and receives only normalized `soc-event-v1` events; it never
connects to Elasticsearch itself (the worker in `soc/workers/features.py` does that and calls
this module).

- `network-window-v1`: one five-minute vector per `src_ip` (connection, destination, byte, DNS,
  TLS, blocked-ratio, Suricata-alert and failed-auth counters). Only firewall log lines and
  Suricata `flow` records count as connections or contribute bytes, so one connection is never
  multiplied by the alert/DNS/TLS records that describe it.
- `endpoint-window-v1`: one five-minute vector per `host` (process, rare-process, PowerShell,
  failed-login, FIM, account and privilege-change counters; `process_baseline` supplies the
  rarity reference).
- `sequences.py`: the `T - 1` preceding window ends of an entity and the zero-filled sequence
  matrix used by the LSTM.

The contracts are closed and separate. `schemas/features/feature-vector.schema.json` is only a
compatibility entry point that accepts exactly one of them, so callers cannot mix fields or
silently add model inputs. Each vector carries its schema hash, a deterministic hash of the exact
source event set (so a retry is idempotent) and the generator Git revision.
