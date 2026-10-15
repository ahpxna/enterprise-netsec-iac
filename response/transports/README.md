# Response transports

Mutually authenticated clients behind the adapters. Each exposes only the fixed
operations the adapter needs; none accepts an alias name, rule, script or URL from
a command.

| Module | Backend | Operations | Authentication |
|---|---|---|---|
| [`nftables.py`](nftables.py) | `docker/enforcer/nft_enforcer.py` on `fw-core`/`fw-dmz` | add (with timeout), remove, contains on `soc_blocklist` | mTLS client certificate issued by the SOC CA |
| [`vyos.py`](vyos.py) | VyOS HTTPS API | set/delete/show of the `SOC_BLOCKLIST` address-group | API key file |
| [`opnsense.py`](opnsense.py) | OPNsense API | add/delete/contains on the `SOC_BLOCKLIST` alias | credentials file |
| [`wazuh_api.py`](wazuh_api.py) | Wazuh manager API | the two Active Response commands, agent lookup, FIM marker read | least-privilege API user (`active-response:command`, `agent:read`, `syscheck:read`) |
| [`http.py`](http.py) | shared | TLS-verified JSON over HTTPS | CA file is mandatory; there is no way to disable verification |

## Ownership ledger

[`ownership.py`](ownership.py) wraps any of the three firewall set clients in
`OwnedBlocklistClient`. For each peer it durably records which operations
(idempotency keys) hold an address and whether the address *pre-existed* our first
claim (an analyst's manual block, another response). The intent is written before
the side effect, so an add that times out after the peer applied it is still owned
and can be released. Release physically removes an entry only for the last owner
of an address that this response plane added; a foreign entry is never removed.
Every operation is safe to repeat.

## Wazuh isolation verification

`wazuh_api.py` never executes anything on the endpoint. The Active Response script
(`docker/wazuh/active-response/cxyz_endpoint_isolation.py`) writes a marker file
under `/var/ossec/var/cxyz-isolation/` only *after* its nftables ruleset is active
and removes it only *after* the ruleset is gone. Wazuh FIM watches that directory,
so "marker present in the FIM inventory" is the read-only proof of isolation and
"marker absent" is the proof of restoration.

Known limits: FIM reporting lags (the client polls up to its verify timeout);
VyOS has no per-element timeout, so the orchestrator's TTL sweep is the expiry
there; the Wazuh API certificate in Path C carries the Compose host name, so
endpoint isolation stays unconfigured (fails closed) until the PKI is reissued
(`docs/PKI-ROTATION.md`).
