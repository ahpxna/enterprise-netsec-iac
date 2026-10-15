# Response adapters

These adapters are reachable only from the Response Orchestrator after it
accepts a signed, policy-hashed command. They do not import AI code.

- [`blocklist.py`](blocklist.py) is the shared fixed-set adapter. It can only add,
  remove and read membership of `SOC_BLOCKLIST` on every configured peer; all
  peers must agree before an action is reported applied or verified, and a
  partial apply is compensated before a failure is returned. The nftables and VyOS
  adapters are thin subclasses; [`opnsense.py`](opnsense.py) is the OPNsense variant.
  Each hands the firewall a lifetime so the entry expires on its own if the
  orchestrator dies (the orchestrator's TTL remains authoritative).
- [`wazuh.py`](wazuh.py) accepts only `isolate_host`, exposes only
  `cxyz-isolate-endpoint` and `cxyz-restore-endpoint`, and verifies their
  controlled status. It has no shell command, script name, or arbitrary Wazuh
  action argument.

Transport clients are injected through tiny protocols. The concrete clients live in
[`../transports/`](../transports/README.md): they pin their trusted CA, use mTLS or a
scoped credential file as applicable, and receive credentials from files mounted
outside this repository. No credentials, `verify=false`, `curl -k`, or generic HTTP
client is present in the adapters.

## Recovery contract for transport implementations

`recovery_reference(command)` must be a pure local calculation. It supplies a
stable reference before apply; it cannot depend on a response receipt that may
be lost. Every apply/revert call uses the immutable idempotency key. Wazuh's
legacy transport argument is named `correlation_id`, but its value is now the
operation idempotency key, not the caller's tracing label.

Revert must be safe to repeat, including after an apply timeout or after an
already completed revert. Removal may release only the ownership acquired by
this operation; pre-existing blocks and another operation's isolation must
remain intact. A client that only performs a blind alias delete does not satisfy this protocol;
the real clients get durable ownership tracking from
`../transports/ownership.py`.

OPNsense compensation includes the peer whose add was in flight when a timeout
occurred. Failed compensation remains an unknown outcome requiring recovery.
Boolean readbacks must be actual booleans; strings such as `"false"` or missing
values cannot prove enforcement or removal.
