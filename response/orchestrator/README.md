# Response orchestrator

[`engine.py`](engine.py) is the privileged lifecycle boundary. It verifies the
signed command, active policy version/hash, TTL, action/target pairing, target
protections, deduplication, and rate limit before selecting one constrained
adapter. Submission creates `REQUESTED`; it does not auto-apply an action.

The lifecycle is explicit:

```text
submit -> REQUESTED
apply  -> APPLIED
verify -> VERIFIED only with adapter evidence
expire -> EXPIRED after TTL and successful revert
manual -> ROLLED_BACK after successful revert
error  -> FAILED (never reported as verified)
```

When verification fails, the orchestrator attempts immediate rollback. A
successful compensation is recorded as `ROLLED_BACK` with failure metadata;
otherwise the state is `FAILED`. Every state transition becomes one immutable
`response-audit-event-v1` record. `SQLiteResponseStore` is the local persistent
implementation. `InMemoryAuditLedger` remains available for source examples
and does not provide restart recovery.

`FAILED` after an attempted action can still mean containment remains in place.
Manual rollback and the TTL sweep retry recovery; each failed attempt appends
another `FAILED` event, and proven recovery appends `ROLLED_BACK`. Failures
before an adapter invocation cannot enter this recovery path. Unknown apply
outcomes can be recovered without claiming that application ever succeeded.

Submission becomes eligible for apply only after the initial audit append,
target protection check, and rate limit succeed. If a rejection cannot be
audited, the request remains ineligible for apply. Retained lifecycle records
also prevent reusing an event identity after the short dedup cache expires.

## Persistent wiring and recovery

Pass `store=SQLiteResponseStore(path)` to `ResponseOrchestrator` together with
the catalog, authenticator and two adapters. Omit `ledger`; the same database
must own state and audit so every lifecycle transition commits atomically.
Use a private, owned directory (0700), for example
`soc/runtime/response/journal.sqlite`. The database and owner lock must be
private regular files (0600). Do not unlink the lock or replace the database
while an owner is running. Close the store on shutdown.

The store retains commands, TTLs, admission decisions, submission timestamps,
and lifecycle identities. It records an operation intent and deterministic
recovery reference before any apply/revert call. Audit events cannot be updated
or deleted through the store. SQLite WAL with synchronous FULL protects local
commits; this is not external tamper-proof archival storage.

On startup, call `recover_pending()` before accepting new work, then
`expire_due()`. Continue calling both from the service scheduler with backoff
when peers are unavailable. Construction only loads state; it never contacts
peers or automatically starts a scheduler. `recover_pending()` compensates
unfinished operations and never replays an uncertain apply. It can recover
using the original operation identity after authorization expiry or a policy
change. Adapters must implement the ownership-safe recovery contract described
in `../adapters/README.md`.

If a checkpoint fails, the instance stops all further operations because a
commit may have succeeded without acknowledgment. Close it, reopen the store,
construct a new orchestrator and recover. A committed `APPLIED` is restored as
such; an uncommitted outcome retains the earlier intent for compensation.
Recovery audit includes `action_intent`; it does not invent an `application`
timestamp for an apply whose outcome was unknown.

Public operations are serialized within the process. A lifetime owner lock
rejects another process, and active/unresolved operations block another apply
against the same normalized target. This implementation supports one owner
on a local filesystem, not multi-host replicas or NFS coordination. Rejected
or partly admitted requests remain ineligible after restart; new evidence is
required for a new response identity.

The rate budget is derived from committed `REQUESTED` events and includes
denied submissions, preserving the existing ledger-backed accounting semantics.

Regression cases cover restart, rate-limit persistence, uncertain apply,
commit acknowledgment loss, rollback retry and owner exclusion, and run in the
offline suite (`make soc-ai-contracts`). The scheduler that invokes `recover_pending`,
`pending_apply`, `awaiting_verification` and `expire_due`, and the external audit
export, are provided by [`../service/runner.py`](../service/runner.py); the real peer
transports by [`../transports/`](../transports/README.md). Live enforcement against the
lab firewalls is proven only by `make soc-ai-validate` (controls RESP-01/03) and stays
`UNVERIFIED` until that has run.

## Existing audit-only option

`SQLiteAuditLedger` in `sqlite_audit.py` remains available as `ledger=...`. It
persists append-only audit, one-shot apply claims and submission counts, and
its `recovery_queue()` provides a read-only snapshot for peer reconciliation.
It also saves immutable commands. Its explicit `restore_recovery()` path on a
fresh orchestrator reconstructs rollback-only records from signed commands and
audit; it does not restore queued apply authorization or an uncertain apply
reference that never reached the audit. Such unknown outcomes still require
manual reconciliation with the audit-only backend.
Use a separate database path for `SQLiteResponseStore`: the formats differ and
no automatic migration is provided. Never delete old claims to force a replay.
Preserve and reconcile outstanding operations before switching store formats.
Retain verification keys for outstanding signed commands: recovery checks the
original signature at acceptance time, even when the current policy has changed.
