# ADR 0007 — Run the SOC/AI loop as least-privilege services and prove it with scoped live verifiers

## Status

Accepted. Implemented in source and covered by offline tests; live evidence is produced by
`make soc-ai-validate`, `make vm-audit` and `make k8s-smoke` and is `UNVERIFIED` until those run.

## Context

ADR 0006 fixed the architecture (model output is evidence, correlation gates containment). Turning it into
running services raised questions the architecture did not settle: how a compromised orchestrator is prevented
from forging commands, how a revert avoids removing someone else's block, how automatic response is kept off by
default yet testable, and how SOC controls enter an evidence-first compliance system without being declared
passed from source alone.

## Decision

- **Asymmetric command authentication.** The decision runner holds the only Ed25519 private key; the orchestrator
  and auditors hold public keys in a ring selected by `key_id`. Shared-key HMAC remains a unit-test reference only.
- **Constrained, mutually authenticated backends.** One three-operation nftables agent (mTLS, management network
  only), the VyOS API, the OPNsense API and the Wazuh API, each behind a fixed-set adapter with no rule, alias or
  script surface. An ownership ledger written *before* each side effect guarantees a revert never removes a
  pre-existing or foreign entry. nftables elements also carry a firewall-side timeout as a dead-man backstop.
- **Observe by default.** Both response services ship in `mode: observe`. Enforcement is a reviewed-file change.
  The only override, `SOC_MODE`, lives in the gitignored `.env`, accepts exactly `observe|enforce`, and exists so
  live validation can enable enforcement without dirtying the tracked tree (which strict evidence reports reject).
  Validation overlays differ from their base policy only by a 60 s TTL, enforced by a unit test.
- **One service image, one identity per workload.** All Python services share `cxyz/soc-python` (hash-locked
  dependencies, read-only, uid 10001, no capabilities) but each mounts only its own credential volume or Secret;
  static checks fail the build if that changes or if the AI plane gains a response import path.
- **Model approval is external.** A model loads only when the SHA-256 of its metadata equals a digest supplied
  independently of the registry; promotion re-derives every claim and refuses an evaluation not bound to the
  artifact. Thresholds are chosen on validation only.
- **Live verifiers share one implementation.** `tests/validation/soc_live.py` runs against an abstract `Lab`
  (Docker Compose in the lab, an in-process lab in unit tests). Failures of the control are `FAIL`; unmet
  preconditions are `ERROR`. The injected anomaly that feeds the response scenario is labelled and stands in for
  model output; the model path is verified separately (AI-01).
- **Profile scoping is explicit.** `applicable_profiles` in `controls.yaml` lets a control exist where its subject
  does (endpoint isolation on Path B). A scoped-out profile carries no verifier and is reported as not applicable.

## Consequences

- Fourteen controls (LOG, AI, COR, RESP, SOC) are now evidence-backed; every strict compliance report is incomplete
  until the live runs happen, which is the intended fail-closed behaviour.
- RESP-04 (OPNsense HA / CARP) remains a *planned* control: no lab path contains OPNsense, so the OPNsense backend is
  contract-tested only and the network-fidelity gate (VLAN 30/40/50/99, Core SPAN, real HA pair) is not implemented.
- `make audit` and `make vm-audit` now temporarily switch the lab response services to enforcement and restore observe
  mode afterwards.
- On VyOS expiry rests on the orchestrator TTL sweep and a reboot clears containment; Day-2 refuses to persist it.
- Path C cannot isolate endpoints until the Wazuh API certificate carries the in-cluster name.

## Options rejected

- Letting the AI service call adapters (ADR 0006); a shared HMAC key between decision and orchestrator (a compromised
  orchestrator could forge commands); blind alias deletes on revert; flipping `mode` by editing tracked files for
  validation (dirty-tree evidence is refused); reporting any SOC control from source configuration alone.
