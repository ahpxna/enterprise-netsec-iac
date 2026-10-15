# Resume checkpoint — 2026-10-08

Branch: `soc-ai`. Changes are uncommitted. This checkpoint replaces the 2026-09-07 one (which
listed the service, response-transport, Kubernetes and live-verifier work as unfinished).

## What exists now (source + offline tests)

| Area | State |
|---|---|
| Analytics plane (Compose) | TLS ELK profile, ingestion/normalization pipelines, raw create-only output, DLQ, ILM/templates, four dashboards |
| Analytics plane (Kubernetes) | Elasticsearch StatefulSet, Kibana, bootstrap/setup Jobs, Logstash sidecars on the Wazuh manager and every Suricata pod |
| AI plane | continuous feature worker, ES-pull enrichment outbox, mTLS inference API, Isolation Forest **and** LSTM autoencoder, artifact-bound evaluation, five-detector comparison, governed promotion, leakage-safe dataset builder |
| Response plane | Ed25519-signed commands, decision runner, orchestrator service (durable journal, recovery, TTL sweep, audit export), nftables / VyOS / OPNsense blocklist backends with an ownership ledger, Wazuh Active Response isolation verified by a FIM marker |
| Network configs | `soc_blocklist` sets and early drops in `fw-core`/`fw-dmz` (nftables) and the VyOS boot configs; three-operation mTLS enforcement agent; VyOS response-API role; rewritten `wazuh_agent` role |
| Path C | per-workload Secrets and NetworkPolicies, model loader Pod, `make k8s-soc-image` / `k8s-soc-model`, extended `k8s-smoke`, offline schema validation (Kubernetes 1.30, strict) |
| Compliance | 14 SOC controls promoted to evidence-backed with shared live verifiers; `applicable_profiles` scoping (RESP-02 is Path B only); RESP-04 remains planned |
| Safety defaults | `mode: observe`; `SOC_MODE` override only for validation; protected targets; rate limit; TTL; mTLS everywhere; one Secret/volume per workload |

## Local validation (this checkpoint)

- Isolated Python 3.12 environment; `pytest tests/unit tests/soc`: **305 passed**,
  one upstream Starlette/AnyIO deprecation warning. No live device is contacted.
- Passing: `check_soc_static`, `check_soc_ai_static` (with mutation tests), `security_static_checks`,
  `check_ci_contract`, `check_image_lock`, `check_yaml_syntax`, `check_k8s_schema` (72 documents, strict),
  `render_fabric/batfish/k8s_assets --check`, `check_path_b_intent`, `check_vyos_boot`, `compliance/check_wiring`
  (27 controls; 1 scoped to a single profile), `compileall`, `git diff --check`.
- Not runnable here: Batfish tests (needs `pybatfish` and the Batfish service), `check_wazuh_pki` (needs
  generated PKI), `ansible-lint`/`yamllint`/Terraform, Docker builds (registry unreachable from this host).
- `test_architecture_contracts.py::test_ai_cannot_bypass_decision_orchestrator_boundary` no longer fails on a macOS
  `.DS_Store`: that one OS-metadata name is skipped and binary artifacts are decoded leniently; every other file under `ai/`
  is still scanned (verified: a planted forbidden token in a `.py` or binary file is still caught).

## Not verified anywhere (live evidence outstanding)

1. Docker image build and every Compose/containerlab/VyOS/Kubernetes runtime behaviour.
2. Logstash pipelines on real input; the VyOS and Wazuh API contracts against real software; FIM-marker latency.
3. All SOC controls: LOG-01..03, AI-01..04, COR-01, RESP-01..03, SOC-01..03 are `UNVERIFIED` until
   `make soc-ai-validate` (Path A) and `make vm-audit` (Path B) have produced evidence; Path C needs `make k8s-smoke`.
4. A real trained model: none ships; AI-04 needs a captured dataset and a promoted registry carrying `comparison.json`.

## Not implemented

- Network-fidelity gate: OPNsense HA/CARP, Core L3/SPAN, VLAN 30/40/50/99 (RESP-04 stays planned).
- Endpoint isolation in Path C (Wazuh API certificate SAN), adversarial and false-positive experiments.

## Operator next steps

`make secrets` → `make soc-up` → train/promote a model (`ai/training/README.md`) → set `SOC_AI_METADATA_SHA256`
and `SOC_GIT_SHA` in `.env` → `make soc-ai-preflight && make soc-ai-up` (observe mode) → review alerts →
`make soc-ai-validate` / `make vm-audit` for evidence. See `RUNBOOK.md`.
