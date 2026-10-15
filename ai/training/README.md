# Training and promotion

Everything here writes artifacts under an output directory that must be absent or empty and
that belongs outside Git (`ai/registry/` is ignored). Nothing trains or promotes at import time.

## 1. Capture and build a leakage-safe dataset

```bash
python -m soc.workers.export_events --schema network-window-v1 \
    --start 2026-09-01T00:00:00Z --end 2026-09-04T00:00:00Z --output capture.jsonl
python -m ai.training.build_dataset capture.jsonl --scenarios scenarios.json \
    --schema network-window-v1 --dataset-id lab-001 \
    --start ... --train-end ... --validation-end ... --test-end ... \
    --git-sha "$(git rev-parse HEAD)" --sources suricata firewall wazuh --output-dir dataset/
```

`scenarios.json` (`scenarios-v1`) lists the controlled attacks that were actually run (id,
entity, start, end). The builder writes `train/validation/test.jsonl`, `labels.jsonl`
(`labels-v1`, bound to vectors by canonical hash), `session-assignments.json` (per-vector
source/session ledger, `partition-membership-v1`) and `dataset-manifest.yaml`
(`dataset-manifest-v1`, binds every file digest). The split is temporal and session-isolated:
the training partition is benign only, and a scenario that straddles a partition boundary is
refused because it would leak a session across partitions. Stable source/session identifiers must
come from collection/replay evidence; inventing new IDs for a repeated attack defeats the check.

## 2. Train a candidate

```bash
python -m ai.training.train_isolation_forest  --train-vectors ... --validation-vectors ... \
    --test-vectors ... --session-assignments ... --dataset-manifest ... --labels ... \
    --feature-schema network-window-v1 --model-id if-1 --random-seed 7 --git-sha ... \
    --runtime-image-digest sha256:... --library-lock-sha256 ... --output-dir cand-if/
python -m ai.training.train_lstm_autoencoder  <same arguments> --sequence-length 6   # needs requirements-soc-lstm.txt
```

`load_dataset` re-validates the whole dataset first (manifest schema, partition order, vector
hashes, session isolation, label digest, benign-only training, attack presence in validation and
test). The operating threshold is chosen **on validation only**, under an analyst false-positive
budget (`--max-false-positives-per-hour`); the frozen test partition is scored once. The candidate
directory contains the artifact, `metadata.json` (`status: candidate`), `evaluation.json`
(`evaluation-binding-v1`) and the benchmark. Training is deterministic for a fixed seed (the
safetensors header is canonicalised so the digest is byte-reproducible).

## 3. Compare detectors and promote

```bash
python -m ai.evaluation.compare <dataset arguments> --isolation-forest-candidate cand-if/ \
    --lstm-candidate cand-lstm/ --output-dir cmp/
python -m ai.training.promote promote cand-if/ --output-dir ai/registry/active \
    --approver "<reviewer>" --comparison cmp/
```

`promote` checks the artifact digest, the binding to dataset/labels/vectors, agreement between
`metadata.json` and `evaluation.json`, and the frozen *test* metrics against
[`promotion-policy.yaml`](promotion-policy.yaml) (precision/recall/F1/scenario detection floors,
false-positive and p95-latency ceilings). Floors are research decisions: change them only through
review, because the policy digest is recorded in every approval. A carried `--comparison` must be
the five-detector report over the same dataset and must include the promoted artifact.
The printed `metadata_sha256` is the deployment approval (`SOC_AI_METADATA_SHA256`).
