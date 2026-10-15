# AI model registry

Model binaries are not trusted merely because they exist. Every promoted model has a
provenance record conforming to `schemas/events/model-provenance-v1.schema.json`:
artifact and dataset hashes, feature-contract hash, Git revision, seed, hyperparameters,
threshold, temporal partitions, and non-accuracy evaluation metrics.

The active registry directory (`ai/registry/active`, generated and ignored by Git)
contains:

```text
model.joblib | model.safetensors   # exactly one, named by the algorithm
metadata.json                      # model-provenance-v1, status: approved
approval.json                      # approver, policy digest, candidate digest, metadata digest
evaluation.json                    # evaluation-binding-v1: bound to this exact artifact
metrics.json  benchmark.json  benchmark.md
feature_schema.json                # copy of the repository contract, digest-checked
comparison.json  comparison.md     # optional: five-detector comparison (ai.evaluation.compare)
```

Training writes `status: candidate`; the inference loader rejects every status other than
`approved`. `python -m ai.training.promote promote` re-derives every claim (artifact hash,
binding to dataset/labels/vectors, metrics against the reviewed policy) and writes a *new*
directory with `approved` metadata and its SHA-256. That digest is the deployment approval:
hand it to the deployment as `SOC_AI_METADATA_SHA256` through a channel that is not the
registry. Editing `status` to `approved` by hand therefore cannot authorise loading.
`retire` writes a `retired`/`revoked` registry that the loader refuses.

Mount the registry read-only at runtime (Compose bind mount, Kubernetes PVC loaded once by
`make k8s-soc-model`, which re-verifies provenance inside the cluster before consumers see it).
