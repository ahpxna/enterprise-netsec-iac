# SOC dataset manifests

This directory contains metadata-only dataset manifests. Raw logs, extracted
feature tables, PCAPs, labels with personal data, and replay artifacts must
remain outside Git in an approved evidence store or ignored local path.

Every manifest follows `schemas/events/dataset-manifest-v1.schema.json` and
records its canonical data hash, source set, temporal/session-isolated split,
feature-contract hash, Git revision, and labeling provenance. The train split
must precede validation, which must precede test; replay/session identifiers
may not span partitions.

`soc-lab-2026-001.example.yaml` is deliberately synthetic metadata only. It
does not identify a real endpoint or expose a raw dataset location.
