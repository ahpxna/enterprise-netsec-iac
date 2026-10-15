#!/usr/bin/env python3
"""Governed promotion of a candidate model into an approved registry directory.

``promote`` re-derives every claim instead of trusting the candidate:

* the artifact bytes match the provenance digest and size;
* ``evaluation.json`` is bound to that exact artifact, feature contract, dataset
  manifest, labels and test/validation vectors, and agrees with ``metadata.json``;
* the frozen test metrics clear the reviewed promotion policy.

It writes a NEW directory containing ``status: approved`` metadata and prints the
metadata SHA-256.  That digest is the deployment approval: the inference service
refuses a registry whose metadata does not hash to the value supplied
independently through ``SOC_AI_METADATA_SHA256``.  Editing a candidate's status by
hand therefore cannot authorise loading.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import shutil
from typing import Any, Mapping

import yaml

from ai.features.contracts import feature_schema_sha256, sha256_file
from ai.models.isolation_forest import ARTIFACT_BY_ALGORITHM, ModelProvenanceError, _validate_provenance
from ai.training.pipeline import METRIC_FIELDS, REPOSITORY_ROOT

DEFAULT_POLICY = Path(__file__).with_name("promotion-policy.yaml")
CARRIED_FILES = ("feature_schema.json", "evaluation.json", "metrics.json", "benchmark.json", "benchmark.md")
COMPARISON_FILES = ("comparison.json", "comparison.md")


def _load(path: Path) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ModelProvenanceError(f"cannot read {path.name}") from exc
    if not isinstance(payload, Mapping):
        raise ModelProvenanceError(f"{path.name} must contain an object")
    return payload


def load_policy(path: Path) -> tuple[Mapping[str, Any], str]:
    raw = Path(path).read_bytes()
    policy = yaml.safe_load(raw)
    if not isinstance(policy, Mapping) or policy.get("schema_version") != "promotion-policy-v1":
        raise ModelProvenanceError("promotion policy must be promotion-policy-v1")
    if set(policy.get("minimum", {})) != {"precision", "recall", "f1", "scenario_detection_ratio"}:
        raise ModelProvenanceError("promotion policy minimum bounds are incomplete")
    if set(policy.get("maximum", {})) != {"false_positives_per_hour", "p95_inference_ms"}:
        raise ModelProvenanceError("promotion policy maximum bounds are incomplete")
    return policy, sha256(raw).hexdigest()


def verify_candidate(candidate: Path, policy: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    metadata = _load(candidate / "metadata.json")
    binding = _load(candidate / "evaluation.json")
    _validate_provenance(metadata, REPOSITORY_ROOT)
    if metadata["status"] != "candidate":
        raise ModelProvenanceError("only a candidate can be promoted")
    algorithm = metadata["algorithm"]
    if algorithm not in ARTIFACT_BY_ALGORITHM:
        raise ModelProvenanceError("unsupported model algorithm")
    artifact = metadata["artifact"]
    expected_format, expected_name = ARTIFACT_BY_ALGORITHM[algorithm]
    if artifact["format"] != expected_format or artifact["path"] != expected_name:
        raise ModelProvenanceError("artifact does not match its algorithm's registry layout")
    artifact_path = candidate / expected_name
    if not artifact_path.is_file() or sha256_file(artifact_path) != artifact["sha256"]:
        raise ModelProvenanceError("artifact digest does not match provenance")
    if artifact_path.stat().st_size != artifact["size_bytes"]:
        raise ModelProvenanceError("artifact size does not match provenance")
    schema_id = metadata["feature_schema"]["id"]
    if metadata["feature_schema"]["sha256"] != feature_schema_sha256(schema_id, REPOSITORY_ROOT):
        raise ModelProvenanceError("feature schema digest differs from the repository contract")

    # --- evaluation must be bound to this exact artifact and dataset
    if binding.get("schema_version") != "evaluation-binding-v1":
        raise ModelProvenanceError("evaluation.json must be evaluation-binding-v1")
    for field, actual in (
        ("model_sha256", artifact["sha256"]),
        ("feature_schema_sha256", metadata["feature_schema"]["sha256"]),
        ("dataset_manifest_sha256", metadata["dataset"]["manifest_sha256"]),
    ):
        if binding.get(field) != actual:
            raise ModelProvenanceError(f"evaluation is not bound to this candidate ({field})")
    if binding.get("threshold") != metadata["threshold"]:
        raise ModelProvenanceError("evaluation threshold differs from provenance")
    test = binding.get("test_metrics", {})
    for name in METRIC_FIELDS:
        if test.get(name) != metadata["evaluation"][name]:
            raise ModelProvenanceError(f"provenance metric {name} differs from the bound evaluation")
    if binding.get("threshold_policy", {}).get("selected_on") != "validation":
        raise ModelProvenanceError("threshold must have been selected on the validation partition")

    # --- reviewed policy
    minimum, maximum = policy["minimum"], policy["maximum"]
    total = test.get("scenarios_total") or 0
    ratio = (test.get("scenarios_detected", 0) / total) if total else 0.0
    failures = []
    for name in ("precision", "recall", "f1"):
        if test[name] < minimum[name]:
            failures.append(f"{name} {test[name]:.3f} < {minimum[name]}")
    if ratio < minimum["scenario_detection_ratio"]:
        failures.append(f"scenario detection ratio {ratio:.3f} < {minimum['scenario_detection_ratio']}")
    for name in ("false_positives_per_hour", "p95_inference_ms"):
        if test[name] > maximum[name]:
            failures.append(f"{name} {test[name]:.3f} > {maximum[name]}")
    if failures:
        raise ModelProvenanceError("promotion policy not satisfied: " + "; ".join(failures))
    return metadata, binding


def _write_registry(source: Path, output: Path, metadata: Mapping[str, Any], names: tuple[str, ...]) -> str:
    if output.exists() and any(output.iterdir()):
        raise ModelProvenanceError("output directory must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    for name in names:
        if (source / name).is_file():
            shutil.copy2(source / name, output / name)
    body = (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8")
    (output / "metadata.json").write_bytes(body)
    return sha256(body).hexdigest()


def verify_comparison(directory: Path, metadata: Mapping[str, Any]) -> None:
    """A carried comparison must be the five-detector report over THIS model and dataset."""

    report = _load(directory / "comparison.json")
    if report.get("schema_version") != "benchmark-comparison-v1":
        raise ModelProvenanceError("comparison.json must be benchmark-comparison-v1")
    if report.get("dataset_manifest_sha256") != metadata["dataset"]["manifest_sha256"]:
        raise ModelProvenanceError("comparison was computed on a different dataset")
    if metadata["artifact"]["sha256"] not in {m["model_sha256"] for m in report.get("models", {}).values()}:
        raise ModelProvenanceError("comparison does not include the promoted model artifact")
    if [row.get("detector") for row in report.get("rows", [])] != [
        "static-rules", "isolation-forest", "static+isolation-forest", "lstm-autoencoder", "static+lstm-autoencoder",
    ]:
        raise ModelProvenanceError("comparison must cover the five protocol detectors")


def promote(candidate: Path, output: Path, *, approver: str, policy_path: Path = DEFAULT_POLICY,
            note: str = "", now: datetime | None = None, comparison: Path | None = None) -> dict[str, str]:
    if not approver.strip():
        raise ModelProvenanceError("an approver identity is required")
    policy, policy_digest = load_policy(policy_path)
    metadata, _ = verify_candidate(Path(candidate), policy)
    if comparison is not None:
        verify_comparison(Path(comparison), metadata)
    approved = dict(metadata)
    approved["status"] = "approved"
    names = (metadata["artifact"]["path"], *CARRIED_FILES)
    digest = _write_registry(Path(candidate), Path(output), approved, names)
    if comparison is not None:
        for name in ("comparison.json", "comparison.md"):
            shutil.copy2(Path(comparison) / name, Path(output) / name)
    _validate_provenance(json.loads((Path(output) / "metadata.json").read_text()), REPOSITORY_ROOT)
    approval = {
        "approver": approver.strip(),
        "approved_at": (now or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z"),
        "model_id": metadata["model_id"],
        "metadata_sha256": digest,
        "policy_sha256": policy_digest,
        "candidate_metadata_sha256": sha256_file(Path(candidate) / "metadata.json"),
        "note": note,
    }
    (Path(output) / "approval.json").write_text(json.dumps(approval, indent=2, sort_keys=True) + "\n")
    return {"metadata_sha256": digest, "policy_sha256": policy_digest}


def retire(active: Path, output: Path, *, status: str, reason: str) -> str:
    """Write ``retired`` / ``revoked`` metadata so the loader refuses the model."""

    if status not in {"retired", "revoked"} or not reason.strip():
        raise ModelProvenanceError("status must be retired or revoked and a reason is required")
    metadata = dict(_load(Path(active) / "metadata.json"))
    _validate_provenance(metadata, REPOSITORY_ROOT)
    metadata["status"] = status
    names = (metadata["artifact"]["path"], *CARRIED_FILES, *COMPARISON_FILES, "approval.json")
    digest = _write_registry(Path(active), Path(output), metadata, names)
    (Path(output) / "retirement.json").write_text(json.dumps({"status": status, "reason": reason}) + "\n")
    return digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    up = commands.add_parser("promote")
    up.add_argument("candidate", type=Path)
    up.add_argument("--output-dir", type=Path, required=True)
    up.add_argument("--approver", required=True)
    up.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    up.add_argument("--note", default="")
    up.add_argument("--comparison", type=Path, help="directory written by ai.evaluation.compare (five-detector report)")
    down = commands.add_parser("retire")
    down.add_argument("active", type=Path)
    down.add_argument("--output-dir", type=Path, required=True)
    down.add_argument("--status", choices=("retired", "revoked"), required=True)
    down.add_argument("--reason", required=True)
    args = parser.parse_args()
    try:
        if args.command == "promote":
            result = promote(args.candidate, args.output_dir, approver=args.approver,
                             policy_path=args.policy, note=args.note, comparison=args.comparison)
            print(json.dumps(result, indent=2))
            print("Provide metadata_sha256 to the deployment as SOC_AI_METADATA_SHA256 through an "
                  "independent channel; do not store it next to the registry.")
        else:
            print(json.dumps({"metadata_sha256": retire(
                args.active, args.output_dir, status=args.status, reason=args.reason)}))
    except ModelProvenanceError as exc:
        raise SystemExit(f"refused: {exc}") from exc
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
