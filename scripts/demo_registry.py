#!/usr/bin/env python3
"""Build a DEMO approved model registry from deterministic synthetic telemetry.

The AI/response services refuse to start without an approved model, and a real one needs days of
captured telemetry plus controlled attacks.  This tool lets a lab bring the *whole loop* up in a few
minutes: it generates the repository's synthetic dataset, trains an Isolation Forest candidate,
promotes it through the same governed gate as a real model (with deliberately relaxed floors) and
writes ``ai/registry/active``.

What this proves: the wiring (provenance, digest binding, inference API, enrichment, decision,
response).  What it does NOT prove: any detection quality.  The metrics are an artifact of
synthetic data; the approval note and model id say so, and nothing here may be cited as a result.
Use ``python -m ai.training.promote`` with real data for anything that matters.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from hashlib import sha256

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests" / "soc")]

NOTE = "DEMO registry built from synthetic data by scripts/demo_registry.py: proves wiring only, not detection quality."
RELAXED_FLOOR = 0.2


def git_sha() -> str:
    done = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False)
    value = done.stdout.strip()
    return value if done.returncode == 0 and len(value) >= 7 else "0123456789abcdef0123456789abcdef01234567"


def update_env(env_file: pathlib.Path, values: dict[str, str]) -> None:
    """Set KEY=value lines in a dotenv file, preserving everything else and the file mode."""

    lines = env_file.read_text(encoding="utf-8").splitlines() if env_file.is_file() else []
    remaining = dict(values)
    out = []
    for line in lines:
        key = line.partition("=")[0].strip()
        if key in remaining and not line.lstrip().startswith("#"):
            out.append(f"{key}={remaining.pop(key)}")
        else:
            out.append(line)
    out.extend(f"{key}={value}" for key, value in remaining.items())
    mode = env_file.stat().st_mode & 0o777 if env_file.is_file() else 0o600
    temporary = env_file.with_name(env_file.name + ".tmp")
    temporary.write_text("\n".join(out) + "\n", encoding="utf-8")
    os.chmod(temporary, mode)
    temporary.replace(env_file)


def build(output: pathlib.Path, *, with_lstm: bool, seed: int, work: pathlib.Path) -> dict[str, str]:
    import argparse as _argparse

    import synthetic_soc as synthetic
    from ai.training import promote as promotion
    from ai.training.build_dataset import build as build_dataset, load_scenarios, write_dataset
    from ai.training.train_isolation_forest import train as train_forest

    sha = git_sha()
    scenarios = work / "scenarios.json"
    scenarios.write_text(json.dumps(synthetic.scenario_file_payload()))
    result = build_dataset(events=synthetic.generate_events(), scenarios=load_scenarios(scenarios), schema="network-window-v1",
                           boundaries=synthetic.boundaries(), git_sha=sha)
    dataset = work / "dataset"
    write_dataset(result, output_dir=dataset, dataset_id="demo-synthetic-001", schema="network-window-v1",
                  boundaries=synthetic.boundaries(), git_sha=sha, sources=["suricata", "opnsense"], events_sha256="c" * 64,
                  collector_config_sha256="d" * 64, normalization_schema_sha256="e" * 64, raw_data_location_class="local_ignored",
                  created_at=datetime(2026, 9, 1, tzinfo=timezone.utc), repository_root=ROOT)
    lock = ROOT / "requirements-soc-service.lock"
    common = dict(git_sha=sha, runtime_image_digest="sha256:" + "0" * 64,
                  library_lock_sha256=sha256(lock.read_bytes()).hexdigest() if lock.is_file() else "b" * 64)
    forest = train_forest(synthetic.training_arguments(dataset, work / "forest", model_id="demo-synthetic-if-1", random_seed=seed,
                                                       max_false_positives_per_hour=1.0, **common))
    comparison = None
    if with_lstm:
        from ai.evaluation.compare import compare
        from ai.training.train_lstm_autoencoder import train as train_lstm

        args = synthetic.training_arguments(dataset, work / "lstm", model_id="demo-synthetic-lstm-1", random_seed=seed, **common)
        args.sequence_length, args.epochs, args.hidden_size, args.latent_size = 6, 20, 12, 4
        args.learning_rate, args.batch_size = 0.02, 64
        lstm = train_lstm(args)
        base = synthetic.training_arguments(dataset, work / "cmp")
        names = ("train_vectors", "validation_vectors", "test_vectors", "session_assignments", "dataset_manifest", "labels", "feature_schema")
        comparison = compare(_argparse.Namespace(**{n: getattr(base, n) for n in names}, isolation_forest_candidate=forest,
                                                 lstm_candidate=lstm, output_dir=work / "cmp", max_false_positives_per_hour=1.0))
    policy = yaml.safe_load((ROOT / "ai/training/promotion-policy.yaml").read_text())
    policy["minimum"] = {key: RELAXED_FLOOR for key in policy["minimum"]}
    relaxed = work / "relaxed-policy.yaml"
    relaxed.write_text("# DEMO ONLY: floors relaxed to %s so synthetic data can pass; never use for a real model\n" % RELAXED_FLOOR
                       + yaml.safe_dump(policy))
    return promotion.promote(forest, output, approver="demo-registry (synthetic)", policy_path=relaxed, note=NOTE, comparison=comparison)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "ai" / "registry" / "active")
    parser.add_argument("--with-lstm", action="store_true", help="also train the LSTM and carry the five-detector comparison (needs PyTorch)")
    parser.add_argument("--write-env", action="store_true", help="put SOC_AI_METADATA_SHA256 and SOC_GIT_SHA into the env file")
    parser.add_argument("--env-file", type=pathlib.Path, default=ROOT / ".env")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args(argv)
    if args.output.exists() and any(args.output.iterdir()):
        print(f"refusing to overwrite {args.output}: it is not empty (remove it deliberately if you want a new demo model)", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="cxyz-demo-") as scratch:
        work = pathlib.Path(scratch)
        os.chmod(work, 0o700)
        try:
            result = build(args.output, with_lstm=args.with_lstm, seed=args.seed, work=work)
        except ImportError as exc:
            print(f"missing dependency: {exc}. Install requirements-soc-test.txt (and requirements-soc-lstm.txt for --with-lstm).", file=sys.stderr)
            return 2
    digest = result["metadata_sha256"]
    print(f"demo registry written to {args.output}")
    print(f"SOC_AI_METADATA_SHA256={digest}")
    if args.write_env:
        update_env(args.env_file, {"SOC_AI_METADATA_SHA256": digest, "SOC_GIT_SHA": git_sha()})
        print(f"updated {args.env_file}")
    else:
        print("add that line (and SOC_GIT_SHA=<git rev-parse HEAD>) to .env, or re-run with --write-env")
    print("NOTE: " + NOTE, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
