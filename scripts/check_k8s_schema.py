#!/usr/bin/env python3
"""Validate the rendered Kustomize output against the Kubernetes API schemas, offline.

``kubectl kustomize`` only proves the overlay assembles; it accepts a Deployment with a
misspelled field.  This renders ``k8s/`` and validates every document strictly (unknown
fields are errors) against the bundled schemas of a pinned Kubernetes minor version, with
no cluster and no network.  The ignored runtime Secrets/ConfigMaps are not part of the
Kustomize output and are validated by their renderers.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
KUBERNETES_VERSION = "1.30"


def main() -> int:
    try:
        import kubernetes_validate
    except ImportError:
        print("kubernetes-validate is required: python -m pip install -r requirements-ci.txt", file=sys.stderr)
        return 2
    tool = shutil.which("kubectl")
    if tool is None:
        print("kubectl is required to render the Kustomize overlay", file=sys.stderr)
        return 2
    rendered = subprocess.run([tool, "kustomize", "k8s/"], cwd=ROOT, capture_output=True, text=True, check=False)
    if rendered.returncode != 0:
        print(rendered.stderr.strip(), file=sys.stderr)
        return 1
    documents = [d for d in yaml.safe_load_all(rendered.stdout) if d]
    failures = []
    for document in documents:
        label = f"{document.get('kind')}/{document.get('metadata', {}).get('name')}"
        try:
            kubernetes_validate.validate(document, KUBERNETES_VERSION, strict=True)
        except kubernetes_validate.ValidationError as exc:
            failures.append(f"{label}: {str(exc).splitlines()[0][:300]}")
        except kubernetes_validate.SchemaNotFoundError as exc:
            failures.append(f"{label}: no schema ({exc})")
    if failures:
        print("Kubernetes schema validation FAILED:", file=sys.stderr)
        print("\n".join(f" - {item}" for item in failures), file=sys.stderr)
        return 1
    print(f"OK: {len(documents)} rendered Kubernetes documents satisfy the v{KUBERNETES_VERSION} API schemas (strict)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
