#!/usr/bin/env python3
"""Keep Kustomize inputs inside k8s/ without duplicating their source of truth.

Kustomize's default LoadRestrictionsRootOnly rejects ../docker/... file
references.  Docker-side IDS/SIEM config remains canonical; this script mirrors
only the files Kustomize needs and CI rejects drift.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAPPINGS = {
    ROOT / "docker/siem/decoders/cxyz_decoders.xml": ROOT / "k8s/generated/cxyz_decoders.xml",
    ROOT / "docker/siem/rules/cxyz_rules.xml": ROOT / "k8s/generated/cxyz_rules.xml",
    ROOT / "docker/ids/suricata.yaml": ROOT / "k8s/generated/suricata.yaml",
    ROOT / "docker/ids/rules/cxyz.rules": ROOT / "k8s/generated/cxyz.rules",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    stale: list[str] = []
    for source, destination in MAPPINGS.items():
        content = source.read_bytes()
        if args.check:
            if not destination.exists() or destination.read_bytes() != content:
                stale.append(str(destination.relative_to(ROOT)))
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)

    if stale:
        print("Kubernetes generated assets are stale:", file=sys.stderr)
        for path in stale:
            print(f" - {path}", file=sys.stderr)
        print("run: python scripts/render_k8s_assets.py", file=sys.stderr)
        return 1
    if args.check:
        print("OK: Kubernetes generated assets match canonical Docker IDS/SIEM config")
    else:
        print("rendered Kubernetes-local IDS/SIEM assets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
