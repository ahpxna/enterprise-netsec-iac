#!/usr/bin/env python3
"""Render Kubernetes-local assets from canonical Docker-side source files.

Kustomize's default LoadRestrictionsRootOnly rejects ../docker/... references.
Most files are mirrored byte-for-byte. Wazuh endpoint names are adapted from
Compose DNS (wazuh.indexer / wazuh.manager) to Kubernetes Service DNS
(wazuh-indexer / wazuh-manager) while retaining the Docker files as canonical.
CI rejects drift in every generated derivative.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

MAPPINGS = {
    ROOT / "docker/siem/decoders/cxyz_decoders.xml": ROOT / "k8s/generated/cxyz_decoders.xml",
    ROOT / "docker/siem/rules/cxyz_rules.xml": ROOT / "k8s/generated/cxyz_rules.xml",
    ROOT / "docker/ids/suricata.yaml": ROOT / "k8s/generated/suricata.yaml",
    ROOT / "docker/ids/rules/cxyz.rules": ROOT / "k8s/generated/cxyz.rules",
    ROOT / "docker/authentik/blueprints/cxyz-ztna.yaml": ROOT / "k8s/generated/cxyz-ztna.yaml",
    ROOT / "docker/siem/ossec.conf": ROOT / "k8s/generated/ossec.conf",
    ROOT / "docker/wazuh/indexer.yml": ROOT / "k8s/generated/wazuh-indexer.yml",
    ROOT / "docker/wazuh/opensearch_dashboards.yml": ROOT / "k8s/generated/opensearch_dashboards.yml",
}


def rendered_content(source: pathlib.Path) -> bytes:
    content = source.read_bytes()
    if source.name in {"opensearch_dashboards.yml", "ossec.conf"}:
        content = content.replace(b"https://wazuh.indexer:9200", b"https://wazuh-indexer:9200")
    if source.name == "ossec.conf":
        # Suricata reaches the Kubernetes manager through its Wazuh-agent
        # sidecar; those Path A host-file collectors are not mounted in Path C.
        for location in (b"/var/log/suricata/eve.json", b"/var/log/cxyz/remote.log"):
            content = re.sub(
                rb"\s*<localfile>.*?<location>" + re.escape(location) + rb"</location>.*?</localfile>",
                b"",
                content,
                flags=re.DOTALL,
            )
    return content


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    stale: list[str] = []
    for source, destination in MAPPINGS.items():
        content = rendered_content(source)
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
        print("OK: Kubernetes generated assets match canonical Docker config + K8s DNS adaptations")
    else:
        print("rendered Kubernetes-local IDS/SIEM/Auth assets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
