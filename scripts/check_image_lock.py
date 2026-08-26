#!/usr/bin/env python3
"""Fail closed if external container image usage drifts from the audited lock.

This check is intentionally offline. Registry resolution lives in
``verify_image_platforms.py`` so PR CI does not depend on external registries.
"""
from __future__ import annotations

import pathlib
import re
import sys
from collections import defaultdict
from typing import Iterable

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOCK_PATH = ROOT / "supply-chain/images.lock.yml"
DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
ERRORS: list[str] = []


def fail(message: str) -> None:
    ERRORS.append(message)


def load_lock() -> dict:
    data = yaml.safe_load(LOCK_PATH.read_text())
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise SystemExit("image lock: unsupported or missing schema_version")
    if not isinstance(data.get("images"), dict):
        raise SystemExit("image lock: images mapping is missing")
    return data


def yaml_images(path: pathlib.Path) -> list[str]:
    refs: list[str] = []
    for document in yaml.safe_load_all(path.read_text()):
        if not isinstance(document, (dict, list)):
            continue
        stack = [document]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                image = value.get("image")
                if isinstance(image, str):
                    refs.append(image)
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
    return refs


def dockerfile_images(path: pathlib.Path) -> list[str]:
    refs: list[str] = []
    for line in path.read_text().splitlines():
        match = re.match(r"\s*FROM(?:\s+--platform=\S+)?\s+(\S+)", line, re.I)
        if match:
            ref = match.group(1)
            if not ref.startswith("${"):
                refs.append(ref)
    return refs


def source_files() -> list[pathlib.Path]:
    paths = [
        ROOT / "docker-compose.yml",
        ROOT / "clab/companyxyz.clab.yml",
        ROOT / "docker/wazuh/generate-indexer-certs.yml",
        ROOT / ".github/workflows/netdevops-ci.yml",
        ROOT / "scripts/render_wazuh_users.sh",
        ROOT / "scripts/dev_check.sh",
        ROOT / "scripts/render_fabric.py",
    ]
    paths.extend(sorted((ROOT / "k8s").glob("*.yaml")))
    paths.extend(sorted((ROOT / "k8s").glob("*.yml")))
    paths.extend(sorted((ROOT / "docker").glob("*/Dockerfile")))
    return paths


def configured_refs(paths: Iterable[pathlib.Path]) -> dict[str, set[str]]:
    """Return exact image refs found in structured/runtime source locations."""
    found: dict[str, set[str]] = defaultdict(set)
    for path in paths:
        rel = str(path.relative_to(ROOT))
        if path.name == "Dockerfile":
            refs = dockerfile_images(path)
        elif path.suffix in {".yml", ".yaml"}:
            refs = yaml_images(path)
        else:
            body = path.read_text()
            refs = []
            # Explicit shell/workflow image-bearing forms used by this repo.
            refs.extend(re.findall(r"TF_IMAGE=\"\$\{TF_IMAGE:-([^}]+)\}\"", body))
            refs.extend(re.findall(r"docker\s+run(?:\s+[^\n]+?\s)([A-Za-z0-9][A-Za-z0-9._/-]*(?::[^\s\\]+|@sha256:[0-9a-f]{64}))(?=\s|\\|$)", body))
            # docker-run lines can span lines; known digest/tag refs are also
            # discovered below from the lock, so this regex is only additive.
        for ref in refs:
            found[ref].add(rel)
    return found


def is_local(ref: str, prefixes: list[str]) -> bool:
    return any(ref.startswith(prefix) for prefix in prefixes)


def main() -> int:
    lock = load_lock()
    images: dict[str, dict] = lock["images"]
    policy = lock.get("policy", {})
    portable_required = set(policy.get("portable_runtime_required_platforms", []))
    path_a_required = set(policy.get("path_a_required_platforms", []))
    ci_required = set(policy.get("ci_required_platforms", []))
    local_prefixes = list(policy.get("local_image_prefixes", []))
    paths = source_files()
    texts = {str(path.relative_to(ROOT)): path.read_text() for path in paths}
    all_text = "\n".join(texts.values())
    found = configured_refs(paths)

    # Structured image fields/FROM instructions may not silently introduce an
    # external image that is absent from the lock.
    known_refs: set[str] = set()
    for entry in images.values():
        for key in ("intent_ref", "pinned_ref"):
            value = entry.get(key)
            if value:
                known_refs.add(str(value))
    for ref, locations in sorted(found.items()):
        if is_local(ref, local_prefixes):
            continue
        if ref not in known_refs:
            fail(f"unlocked external image {ref} in {', '.join(sorted(locations))}")

    seen_repository_keys: dict[str, str] = {}
    for name, entry in images.items():
        status = entry.get("status")
        intent = entry.get("intent_ref")
        pinned = entry.get("pinned_ref")
        scopes = entry.get("scopes") or []
        platforms = set(entry.get("required_platforms") or [])
        verification = entry.get("verification") or {}
        verification_kind = verification.get("kind")

        if status not in {"verified", "deferred", "inherited-pinned"}:
            fail(f"{name}: invalid status {status!r}")
            continue
        if not isinstance(intent, str) or not intent:
            fail(f"{name}: intent_ref is required")
            continue
        if not scopes:
            fail(f"{name}: scopes must not be empty")
        if not platforms:
            fail(f"{name}: required_platforms must not be empty")
        if any(scope in {"compose", "kubernetes", "dockerfile", "compose-helper", "developer-tool"} for scope in scopes):
            if not portable_required.issubset(platforms):
                fail(f"{name}: portable runtime/developer image must cover {sorted(portable_required)}")
        if "containerlab" in scopes and not path_a_required.issubset(platforms):
            fail(f"{name}: Path A containerlab image must cover {sorted(path_a_required)}")
        if "ci" in scopes and not ci_required.issubset(platforms):
            fail(f"{name}: CI image must cover {sorted(ci_required)}")
        if verification_kind == "single-platform-manifest" and len(platforms) != 1:
            fail(f"{name}: single-platform manifest must declare exactly one required platform")
        if verification_kind == "multi-platform-index" and len(platforms) < 2:
            fail(f"{name}: multi-platform index must declare at least two required platforms")

        if status in {"verified", "inherited-pinned"}:
            if not isinstance(pinned, str) or not DIGEST_RE.search(pinned):
                fail(f"{name}: {status} entry requires an immutable sha256 pinned_ref")
            else:
                if pinned not in all_text:
                    fail(f"{name}: pinned_ref is not used by any audited source file")
            if status == "verified" and intent in all_text:
                fail(f"{name}: mutable intent_ref remains in audited source: {intent}")
            if not verification.get("level"):
                fail(f"{name}: pinned entry lacks verification metadata")
        else:
            if pinned is not None:
                fail(f"{name}: deferred entry must keep pinned_ref null until resolved")
            if intent not in all_text:
                fail(f"{name}: deferred intent_ref is no longer used; update the lock: {intent}")
            if not str(entry.get("reason", "")).strip():
                fail(f"{name}: deferred entry requires a reason")

        # One logical repository/component name should not be represented by
        # conflicting lock entries. Strip tag/digest to compare repository key.
        repo_key = re.split(r"@sha256:|:(?=[^/]+$)", intent, maxsplit=1)[0]
        previous = seen_repository_keys.get(repo_key)
        if previous and previous != name:
            fail(f"duplicate logical repository in image lock: {repo_key} ({previous}, {name})")
        seen_repository_keys[repo_key] = name

    # Known shell-only refs are easy to accidentally lose from structured
    # discovery, so explicitly ensure their lock coverage stays active.
    developer_ref = images.get("terraform-dev-image", {}).get("pinned_ref")
    if developer_ref and developer_ref not in all_text:
        fail(f"expected developer image reference disappeared: {developer_ref}")

    if ERRORS:
        print("image lock check FAILED:", file=sys.stderr)
        for error in ERRORS:
            print(f" - {error}", file=sys.stderr)
        return 1

    pinned_count = sum(1 for item in images.values() if item.get("status") in {"verified", "inherited-pinned"})
    deferred_count = sum(1 for item in images.values() if item.get("status") == "deferred")
    print(f"OK: image lock covers {len(images)} external image components ({pinned_count} pinned, {deferred_count} deferred)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
