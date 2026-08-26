#!/usr/bin/env python3
"""Resolve OCI/Docker image indexes and verify the image lock online.

This command deliberately is *not* part of PR CI: registry availability and
rate limits must not make deterministic source validation flaky. Run it on a
networked developer/release host before accepting image-lock updates.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOCK_PATH = ROOT / "supply-chain/images.lock.yml"
DIGEST_RE = re.compile(r"^Digest:\s*(sha256:[0-9a-f]{64})\s*$", re.M)
PLATFORM_RE = re.compile(r"^\s*Platform:\s*([^\s]+)\s*$", re.M)


def inspect(ref: str) -> tuple[str, set[str], bool]:
    proc = subprocess.run(
        ["docker", "buildx", "imagetools", "inspect", ref],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip() or f"imagetools inspect failed for {ref}")
    match = DIGEST_RE.search(proc.stdout)
    if not match:
        raise RuntimeError(f"could not parse top-level digest for {ref}")
    digest = match.group(1)
    platforms = set(PLATFORM_RE.findall(proc.stdout))

    raw = subprocess.run(
        ["docker", "buildx", "imagetools", "inspect", "--raw", ref],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if raw.returncode:
        raise RuntimeError(raw.stderr.strip() or f"raw inspect failed for {ref}")
    try:
        document = json.loads(raw.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid manifest JSON for {ref}: {exc}") from exc
    is_index = isinstance(document.get("manifests"), list)
    if is_index and not platforms:
        for manifest in document["manifests"]:
            platform = manifest.get("platform") or {}
            os_name = platform.get("os")
            arch = platform.get("architecture")
            variant = platform.get("variant")
            if os_name and arch:
                value = f"{os_name}/{arch}"
                if variant:
                    value += f"/{variant}"
                platforms.add(value)

    # A historical/single-platform image has no child descriptors from which
    # to infer the platform. Ask Buildx for the image config instead of
    # silently treating an unreported platform as verified.
    if not is_index and not platforms:
        config = subprocess.run(
            ["docker", "buildx", "imagetools", "inspect", "--format", "{{json .Image}}", ref],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if config.returncode:
            raise RuntimeError(config.stderr.strip() or f"image-config inspect failed for {ref}")
        try:
            image = json.loads(config.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid image-config JSON for {ref}: {exc}") from exc
        os_name = image.get("os") if isinstance(image, dict) else None
        arch = image.get("architecture") if isinstance(image, dict) else None
        variant = image.get("variant") if isinstance(image, dict) else None
        if os_name and arch:
            value = f"{os_name}/{arch}"
            if variant:
                value += f"/{variant}"
            platforms.add(value)
    return digest, platforms, is_index


def normalized_platforms(values: set[str]) -> set[str]:
    # Treat Docker's arm64/v8 spelling as satisfying linux/arm64.
    result = set(values)
    for value in list(values):
        if value.startswith("linux/arm64/"):
            result.add("linux/arm64")
        if value.startswith("linux/amd64/"):
            result.add("linux/amd64")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true", help="fail while any lock entry remains deferred")
    parser.add_argument("--only", action="append", default=[], help="verify only the named lock entry (repeatable)")
    args = parser.parse_args()

    if shutil.which("docker") is None:
        print("verify-image-platforms: docker is required", file=sys.stderr)
        return 2
    probe = subprocess.run(["docker", "buildx", "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if probe.returncode:
        print("verify-image-platforms: docker buildx is required", file=sys.stderr)
        return 2

    lock = yaml.safe_load(LOCK_PATH.read_text())
    entries: dict[str, dict] = lock["images"]
    failures: list[str] = []
    deferred_resolved: list[str] = []

    for name, entry in entries.items():
        if args.only and name not in args.only:
            continue
        status = entry["status"]
        if status == "inherited-pinned":
            ref = entry["pinned_ref"]
        else:
            ref = entry["intent_ref"]
        print(f"==> {name}: {ref}")
        try:
            digest, platforms, is_index = inspect(ref)
        except RuntimeError as exc:
            failures.append(f"{name}: {exc}")
            continue
        platforms = normalized_platforms(platforms)
        required = set(entry.get("required_platforms") or [])
        missing = sorted(required - platforms)
        if missing:
            failures.append(f"{name}: missing required platforms {missing}; observed {sorted(platforms)}")
        if len(required) > 1 and not is_index:
            failures.append(f"{name}: multi-platform runtime ref resolved to a single manifest, not an image index")

        if status == "verified":
            expected = entry["pinned_ref"].rsplit("@", 1)[1]
            if digest != expected:
                failures.append(f"{name}: tag moved: lock={expected}, registry={digest}")
            else:
                print(f"    digest OK {digest}; platforms={', '.join(sorted(platforms)) or 'not reported'}")
        elif status == "inherited-pinned":
            expected = entry["pinned_ref"].rsplit("@", 1)[1]
            if digest != expected:
                failures.append(f"{name}: pinned digest inspect mismatch: expected={expected}, got={digest}")
            else:
                print(f"    inherited pin OK {digest}; platforms={', '.join(sorted(platforms)) or 'not reported'}")
        else:
            repo = entry["intent_ref"].split("@", 1)[0]
            # Remove a final tag without damaging registry host ports.
            slash = repo.rfind("/")
            colon = repo.rfind(":")
            if colon > slash:
                repo = repo[:colon]
            suggestion = f"{repo}@{digest}"
            deferred_resolved.append(name)
            print(f"    RESOLVE: pinned_ref: {suggestion}")
            print(f"    platforms={', '.join(sorted(platforms)) or 'not reported'}")

    if deferred_resolved and args.strict:
        failures.append("deferred entries resolved online but are not yet committed: " + ", ".join(deferred_resolved))

    if failures:
        print("image platform verification FAILED:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1
    print("OK: registry digests/platforms match the committed image lock")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
