"""Regression coverage for dotenv parsing without shell evaluation."""

from __future__ import annotations

import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from env_exec import parse_dotenv  # noqa: E402
from scan_locked_images import locked_refs  # noqa: E402
from check_authentik_migration import legacy_volume_names  # noqa: E402


def test_crypt_hash_is_read_as_literal_data(tmp_path: pathlib.Path):
    env_file = tmp_path / ".env"
    env_file.write_text("RADIUS_ADMIN_CRYPT=$6$rounds=5000$abc$hash\n")

    assert parse_dotenv(env_file)["RADIUS_ADMIN_CRYPT"] == "$6$rounds=5000$abc$hash"


def test_runtime_image_scan_uses_only_immutable_locked_references():
    refs = locked_refs()

    assert refs
    assert len(refs) == len(set(refs))
    assert all("@sha256:" in ref for ref in refs)


def test_authentik_migration_guard_detects_only_the_legacy_project_volume(monkeypatch):
    class Result:
        returncode = 0
        stdout = "enterprise-netsec-iac_authentik_db\nauthentik_db_2026\nother_authentik_db\n"
        stderr = ""

    monkeypatch.setattr("check_authentik_migration.subprocess.run", lambda *args, **kwargs: Result())

    assert legacy_volume_names("enterprise-netsec-iac") == {"enterprise-netsec-iac_authentik_db"}


def test_yaml_duplicate_mapping_keys_are_rejected():
    import yaml
    from check_yaml_syntax import duplicate_key_errors

    document = yaml.compose("apiVersion: v1\nkind: Service\napiVersion: apps/v1\n")
    errors = duplicate_key_errors(document)

    assert any("duplicate mapping key 'apiVersion'" in error for error in errors)
