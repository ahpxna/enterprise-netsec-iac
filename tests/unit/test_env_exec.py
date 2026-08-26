"""Regression coverage for dotenv parsing without shell evaluation."""

from __future__ import annotations

import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from env_exec import parse_dotenv  # noqa: E402


def test_crypt_hash_is_read_as_literal_data(tmp_path: pathlib.Path):
    env_file = tmp_path / ".env"
    env_file.write_text("RADIUS_ADMIN_CRYPT=$6$rounds=5000$abc$hash\n")

    assert parse_dotenv(env_file)["RADIUS_ADMIN_CRYPT"] == "$6$rounds=5000$abc$hash"
