"""A rotated Elasticsearch credential takes effect without restarting the worker that holds it."""

import os

import pytest

from soc.workers.common import FileAuthorization
from soc.workers.https import JsonHTTPS


def write(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(value)
    os.replace(temporary, path)          # how a rotation lands: a new inode under the same name


def test_a_replaced_key_file_is_picked_up_on_the_next_request(tmp_path):
    key = tmp_path / "es.key"
    write(key, "first-key")
    authorization = FileAuthorization(key)
    assert authorization() == "ApiKey first-key"
    write(key, "rotated-key")
    assert authorization() == "ApiKey rotated-key"


def test_user_password_credentials_keep_basic_auth(tmp_path):
    key = tmp_path / "es.cred"
    write(key, "soc_decision:s3cret")
    assert FileAuthorization(key)().startswith("Basic ")


def test_a_missing_or_malformed_credential_still_fails_at_start_up(tmp_path):
    with pytest.raises(OSError):
        FileAuthorization(tmp_path / "absent")
    bad = tmp_path / "bad"
    write(bad, "two tokens")
    with pytest.raises(ValueError):
        FileAuthorization(bad)


def test_a_half_written_or_vanished_file_keeps_the_last_good_value(tmp_path):
    key = tmp_path / "es.key"
    write(key, "good-key")
    authorization = FileAuthorization(key)
    write(key, "")                       # caught between truncate and write
    assert authorization() == "ApiKey good-key"
    key.unlink()                         # caught between delete and re-create
    assert authorization() == "ApiKey good-key"
    write(key, "next-key")
    assert authorization() == "ApiKey next-key"


def test_the_transport_asks_a_callable_authorization_on_every_request(tmp_path, monkeypatch):
    seen = []

    class Reply:
        status, length = 200, None

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, limit):
            return b"{}"

    transport = JsonHTTPS("https://elasticsearch:9200", ca=None, authorization=iter(["ApiKey a", "ApiKey b"]).__next__)
    monkeypatch.setattr(transport._opener, "open", lambda request, timeout: seen.append(request.get_header("Authorization")) or Reply())
    transport.request("GET", "/")
    transport.request("GET", "/")
    assert seen == ["ApiKey a", "ApiKey b"]
