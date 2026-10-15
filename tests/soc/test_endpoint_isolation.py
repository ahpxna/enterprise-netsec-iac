"""Wazuh API client contract and the endpoint Active Response script (offline)."""

import importlib.util
import io
import json
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from response.adapters.wazuh import WazuhIsolationAdapter
from response.transports.http import DeliveryError
from response.transports.wazuh_api import ISOLATE_SCRIPT, RESTORE_SCRIPT, WazuhApiClient, marker_path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "cxyz_endpoint_isolation", ROOT / "docker/wazuh/active-response/cxyz_endpoint_isolation.py")
script = importlib.util.module_from_spec(spec)
spec.loader.exec_module(script)

OP = "idemp-" + "a" * 64


class FakeWazuh:
    """Duck-types JsonHTTPS for the manager API."""

    def __init__(self):
        self.calls = []
        self.agents = [{"id": "007", "name": "pc1", "status": "active"}]
        self.marker = False
        self.token_requests = 0
        self.expire_token_once = False

    def with_authorization(self, authorization):
        clone = SimpleNamespace(request=lambda m, p, b=None: self._dispatch(authorization, m, p, b))
        return clone

    def _dispatch(self, authorization, method, path, payload):
        self.calls.append((authorization.split()[0], method, path, payload))
        if path.startswith("/security/user/authenticate"):
            self.token_requests += 1
            return 200, {"data": {"token": f"jwt-{self.token_requests}"}}
        if self.expire_token_once and authorization == "Bearer jwt-1":
            self.expire_token_once = False
            raise DeliveryError("HTTP_401", retryable=False, status=401)
        if path.startswith("/agents"):
            return 200, {"data": {"affected_items": self.agents}}
        if path.startswith("/active-response"):
            if payload["command"] == ISOLATE_SCRIPT:
                self.marker = True
            elif payload["command"] == RESTORE_SCRIPT:
                self.marker = False
            return 200, {"data": {"affected_items": ["007"], "total_failed_items": 0}}
        if path.startswith("/syscheck"):
            return 200, {"data": {"total_affected_items": 1 if self.marker else 0}}
        raise AssertionError(path)


def client(fake, **kw):
    return WazuhApiClient(fake, user="u", password="p", poll_seconds=0, sleep=lambda _: None, **kw)


def test_isolate_verify_restore_round_trip_uses_only_the_two_fixed_scripts():
    fake = FakeWazuh()
    api = client(fake)
    assert api.start_isolation(host="pc1", correlation_id=OP).startswith("ar:007:")
    assert api.isolation_is_enforced(host="pc1", correlation_id=OP) is True
    api.restore_isolation(host="pc1", correlation_id=OP)
    assert api.isolation_is_removed(host="pc1", correlation_id=OP) is True
    commands = [c[3]["command"] for c in fake.calls if c[3] and "command" in c[3]]
    assert commands == [ISOLATE_SCRIPT, RESTORE_SCRIPT]
    assert all(c[3]["arguments"] == [OP] and c[3]["custom"] is True for c in fake.calls if c[3] and "command" in c[3])
    syscheck = [c[2] for c in fake.calls if c[2].startswith("/syscheck")]
    assert marker_path(OP).replace("/", "%2F") in syscheck[0]


def test_verification_times_out_when_the_marker_never_appears():
    fake = FakeWazuh()
    now = iter(range(0, 1000, 10))
    api = WazuhApiClient(fake, user="u", password="p", verify_timeout_seconds=25, poll_seconds=0,
                         clock=lambda: float(next(now)), sleep=lambda _: None)
    assert api.isolation_is_enforced(host="pc1", correlation_id=OP) is False


@pytest.mark.parametrize("agents", [[], [{"id": "1", "name": "pc1", "status": "active"},
                                         {"id": "2", "name": "pc1", "status": "active"}],
                                    [{"id": "7", "name": "pc1", "status": "disconnected"}],
                                    [{"id": "7", "name": "pc10", "status": "active"}]])
def test_agent_must_be_unique_exact_and_active(agents):
    fake = FakeWazuh()
    fake.agents = agents
    with pytest.raises(DeliveryError):
        client(fake).start_isolation(host="pc1", correlation_id=OP)


def test_token_is_reused_and_refreshed_once_on_401():
    fake = FakeWazuh()
    api = client(fake)
    api.start_isolation(host="pc1", correlation_id=OP)
    api.isolation_is_enforced(host="pc1", correlation_id=OP)
    assert fake.token_requests == 1
    fake.expire_token_once = True
    api.isolation_is_enforced(host="pc1", correlation_id=OP)
    assert fake.token_requests == 2


def test_adapter_over_the_api_client_verifies_and_reverts():
    fake = FakeWazuh()
    adapter = WazuhIsolationAdapter(client=client(fake))
    command = {"action": "isolate_host", "target": {"type": "host", "value": "pc1"}, "idempotency_key": OP}
    assert adapter.apply(command).ok
    assert adapter.verify(command, adapter_reference=adapter.recovery_reference(command)).ok
    assert adapter.revert(command, adapter_reference=adapter.recovery_reference(command)).ok
    assert fake.marker is False


# ------------------------------------------------------------- endpoint script


class Nft:
    def __init__(self, rc=0, stderr=""):
        self.calls, self.rc, self.stderr = [], rc, stderr

    def __call__(self, argv, stdin=None):
        self.calls.append((list(argv), stdin))
        return SimpleNamespace(returncode=self.rc, stdout="", stderr=self.stderr)


@pytest.fixture()
def endpoint(tmp_path):
    config = tmp_path / "cxyz-isolation.json"
    config.write_text(json.dumps({"allowed_addresses": ["172.16.50.10", "10.1.1.1", "2001:db8::10"]}))
    return config, tmp_path / "markers"


def test_isolation_installs_a_manager_only_ruleset_then_writes_the_marker(endpoint):
    config, markers = endpoint
    nft = Nft()
    script.isolate(OP, config=config, marker_dir=markers, run=nft)
    rules = nft.calls[0][1]
    assert "policy drop" in rules and "172.16.50.10" in rules and "2001:db8::10" in rules
    assert "iifname lo accept" in rules and "ct state established,related accept" in rules
    marker = markers / sha256(OP.encode()).hexdigest()[:40]
    assert marker.exists() and oct(marker.stat().st_mode & 0o777) == "0o600"
    assert marker.name == Path(marker_path(OP)).name        # client and script agree on the marker name


def test_marker_is_not_written_if_the_ruleset_fails(endpoint):
    config, markers = endpoint
    with pytest.raises(RuntimeError):
        script.isolate(OP, config=config, marker_dir=markers, run=Nft(rc=1))
    assert not markers.exists() or not any(markers.iterdir())


def test_isolation_refuses_without_a_manager_address(tmp_path):
    config = tmp_path / "c.json"
    config.write_text(json.dumps({"allowed_addresses": []}))
    nft = Nft()
    with pytest.raises(ValueError):
        script.isolate(OP, config=config, marker_dir=tmp_path / "m", run=nft)
    assert nft.calls == []


def test_restore_removes_the_table_then_the_marker_and_is_repeatable(endpoint):
    config, markers = endpoint
    script.isolate(OP, config=config, marker_dir=markers, run=Nft())
    nft = Nft()
    script.restore(OP, marker_dir=markers, run=nft)
    assert nft.calls[0][0] == ["nft", "delete", "table", "inet", "cxyz_isolation"]
    assert not any(markers.iterdir())
    script.restore(OP, marker_dir=markers, run=Nft(rc=1, stderr="Error: No such file or directory"))


@pytest.mark.parametrize("bad", ["", "short", "x" * 200, "idemp-;rm -rf /"])
def test_operation_id_is_strictly_validated(endpoint, bad):
    config, markers = endpoint
    with pytest.raises(ValueError):
        script.isolate(bad, config=config, marker_dir=markers, run=Nft())


def test_script_mode_comes_from_its_installed_name_and_rejects_other_input(monkeypatch):
    seen = []
    monkeypatch.setattr(script, "isolate", lambda op: seen.append(("isolate", op)))
    monkeypatch.setattr(script, "restore", lambda op: seen.append(("restore", op)))
    monkeypatch.setattr(script, "log", lambda *_: None)
    add = io.StringIO(json.dumps({"command": "add", "parameters": {"extra_args": [OP]}}) + "\n")
    assert script.main(["/x/cxyz-isolate-endpoint"], add) == 0
    delete = io.StringIO(json.dumps({"command": "delete", "parameters": {"extra_args": [OP]}}) + "\n")
    assert script.main(["/x/cxyz-isolate-endpoint"], delete) == 0     # Wazuh timeout reversal restores
    restore = io.StringIO(json.dumps({"command": "add", "parameters": {"extra_args": [OP]}}) + "\n")
    assert script.main(["/x/cxyz-restore-endpoint"], restore) == 0
    assert seen == [("isolate", OP), ("restore", OP), ("restore", OP)]
    assert script.main(["/x/anything-else"], io.StringIO("{}\n")) == 2
    extra = io.StringIO(json.dumps({"command": "add", "parameters": {"extra_args": [OP, "pc4"]}}) + "\n")
    assert script.main(["/x/cxyz-isolate-endpoint"], extra) == 1
