"""Path B audit: SOC verifiers are wired to the shared checks and its VyOS/endpoint probes parse correctly."""

import importlib.util
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]


@pytest.fixture()
def audit(tmp_path, monkeypatch):
    monkeypatch.setenv("EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("path_b_audit_under_test", ROOT / "scripts/path_b_audit.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


def test_every_soc_check_is_registered_once_under_its_own_control(audit):
    registered = {control: function.__name__ for control, function in audit.CONTROLS}
    soc = {control for control in audit.soc_live.CHECKS}
    assert soc <= set(registered)
    for control in soc:
        assert registered[control] == "test_" + control.lower().replace("-", "")
    assert len(registered) == len(audit.CONTROLS)


def test_wrappers_delegate_to_the_shared_check_with_a_single_session(audit, monkeypatch):
    seen = []

    class Lab:
        def __init__(self, **kwargs):
            seen.append(kwargs)

    monkeypatch.setattr(audit.soc_live, "DockerLab", Lab)
    monkeypatch.setitem(audit.soc_live.CHECKS, "LOG-01", lambda run: ("ok", {"run": id(run)}))
    monkeypatch.setitem(audit.soc_live.CHECKS, "LOG-02", lambda run: ("ok", {"run": id(run)}))
    first, second = audit.test_log01(), audit.test_log02()
    assert first[1]["run"] == second[1]["run"]                    # one scenario cache for the whole audit
    assert len(seen) == 1 and seen[0]["environment"] == "path-b"
    assert callable(seen[0]["blocklist_probe"]) and callable(seen[0]["endpoint_probe"])


def test_vyos_blocklist_probe_reads_the_committed_address_group(audit, monkeypatch):
    configs = {
        "fw-core": "set firewall group address-group SOC_BLOCKLIST address '203.0.113.9'\n"
                   "set firewall group address-group SOC_BLOCKLIST address 198.51.100.4\n"
                   "set firewall group address-group OTHER address 10.0.0.1\n",
        "fw-dmz": "set firewall group address-group SOC_BLOCKLIST description 'x'\n",
    }
    monkeypatch.setattr(audit, "config", lambda node: configs[node])
    assert audit._vyos_blocklists() == {"fw-core": {"203.0.113.9", "198.51.100.4"}, "fw-dmz": set()}


def test_endpoint_probe_tests_a_new_connection_from_the_admin_station(audit, monkeypatch):
    calls = []
    monkeypatch.setattr(audit, "tcp_from_linux", lambda node, address, port: calls.append((node, address, port)) or False)
    assert audit._endpoint_reachable("pc1") is False
    assert calls == [("pc4", "192.168.10.1", 22)]
