"""Real mutual-TLS between the orchestrator client and the nftables agent; service config rules."""

import ssl
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from response.service.api import create_app
from response.service.config import (
    ConfigError,
    UnavailableAdapter,
    build_adapters,
    parse_decision_service,
    parse_response_service,
)
from response.transports.http import DeliveryError
from response.transports.nftables import NftablesRawSet

from pki import issue, make_ca
from test_firewall_transports import FakeNft, agent, nft_enforcer
from test_response_service import ATTACKER, anomaly, suricata_alert, world  # noqa: F401  (fixture)

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def secure_agent(tmp_path):
    ca_key, ca_cert, ca_path = make_ca(tmp_path)
    server_crt, server_key = issue(tmp_path, ca_key, ca_cert, "enforcer-fw-core", server=True, client=False,
                                   hosts=("127.0.0.1", "localhost"))
    client_crt, client_key = issue(tmp_path, ca_key, ca_cert, "orchestrator", server=False, client=True)
    other_crt, other_key = issue(tmp_path, ca_key, ca_cert, "someone-else", server=False, client=True)
    nft = FakeNft()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(server_crt, server_key)
    context.load_verify_locations(ca_path)
    context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingHTTPServer(("127.0.0.1", 0), nft_enforcer.make_handler(agent(nft), frozenset({"orchestrator"})))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"https://127.0.0.1:{server.server_address[1]}"
    yield dict(url=url, ca=str(ca_path), good=(str(client_crt), str(client_key)),
               other=(str(other_crt), str(other_key)), nft=nft)
    server.shutdown()


def test_orchestrator_client_operates_the_agent_over_mutual_tls(secure_agent):
    cert, key = secure_agent["good"]
    raw = NftablesRawSet.from_files(url=secure_agent["url"], ca=secure_agent["ca"], client_cert=cert, client_key=key)
    raw.add("203.0.113.5", 1200)
    assert raw.contains("203.0.113.5") is False      # FakeNft returns an empty set
    raw.remove("203.0.113.5")
    assert [c[1] for c in secure_agent["nft"].commands if "element" in c] == ["add", "delete"]


def test_a_certificate_the_ca_signed_but_the_agent_does_not_permit_is_forbidden(secure_agent):
    cert, key = secure_agent["other"]
    raw = NftablesRawSet.from_files(url=secure_agent["url"], ca=secure_agent["ca"], client_cert=cert, client_key=key)
    with pytest.raises(DeliveryError) as caught:
        raw.add("203.0.113.5", 600)
    assert caught.value.status == 403
    assert secure_agent["nft"].commands == []


def test_no_client_certificate_fails_the_handshake(secure_agent):
    from response.transports.http import JsonHTTPS

    bare = NftablesRawSet(JsonHTTPS(secure_agent["url"], ca=secure_agent["ca"]))
    with pytest.raises(DeliveryError) as caught:
        bare.add("203.0.113.5", 600)
    assert caught.value.code == "TLS_OR_NETWORK_UNAVAILABLE"
    assert secure_agent["nft"].commands == []


def test_wrong_server_ca_is_rejected(secure_agent, tmp_path):
    unrelated = tmp_path / "unrelated-ca"
    unrelated.mkdir()
    _, _, other_ca = make_ca(unrelated, "other-ca")
    cert, key = secure_agent["good"]
    raw = NftablesRawSet.from_files(url=secure_agent["url"], ca=str(other_ca), client_cert=cert, client_key=key)
    with pytest.raises(DeliveryError):
        raw.contains("203.0.113.5")


# ------------------------------------------------------------------- config


def response_config(**overrides):
    config = {
        "schema_version": "response-service-v1", "mode": "observe", "state_dir": "/var/lib/soc-response",
        "policy_file": "/etc/soc/policy.yaml", "verify_keys_dir": "/etc/soc/keys",
        "elasticsearch": {"url": "https://elasticsearch:9200", "ca": "/ca.crt", "api_key_file": "/key"},
        "listen": {"host": "10.9.0.5", "port": 8443, "cert": "/c", "key": "/k", "client_ca": "/cca"},
        "firewall": {"backend": "nftables", "peers": [
            {"name": "fw-core", "url": "https://10.1.1.20:9443", "ca": "/ca", "client_cert": "/c", "client_key": "/k"},
            {"name": "fw-dmz", "url": "https://10.1.1.30:9443", "ca": "/ca", "client_cert": "/c", "client_key": "/k"}]},
    }
    config.update(overrides)
    return config


def test_valid_response_config_parses_and_defaults_to_observe():
    assert parse_response_service(response_config())["mode"] == "observe"


@pytest.mark.parametrize("mutation", [
    {"mode": "yolo"}, {"extra_key": 1}, {"tick_seconds": 1}, {"tick_seconds": "10"},
    {"firewall": {"backend": "iptables", "peers": []}},
    {"firewall": {"backend": "nftables", "peers": [{"name": "only"}]}},
    {"elasticsearch": {"url": "https://es:9200", "ca": "/ca"}},
])
def test_response_config_is_closed_and_validated(mutation):
    with pytest.raises(ConfigError):
        parse_response_service(response_config(**mutation))


def test_backend_specific_peer_fields_are_enforced():
    config = response_config()
    config["firewall"]["backend"] = "vyos"
    with pytest.raises(ConfigError):
        parse_response_service(config)        # nftables fields are not valid VyOS peer fields


def test_decision_config_requires_orchestrator_only_when_enforcing():
    base = {"schema_version": "decision-service-v1", "mode": "observe", "state_dir": "/s", "policy_file": "/p",
            "signing_key_file": "/k", "signing_key_id": "d", "elasticsearch": {"url": "https://e", "ca": "/c",
                                                                                "api_key_file": "/f"}}
    parse_decision_service(base)
    with pytest.raises(ConfigError):
        parse_decision_service({**base, "mode": "enforce"})
    with pytest.raises(ConfigError):
        parse_decision_service({**base, "min_score": 0.5})   # below the global hybrid threshold


def test_missing_wazuh_backend_fails_closed_with_a_noop_revert():
    adapter = UnavailableAdapter(name="wazuh", action="isolate_host")
    command = {"idempotency_key": "k" * 20}
    assert not adapter.apply(command).ok and not adapter.verify(command, adapter_reference="r").ok
    assert adapter.revert(command, adapter_reference="r").ok


def test_build_adapters_wires_nftables_peers(tmp_path):
    ca_key, ca_cert, ca_path = make_ca(tmp_path)
    crt, key = issue(tmp_path, ca_key, ca_cert, "orchestrator", server=False, client=True)
    config = response_config()
    for peer in config["firewall"]["peers"]:
        peer.update(ca=str(ca_path), client_cert=str(crt), client_key=str(key))
    adapters = build_adapters(parse_response_service(config), tmp_path / "state")
    names = {(a.action, a.name) for a in adapters}
    assert names == {("block_ip", "nftables"), ("isolate_host", "wazuh")}


# -------------------------------------------------------------- intake API


def test_command_intake_api_accepts_a_signed_command_and_reports_status(world):
    world.fake.add("soc-ai-2026.09.07", "an-1", anomaly())
    world.fake.add("soc-alerts-2026.09.07", "sur-1", suricata_alert())
    world.runner.run_once()
    client = TestClient(create_app(world.service))
    assert client.get("/ready").status_code == 200
    reply = client.post("/v1/commands", json=world.sent[0])
    assert reply.status_code == 202 and reply.json()["state"] == "REQUESTED"
    assert client.get(f"/v1/responses/{reply.json()['response_id']}").json()["target"]["value"] == ATTACKER
    assert client.get("/v1/responses/resp-unknown").status_code == 404
    assert client.post("/v1/commands", content=b"not json").status_code == 400
    assert client.post("/v1/commands", content=b"x" * 20000).status_code == 413
    bad = dict(world.sent[0], target={"type": "ip", "value": "203.0.113.1"})
    assert client.post("/v1/commands", json=bad).status_code == 422
    assert "cxyz_soc_response_accepted_total 1" in client.get("/metrics").text
    assert client.get("/openapi.json").status_code == 404
