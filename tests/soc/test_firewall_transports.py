"""Ownership semantics, backend clients and the nftables enforcement agent (all offline)."""

import importlib.util
import json
from pathlib import Path
import threading
from http.server import ThreadingHTTPServer
from types import SimpleNamespace
from urllib.request import Request, urlopen

import pytest

from response.adapters.blocklist import NftablesBlocklistAdapter, BlocklistPeer, VyosBlocklistAdapter
from response.transports.http import DeliveryError
from response.transports.nftables import NftablesRawSet
from response.transports.opnsense import OPNsenseRawSet
from response.transports.ownership import OwnedBlocklistClient, OwnershipLedger
from response.transports.vyos import VyosRawSet

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("nft_enforcer", ROOT / "docker/enforcer/nft_enforcer.py")
nft_enforcer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nft_enforcer)


class MemorySet:
    def __init__(self):
        self.items = set()
        self.adds = []
        self.removes = []
        self.fail_add_after_apply = False

    def contains(self, address):
        return address in self.items

    def add(self, address, lifetime):
        self.adds.append((address, lifetime))
        self.items.add(address)
        if self.fail_add_after_apply:
            raise TimeoutError("receipt lost")

    def remove(self, address):
        self.removes.append(address)
        self.items.discard(address)


@pytest.fixture()
def owned(tmp_path):
    raw = MemorySet()
    ledger = OwnershipLedger(tmp_path / "private" / "peer.sqlite")
    yield OwnedBlocklistClient(raw, ledger), raw, ledger
    ledger.close()


def test_last_owner_removes_an_entry_the_plane_created(owned):
    client, raw, _ = owned
    assert client.add_soc_blocklist_address(address="203.0.113.5", idempotency_key="op-1",
                                            max_lifetime_seconds=1200).startswith("added:")
    assert raw.adds == [("203.0.113.5", 1200)] and client.soc_blocklist_contains(address="203.0.113.5")
    assert client.remove_soc_blocklist_address(address="203.0.113.5", idempotency_key="op-1").startswith("removed:")
    assert raw.items == set()
    # repeat is safe
    assert client.remove_soc_blocklist_address(address="203.0.113.5", idempotency_key="op-1").startswith("absent:")


def test_a_preexisting_entry_is_never_removed(owned):
    client, raw, _ = owned
    raw.items.add("203.0.113.6")
    assert client.add_soc_blocklist_address(address="203.0.113.6", idempotency_key="op-1").startswith("preexisting:")
    assert raw.adds == []
    assert client.remove_soc_blocklist_address(address="203.0.113.6", idempotency_key="op-1").startswith("preexisting:")
    assert "203.0.113.6" in raw.items and raw.removes == []


def test_shared_owners_release_independently(owned):
    client, raw, _ = owned
    client.add_soc_blocklist_address(address="203.0.113.7", idempotency_key="op-1")
    assert client.add_soc_blocklist_address(address="203.0.113.7", idempotency_key="op-2").startswith("shared:")
    assert client.remove_soc_blocklist_address(address="203.0.113.7", idempotency_key="op-1").startswith("shared:")
    assert "203.0.113.7" in raw.items
    assert client.remove_soc_blocklist_address(address="203.0.113.7", idempotency_key="op-2").startswith("removed:")
    assert "203.0.113.7" not in raw.items


def test_add_that_timed_out_after_applying_is_still_owned_and_removable(owned):
    client, raw, _ = owned
    raw.fail_add_after_apply = True
    with pytest.raises(TimeoutError):
        client.add_soc_blocklist_address(address="203.0.113.8", idempotency_key="op-1")
    assert "203.0.113.8" in raw.items
    assert client.remove_soc_blocklist_address(address="203.0.113.8", idempotency_key="op-1").startswith("removed:")
    assert "203.0.113.8" not in raw.items


def test_foreign_mark_is_forgotten_after_the_last_owner_leaves(owned):
    client, raw, _ = owned
    raw.items.add("203.0.113.9")
    client.add_soc_blocklist_address(address="203.0.113.9", idempotency_key="op-1")
    client.remove_soc_blocklist_address(address="203.0.113.9", idempotency_key="op-1")
    raw.items.discard("203.0.113.9")  # the administrator later removes their own entry
    assert client.add_soc_blocklist_address(address="203.0.113.9", idempotency_key="op-2").startswith("added:")
    assert client.remove_soc_blocklist_address(address="203.0.113.9", idempotency_key="op-2").startswith("removed:")
    assert "203.0.113.9" not in raw.items


def test_ownership_survives_restart(tmp_path):
    path = tmp_path / "private" / "peer.sqlite"
    raw = MemorySet()
    first = OwnershipLedger(path)
    OwnedBlocklistClient(raw, first).add_soc_blocklist_address(address="203.0.113.10", idempotency_key="op-1")
    first.close()
    second = OwnershipLedger(path)
    client = OwnedBlocklistClient(raw, second)
    assert client.remove_soc_blocklist_address(address="203.0.113.10", idempotency_key="op-1").startswith("removed:")
    second.close()


def test_adapter_over_owned_clients_applies_verifies_and_reverts_on_both_peers(tmp_path):
    peers, raws = [], []
    for name in ("fw-core", "fw-dmz"):
        raw = MemorySet()
        raws.append(raw)
        peers.append(BlocklistPeer(name, OwnedBlocklistClient(raw, OwnershipLedger(tmp_path / name / "o.sqlite"))))
    raws[1].items.add("203.0.113.20")  # fw-dmz already blocks it by hand
    adapter = NftablesBlocklistAdapter(peers=peers)
    command = {"action": "block_ip", "target": {"type": "ip", "value": "203.0.113.20"},
               "idempotency_key": "idemp-" + "1" * 64, "ttl_seconds": 900}
    assert adapter.apply(command).ok
    assert raws[0].adds[0][1] == 900 + 300     # firewall-side backstop outlives the orchestrator TTL
    assert adapter.verify(command, adapter_reference=adapter.recovery_reference(command)).ok
    reverted = adapter.revert(command, adapter_reference=adapter.recovery_reference(command))
    assert reverted.ok
    assert "203.0.113.20" not in raws[0].items          # we added it, we removed it
    assert "203.0.113.20" in raws[1].items              # the manual entry stays
    assert any("released" in ref for ref in reverted.evidence_refs)


def test_adapter_needs_two_unique_peers():
    peer = BlocklistPeer("only", object())
    with pytest.raises(ValueError):
        VyosBlocklistAdapter(peers=[peer])
    with pytest.raises(ValueError):
        VyosBlocklistAdapter(peers=[peer, BlocklistPeer("only", object())])


# ------------------------------------------------------------- backend clients


class ScriptedHttp:
    def __init__(self, *replies):
        self.replies, self.calls = list(replies), []

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        return self.replies.pop(0)

    def post_form(self, path, fields):
        self.calls.append(("POST", path, json.loads(fields["data"])))
        return self.replies.pop(0)


def test_opnsense_alias_util_contract():
    http = ScriptedHttp((200, {"rows": [{"ip": "203.0.113.5"}, {"ip": "198.51.100.0/32"}]}),
                        (200, {"status": "done"}), (200, {"status": "done"}))
    raw = OPNsenseRawSet(http)
    assert raw.contains("203.0.113.5") and http.calls[0][:2] == ("GET", "/api/firewall/alias_util/list/SOC_BLOCKLIST")
    raw.add("203.0.113.6", None)
    raw.remove("203.0.113.6")
    assert http.calls[1] == ("POST", "/api/firewall/alias_util/add/SOC_BLOCKLIST", {"address": "203.0.113.6"})
    assert http.calls[2][1] == "/api/firewall/alias_util/delete/SOC_BLOCKLIST"
    with pytest.raises(DeliveryError):
        OPNsenseRawSet(ScriptedHttp((200, {"status": "failed"}))).add("203.0.113.7", None)


def test_nftables_agent_client_contract():
    http = ScriptedHttp((200, {"present": True}), (200, {"ok": True}), (200, {"ok": True}), (200, {"present": "yes"}))
    raw = NftablesRawSet(http)
    assert raw.contains("203.0.113.5") is True
    raw.add("203.0.113.6", 1200)
    raw.remove("203.0.113.6")
    assert http.calls[1] == ("POST", "/v1/add", {"address": "203.0.113.6", "max_lifetime_seconds": 1200})
    with pytest.raises(DeliveryError):
        raw.contains("203.0.113.5")   # a non-boolean readback cannot prove membership


def test_vyos_api_touches_only_the_fixed_group_and_handles_empty_groups():
    http = ScriptedHttp(
        (200, {"success": True, "data": ["203.0.113.5", "203.0.113.8"]}),
        (200, {"success": False, "error": "Configuration under specified path is empty"}),
        (200, {"success": True}),
        (200, {"success": False, "error": "Nothing to delete"}),
    )
    raw = VyosRawSet(http, "k" * 20)
    assert raw.contains("203.0.113.8") and not raw.contains("203.0.113.9")
    raw.add("203.0.113.9", None)
    raw.remove("203.0.113.9")
    assert http.calls[2][2] == {"op": "set", "path": ["firewall", "group", "address-group", "SOC_BLOCKLIST",
                                                      "address", "203.0.113.9"]}
    with pytest.raises(ValueError):
        VyosRawSet(http, "has space")


# ---------------------------------------------------------- enforcement agent


class FakeNft:
    def __init__(self, elements=()):
        self.commands, self.elements = [], list(elements)
        self.fail = False

    def __call__(self, argv):
        self.commands.append(list(argv))
        stdout = ""
        if "list" in argv:
            stdout = json.dumps({"nftables": [{"set": {"elem": self.elements}}]})
        return SimpleNamespace(returncode=1 if self.fail else 0, stdout=stdout, stderr="")


def agent(nft):
    return nft_enforcer.Enforcer(nft="/usr/sbin/nft", family="inet", table="cxyz", set_name="soc_blocklist", run=nft)


def test_enforcer_emits_only_fixed_set_commands_with_a_timeout():
    nft = FakeNft()
    enforcer = agent(nft)
    enforcer.add("203.0.113.5", 1200)
    enforcer.add("2001:db8::5", None)
    enforcer.remove("203.0.113.5")
    assert nft.commands[0] == ["/usr/sbin/nft", "add", "element", "inet", "cxyz", "soc_blocklist",
                               "{ 203.0.113.5 timeout 1200s }"]
    assert nft.commands[1][5] == "soc_blocklist6" and "timeout 3600s" in nft.commands[1][6]
    assert nft.commands[2][1] == "delete"


@pytest.mark.parametrize("address", ["127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "::1", "not-an-ip", 7])
def test_enforcer_refuses_special_use_and_malformed_addresses(address):
    nft = FakeNft()
    with pytest.raises(ValueError):
        agent(nft).add(address, 600)
    assert nft.commands == []


def test_enforcer_lifetime_is_bounded_and_contains_parses_nft_json():
    enforcer = agent(FakeNft(elements=["203.0.113.5", {"elem": {"val": "203.0.113.6", "timeout": 100}}]))
    assert enforcer.contains("203.0.113.5") and enforcer.contains("203.0.113.6") and not enforcer.contains("203.0.113.7")
    for bad in (10, 10_000_000):
        with pytest.raises(ValueError):
            enforcer.add("203.0.113.5", bad)
    broken = FakeNft()
    broken.fail = True
    with pytest.raises(RuntimeError):
        agent(broken).add("203.0.113.5", 600)


def test_enforcer_http_surface_is_three_posts_and_rejects_everything_else():
    nft = FakeNft(elements=["203.0.113.5"])
    server = ThreadingHTTPServer(("127.0.0.1", 0), nft_enforcer.make_handler(agent(nft), frozenset()))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def post(path, body):
        request = Request(base + path, data=json.dumps(body).encode(), method="POST")
        try:
            with urlopen(request, timeout=5) as reply:
                return reply.status, json.loads(reply.read())
        except Exception as exc:  # urllib raises on 4xx/5xx
            return exc.code, json.loads(exc.read())

    try:
        assert post("/v1/contains", {"address": "203.0.113.5"}) == (200, {"present": True})
        assert post("/v1/add", {"address": "203.0.113.9", "max_lifetime_seconds": 600})[0] == 200
        assert post("/v1/add", {"address": "127.0.0.1"})[0] == 400
        assert post("/v1/flush", {"address": "203.0.113.5"})[0] == 404
        assert post("/v1/add", {"address": "not-an-ip"})[0] == 400
    finally:
        server.shutdown()
