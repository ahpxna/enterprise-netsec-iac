"""Network explorer: the derived model must match the deployed sources and leak no secret."""

import json
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import netviz  # noqa: E402


@pytest.fixture(scope="module")
def model():
    return netviz.build_model()


def test_every_node_link_and_address_is_present_and_consistent(model):
    topology = model["topology"]
    assert len(topology["nodes"]) == 12 and {b["id"] for b in topology["bridges"]} == {"vlan10", "vlan40", "br-cxyz-dc"}
    assert model["validation"] == {"ok": True, "problems": []}
    ids = {n["id"] for n in topology["nodes"]} | {b["id"] for b in topology["bridges"]} | {d["id"] for d in topology["docker"]}
    for link in topology["links"]:
        assert link["a"]["node"] in ids and link["b"]["node"] in ids, link["id"]
    assert all(a["interface"].startswith("eth") for n in topology["nodes"] for a in n["attachments"])


def test_interface_names_agree_with_the_containerlab_exec_addressing(model):
    """The (intent link order -> eth) mapping must reproduce every `ip address replace ... dev ethN`."""

    clab = yaml.safe_load((ROOT / "clab/companyxyz.clab.yml").read_text())
    checked = 0
    for node in model["topology"]["nodes"]:
        wanted = {}
        for line in clab["topology"]["nodes"][node["id"]].get("exec", []):
            for address, dev in re.findall(r"ip address replace (\S+) dev (eth\d+)", line):
                wanted[address.split("/")[0]] = dev
        for attachment in node["attachments"]:
            if attachment["ip"] in wanted:
                assert attachment["interface"] == wanted[attachment["ip"]], (node["id"], attachment)
                checked += 1
    assert checked >= 15            # most attachments are verifiable against the exec lines


def test_model_contains_no_secret_values(model):
    text = json.dumps(model)
    assert "CHANGE_ME" not in text
    routing = json.dumps(model["routing"], ensure_ascii=False)
    assert netviz.SECRET_MASK in routing and "ospf_key" not in routing and "bgp_isp" not in routing


def test_ip_plan_covers_every_subnet_and_the_management_network(model):
    cidrs = {row["cidr"] for row in model["ipplan"]}
    intent = yaml.safe_load((ROOT / "intent/fabric.yaml").read_text())
    assert {spec["cidr"] for spec in intent["links"].values()} <= cidrs and intent["management"]["subnet"] in cidrs
    mgmt = next(r for r in model["ipplan"] if r["cidr"] == intent["management"]["subnet"])
    assert {m["who"] for m in mgmt["members"]} == set(intent["nodes"])


def test_routing_adjacencies_are_deduplicated_and_match_the_configs(model):
    pairs = [(a["protocol"], frozenset((a["a"], a["b"]))) for a in model["routing"]["adjacencies"]]
    assert len(pairs) == len(set(pairs))
    assert ("BGP", frozenset(("edge", "isp1"))) in pairs and ("OSPF", frozenset(("core", "dist1"))) in pairs
    vrrp = {(v["interface"], v["priority"]) for v in model["routing"]["nodes"]["dist1"]["vrrp"]}
    assert ("eth2", 150) in vrrp


def test_both_firewalls_expose_the_containment_set_and_default_deny(model):
    for name, fw in model["firewalls"].items():
        table = next(t for t in fw["tables"] if t["name"] == fw["soc_table"])
        assert any(s["name"] == "soc_blocklist" and s["flags"] == "timeout" for s in table["sets"])
        forward = next(c for c in table["chains"] if c["name"] == "forward")
        assert forward["policy"] == "drop" and "@soc_blocklist" in forward["rules"][0]["text"], name


def test_frr_parser_masks_credentials_and_reads_protocols():
    parsed = netviz.parse_frr(
        "hostname x\nrouter bgp 65001\n bgp router-id 1.1.1.1\n neighbor 10.0.0.1 remote-as 65010\n"
        " neighbor 10.0.0.1 password S3cr3t!\n neighbor 10.0.0.1 ttl-security hops 1\n network 195.1.1.0/24\n!\n"
        "router ospf\n ospf router-id 2.2.2.2\n network 10.0.0.0/31 area 0\n passive-interface default\n no passive-interface eth1\n!\n"
        "interface eth1\n ip ospf authentication message-digest\n ip ospf message-digest-key 1 md5 TopSecret\n"
        " vrrp 10 version 3\n vrrp 10 ip 192.168.10.254\n vrrp 10 priority 150\n!\nip route 195.1.1.0/24 Null0\n")
    assert json.dumps(parsed).count("S3cr3t") == 0 and "TopSecret" not in json.dumps(parsed)
    assert parsed["bgp"]["asn"] == 65001 and parsed["bgp"]["neighbors"]["10.0.0.1"]["ttl_security_hops"] == 1
    assert parsed["ospf"]["networks"] == [{"prefix": "10.0.0.0/31", "area": "0"}] and parsed["ospf"]["active"] == ["eth1"]
    assert parsed["interfaces"]["eth1"]["ospf_auth"] == "md5" and parsed["vrrp"][0]["virtual_ip"] == "192.168.10.254"
    assert parsed["static"] == [{"to": "195.1.1.0/24", "via": "Null0"}]


def test_nft_parser_joins_continuations_and_keeps_rule_comments():
    parsed = netviz.parse_nft(
        'table inet t {\n  set s { type ipv4_addr; flags timeout; }\n  chain forward {\n'
        '    type filter hook forward priority 0; policy drop;\n    # allow DNS\n'
        '    ip saddr @s udp dport { 53, 123 } \\\n        accept\n    log prefix "X " drop\n  }\n}\n')
    table = parsed["tables"][0]
    chain = table["chains"][0]
    assert table["sets"][0]["flags"] == "timeout" and chain["policy"] == "drop"
    assert chain["rules"][0] == {"text": "ip saddr @s udp dport { 53, 123 } accept", "verdict": "accept", "comment": "allow DNS", "log": None}
    assert chain["rules"][1]["verdict"] == "drop" and chain["rules"][1]["log"] == "X "


DOCKER_PS = "\n".join(json.dumps(row) for row in [
    {"Names": "clab-companyxyz-fw-core", "State": "running", "Status": "Up 3 minutes", "Image": "x/multitool@sha256:1", "Labels": "containerlab=companyxyz"},
    {"Names": "clab-companyxyz-edge", "State": "exited", "Status": "Exited (1)", "Image": "frr", "Labels": ""},
    {"Names": "repo-elasticsearch-1", "State": "running", "Status": "Up 2 minutes (healthy)", "Image": "es",
     "Labels": "com.docker.compose.service=elasticsearch,a=b"},
])


def test_live_status_parses_containers_blocklists_and_indices(monkeypatch):
    nft = json.dumps({"nftables": [{"set": {"elem": [{"elem": {"val": "203.0.113.9", "expires": 41}}, "198.51.100.4"]}}]})

    def fake(argv, timeout=5.0):
        if argv[:2] == ["docker", "ps"]:
            return 0, DOCKER_PS
        if argv[:3] == ["docker", "network", "ls"]:
            return 0, "enterprise_cxyz_soc_backend\nbridge\n"
        if argv[:3] == ["docker", "network", "inspect"]:
            return 0, json.dumps([{"Name": "enterprise_cxyz_soc_backend", "Internal": True, "IPAM": {"Config": [{"Subnet": "172.19.0.0/16"}]},
                                   "Containers": {"x": {"Name": "repo-elasticsearch-1", "IPv4Address": "172.19.0.2/16"}}}])
        if argv[:2] == ["docker", "exec"] and "nft" in argv:
            assert argv[2] == "clab-companyxyz-fw-core" and argv[-3:] == ["inet", "cxyz", "soc_blocklist"]
            return 0, nft
        if argv[:2] == ["docker", "exec"]:
            return 0, json.dumps([{"index": "soc-raw-2026.09.07", "docs.count": "4"}, {"index": "soc-raw-2026.09.08", "docs.count": "6"}])
        raise AssertionError(argv)

    monkeypatch.setattr(netviz, "sh", fake)
    live = netviz.live_status()
    assert live["docker"]["ok"] and live["nodes"]["fw-core"]["state"] == "running" and live["nodes"]["edge"]["state"] == "exited"
    assert live["services"]["elasticsearch"]["health"] == "healthy"
    assert live["blocklists"]["fw-core"]["elements"] == [{"ip": "203.0.113.9", "expires": 41}, {"ip": "198.51.100.4", "expires": None}]
    assert live["indices"] == {"soc-raw-*": 10} and live["networks"][0]["subnets"] == ["172.19.0.0/16"]


def test_live_status_fails_soft_without_docker(monkeypatch):
    monkeypatch.setattr(netviz, "sh", lambda argv, timeout=5.0: (127, "docker: command not found"))
    live = netviz.live_status()
    assert live["docker"] == {"ok": False} and live["errors"] and live["nodes"] == {}


@pytest.fixture()
def server():
    cache = (netviz.Cache(60, netviz.build_model), netviz.Cache(60, lambda: {"docker": {"ok": False}, "nodes": {}}))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), netviz.make_handler({"127.0.0.1", "localhost"}, *cache))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def fetch(url, method="GET", headers=None):
    request = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=10) as reply:
            return reply.status, dict(reply.headers), reply.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def test_server_is_read_only_loopback_checked_and_sets_security_headers(server):
    status, headers, body = fetch(server + "/")
    assert status == 200 and b"Network Explorer" in body and "default-src 'self'" in headers["Content-Security-Policy"]
    assert headers["Cache-Control"] == "no-store" and headers["X-Content-Type-Options"] == "nosniff"
    assert json.loads(fetch(server + "/api/model")[2])["meta"]["name"] == "companyxyz"
    assert fetch(server + "/api/live")[0] == 200 and fetch(server + "/healthz")[2] == b"ok"
    assert fetch(server + "/etc/passwd")[0] == 404 and fetch(server + "/../../etc/passwd")[0] == 404
    for method in ("POST", "PUT", "DELETE"):
        assert fetch(server + "/api/model", method=method)[0] == 405
    assert fetch(server + "/api/model", headers={"Host": "evil.example"})[0] == 403        # DNS-rebinding guard


def test_ui_is_self_contained_and_never_injects_html():
    html = (ROOT / "scripts/netviz_ui/index.html").read_text()
    assert not re.search(r"(src|href)=[\"']https?://", html) and "cdn." not in html
    assert "innerHTML" not in html and "document.write" not in html and "eval(" not in html


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_ui_script_parses(tmp_path):
    html = (ROOT / "scripts/netviz_ui/index.html").read_text()
    script = re.search(r"<script>(.*)</script>", html, re.S).group(1)
    path = tmp_path / "ui.js"
    path.write_text(script)
    done = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
