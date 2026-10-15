"""DockerLab's command construction and output parsing, against a scripted ``subprocess.run``.

No Docker is involved: these tests pin the argv/stdin handed to ``docker compose exec`` and the way
replies are parsed, so a typo cannot hide until the first live run.
"""

import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/validation"))

import soc_live  # noqa: E402
from soc_live import DockerLab, LabNotReady  # noqa: E402


class Script:
    """Replays queued replies and records every call."""

    def __init__(self):
        self.calls = []
        self.replies = []

    def queue(self, stdout="", returncode=0, stderr=""):
        self.replies.append(subprocess.CompletedProcess([], returncode, stdout, stderr))

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        return self.replies.pop(0)


@pytest.fixture()
def script(monkeypatch):
    recorded = Script()
    monkeypatch.setattr(soc_live.subprocess, "run", recorded)
    return recorded


def test_compose_prefix_selects_the_overlay_per_path():
    assert "docker-compose.path-a.yml" in DockerLab(environment="path-a")._compose_prefix
    prefix = DockerLab(environment="path-b")._compose_prefix
    assert "docker-compose.path-a.yml" not in prefix and prefix[-4:] == ["--profile", "soc", "--profile", "soc-ai"]


def test_es_search_posts_the_body_on_stdin_and_never_interpolates_the_path(script):
    script.queue('{"hits":{"hits":[{"_id":"1","_index":"soc-x","_source":{"a":{"b":1}}}]}}\n200')
    docs = DockerLab().es_search("soc-ai-*", {"query": {"term": {"a.b": 1}}})
    assert docs == [{"a": {"b": 1}, "_id": "1", "_index": "soc-x"}]
    argv, kwargs = script.calls[0]
    assert argv[argv.index("exec"):argv.index("exec") + 2] == ["exec", "-T"] and "elasticsearch" in argv
    assert argv[argv.index("elasticsearch") + 1:argv.index("elasticsearch") + 3] == ["bash", "-ec"]
    assert "SOC_LIVE_PATH=soc-ai-*/_search?allow_no_indices=true&ignore_unavailable=true" in argv
    assert json.loads(kwargs["input"]) == {"query": {"term": {"a.b": 1}}}
    shell = argv[argv.index("-ec") + 1]
    assert "soc-ai" not in shell and "SOC_LIVE_PATH" in shell        # the path travels as an env var


def test_es_errors_are_lab_not_ready_not_failures(script):
    script.queue('{"error":"boom"}\n500')
    with pytest.raises(LabNotReady, match="HTTP 500"):
        DockerLab().es_count("soc-ai-*", {"match_all": {}})
    script.queue("", returncode=1, stderr="no such service: elasticsearch")
    with pytest.raises(LabNotReady, match="no such service"):
        DockerLab().es_count("soc-ai-*", {"match_all": {}})


def test_inject_appends_one_line_to_a_known_fixture_only(script):
    script.queue()
    DockerLab().inject("suricata.json", '{"x": 1}')
    argv, kwargs = script.calls[0]
    assert "SOC_LIVE_FIXTURE=suricata.json" in argv and "logstash" in argv and kwargs["input"] == '{"x": 1}\n'
    with pytest.raises(ValueError):
        DockerLab().inject("../etc/passwd", "x")
    with pytest.raises(ValueError):
        DockerLab().inject("firewall.log", "two\nlines")


def test_ai_request_runs_inside_the_enrichment_worker_and_parses_json_and_text(script):
    script.queue(json.dumps({"status": 422, "body": json.dumps({"detail": {"code": "FEATURE_SCHEMA_MISMATCH"}})}) + "\n")
    status, body = DockerLab().ai_request("POST", "/v1/infer", {"feature_schema": "x"})
    assert status == 422 and body["detail"]["code"] == "FEATURE_SCHEMA_MISMATCH"
    argv, kwargs = script.calls[0]
    assert "soc-enrichment-worker" in argv and json.loads(kwargs["input"])["path"] == "/v1/infer"
    script.queue(json.dumps({"status": 200, "body": "cxyz_soc_ai_inference_errors_total 3\n"}))
    assert DockerLab().ai_request("GET", "/metrics")[1].startswith("cxyz_soc_ai")


def test_require_enforcement_demands_enforce_mode_and_the_short_ttl_policy(script):
    script.queue("enforce\n")
    script.queue("enforce\n")
    script.queue("policies:\n  - id: COR-001\n    ttl_seconds: 60\n  - id: COR-002\n    ttl_seconds: 60\n")
    assert DockerLab().require_enforcement()["policy_ttl_seconds"] == 60
    script.queue("enforce\n")
    script.queue("\n")                                   # observe: SOC_MODE unset in the orchestrator
    with pytest.raises(LabNotReady, match="soc-ai-validate-up"):
        DockerLab().require_enforcement()
    for reply in ("enforce\n", "enforce\n", "policies:\n  - id: COR-001\n    ttl_seconds: 900\n"):
        script.queue(reply)
    with pytest.raises(LabNotReady, match="60 s TTL"):
        DockerLab().require_enforcement()


NFT = """table inet cxyz {
\tset soc_blocklist {
\t\ttype ipv4_addr
\t\tflags timeout
\t\telements = { 203.0.113.9 timeout 1m expires 59s,
\t\t\t     198.51.100.4 timeout 1m expires 1m }
\t}
}
"""


def test_blocklists_parse_nft_elements_and_an_empty_set(script):
    script.queue(NFT)
    script.queue("table inet cxyz {\n\tset soc_blocklist {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n}\n")
    assert DockerLab().blocklists() == {"fw-core": {"203.0.113.9", "198.51.100.4"}, "fw-dmz": set()}
    assert script.calls[0][0][:3] == ["docker", "exec", "clab-companyxyz-fw-core"]
    # each firewall's soc_blocklist lives in its own nftables table (clab/configs/fw-*.nft)
    assert script.calls[0][0][-3:] == ["inet", "cxyz", "soc_blocklist"]
    assert script.calls[1][0][:3] == ["docker", "exec", "clab-companyxyz-fw-dmz"]
    assert script.calls[1][0][-3:] == ["inet", "dmz", "soc_blocklist"]
    script.queue("", returncode=1, stderr="No such container")
    with pytest.raises(LabNotReady, match="soc_blocklist"):
        DockerLab().blocklists()


def test_kibana_object_and_logstash_pipeline_parsing(script):
    script.queue('{"id":"cxyz-ai","attributes":{"title":"CompanyXYZ AI"}}\n200')
    assert DockerLab().kibana_object("dashboard", "cxyz-ai")["attributes"]["title"] == "CompanyXYZ AI"
    script.queue('{"message":"not found"}\n404')
    assert DockerLab().kibana_object("dashboard", "missing") is None
    script.queue('{"pipelines":{"soc-ingestion":{"dead_letter_queue_enabled":true}}}\n'
                 '{"pipelines":{"soc-ingestion":{"queue":{"type":"persisted","events_count":4}}}}')
    lab = DockerLab()
    assert lab.logstash_pipeline()["node"]["pipelines"]["soc-ingestion"]["dead_letter_queue_enabled"] is True
    script.queue('{"x":1}\n{"pipelines":{"soc-ingestion":{"queue":{"type":"persisted","events_count":4}}}}')
    assert lab.logstash_queue_depth() == 4


def test_outage_stops_then_always_restarts_elasticsearch(script):
    script.queue()                       # stop
    script.queue()                       # up --wait
    with DockerLab().elasticsearch_outage():
        pass
    assert script.calls[0][0][-2:] == ["stop", "elasticsearch"] and script.calls[1][0][-4:] == ["up", "-d", "--wait", "elasticsearch"]
    script.queue()
    script.queue()
    with pytest.raises(RuntimeError):
        with DockerLab().elasticsearch_outage():
            raise RuntimeError("body failed")
    assert script.calls[3][0][-1] == "elasticsearch" and "up" in script.calls[3][0]     # restarted despite the error
    script.queue()
    script.queue(returncode=1, stderr="unhealthy")
    with pytest.raises(LabNotReady, match="did not return"):
        with DockerLab().elasticsearch_outage():
            pass


def test_deployed_digest_is_read_from_the_ignored_env_file(tmp_path):
    (tmp_path / ".env").write_text('OTHER=1\nSOC_AI_METADATA_SHA256="%s"\n' % ("a" * 64))
    assert DockerLab(root=tmp_path).deployed_metadata_digest() == "a" * 64
    assert DockerLab(root=tmp_path / "missing").deployed_metadata_digest() is None


def test_firewall_table_names_match_the_shipped_nftables_configs():
    for firewall, table in soc_live.FIREWALL_TABLES.items():
        config = (ROOT / f"clab/configs/{firewall}.nft").read_text()
        assert f"table inet {table} {{" in config and "set soc_blocklist " in config
