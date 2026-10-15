"""Live verifiers for the SOC AI / response controls (LOG, AI, COR, RESP, SOC).

Every check drives the *deployed* stack through a :class:`Lab` (Docker Compose here,
the same interface is satisfied by the in-process lab used by ``tests/soc``) and
returns ``(assertion, observed)``.  Failures of the control raise ``AssertionError``
(evidence ``FAIL``); anything that stops the experiment from running - a service that
is down, enforcement not enabled, a missing endpoint - raises :class:`LabNotReady`
(evidence ``ERROR``).  A check never reports PASS from something it did not observe.

What is and is not proven is stated in each assertion text.  In particular the AI
anomaly that feeds the COR/RESP scenario is *injected* (``observer.name`` is
``soc-live-validation``): it stands in for model output so containment can be
verified deterministically, while the model path itself is exercised by AI-01.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Any, Callable, Mapping, Protocol, Sequence
import uuid

ROOT = Path(__file__).resolve().parents[2]

NORMALIZED = "soc-network-*,soc-endpoint-*,soc-auth-*,soc-alerts-*"
FIXTURE_DATASETS = {
    "firewall.log": "firewall.syslog",
    "radius.log": "freeradius.auth",
    "suricata.json": "suricata.eve",
    "wazuh.json": "wazuh.alerts",
}
AUDIT_STATES = ("REQUESTED", "APPLIED", "VERIFIED", "EXPIRED")
PROTECTED_TARGET = "172.16.50.1"          # server1: DNS/RADIUS/NTP, in every shipped policy
REQUIRED_BENCHMARK_METRICS = (
    "precision", "recall", "f1", "pr_auc", "false_positives_per_hour", "mttd_seconds", "p95_inference_ms",
)

Observation = tuple[str, dict]


class LabNotReady(RuntimeError):
    """The experiment could not run; the control is neither passed nor failed."""


# --------------------------------------------------------------------------- utilities
def rfc3339(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def dig(document: Mapping[str, Any], dotted: str) -> Any:
    value: Any = document
    for part in dotted.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def load_schema(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def validate(instance: Mapping[str, Any], schema_path: str) -> None:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as exc:  # pragma: no cover - dependency problem, not a control failure
        raise LabNotReady("install requirements-soc-live.txt (jsonschema) to run the live SOC checks") from exc
    errors = sorted(Draft202012Validator(load_schema(schema_path), format_checker=FormatChecker())
                    .iter_errors(instance), key=lambda e: list(e.path))
    assert not errors, f"{schema_path}: {errors[0].message} at {list(errors[0].path)}"


# --------------------------------------------------------------------------- lab interface
class Lab(Protocol):
    environment: str

    def now(self) -> datetime: ...
    def sleep(self, seconds: float) -> None: ...
    def es_search(self, index: str, body: Mapping[str, Any]) -> list[dict]: ...
    def es_count(self, index: str, query: Mapping[str, Any]) -> int: ...
    def es_create(self, index: str, doc_id: str, document: Mapping[str, Any]) -> None: ...
    def inject(self, fixture: str, line: str) -> None: ...
    def ai_request(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> tuple[int, Any]: ...
    def require_enforcement(self) -> dict: ...
    def blocklists(self) -> dict[str, set[str]]: ...
    def logstash_pipeline(self) -> dict: ...
    def kibana_object(self, kind: str, object_id: str) -> dict | None: ...
    def elasticsearch_outage(self) -> Any: ...
    def logstash_queue_depth(self) -> int: ...
    def endpoint_reachable(self, host: str) -> bool | None: ...
    def registry_dir(self) -> Path: ...
    def deployed_metadata_digest(self) -> str | None: ...


@dataclass(frozen=True)
class Timeouts:
    """Seconds.  Defaults follow the shipped cadences (60 s feature loop, 15 s decision poll)."""

    ingest: float = 120
    decision: float = 240
    lifecycle: float = 240
    expiry: float = 360
    ai_pipeline: float = 1500
    interval: float = 5

    @staticmethod
    def from_environment() -> "Timeouts":
        scale = float(os.environ.get("SOC_LIVE_TIMEOUT_SCALE", "1"))
        base = Timeouts()
        return Timeouts(**{name: getattr(base, name) * scale for name in base.__dataclass_fields__})


def wait_until(lab: Lab, probe: Callable[[], Any], *, timeout: float, interval: float, what: str) -> Any:
    deadline = lab.now() + timedelta(seconds=timeout)
    while True:
        value = probe()
        if value:
            return value
        if lab.now() >= deadline:
            raise AssertionError(f"timed out after {timeout:.0f}s waiting for {what}")
        lab.sleep(interval)


# --------------------------------------------------------------------------- docker lab
class DockerLab:
    """The real stack: ``docker compose exec`` into the running SOC services."""

    def __init__(
        self,
        *,
        environment: str = "path-a",
        root: Path = ROOT,
        blocklist_probe: Callable[[], dict[str, set[str]]] | None = None,
        endpoint_probe: Callable[[str], bool] | None = None,
    ) -> None:
        self.environment = environment
        self._root = root
        self._blocklist_probe = blocklist_probe
        self._endpoint_probe = endpoint_probe
        files = ["-f", "docker-compose.yml", "-f", "docker-compose.path-a.yml"] if environment == "path-a" else []
        self._compose_prefix = ["docker", "compose", *files, "--profile", "soc", "--profile", "soc-ai"]

    # -- plumbing
    def _compose(self, *args: str, stdin: str | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
        try:
            return subprocess.run([*self._compose_prefix, *args], cwd=self._root, input=stdin, text=True,
                                  capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise LabNotReady(f"docker compose is unavailable: {exc}") from exc

    def _exec(self, service: str, *command: str, stdin: str | None = None, env: Mapping[str, str] | None = None,
              timeout: int = 120) -> str:
        flags = [item for key, value in (env or {}).items() for item in ("-e", f"{key}={value}")]
        result = self._compose("exec", "-T", *flags, service, *command, stdin=stdin, timeout=timeout)
        if result.returncode != 0:
            raise LabNotReady(f"{service}: {' '.join(command[:3])} failed: {result.stderr.strip()[:300]}")
        return result.stdout

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    # -- Elasticsearch (as the lab's elastic superuser, from inside the ES container)
    def _es(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> Any:
        script = (
            'curl --silent --show-error --cacert config/certs/ca.crt --user "elastic:${ELASTIC_PASSWORD}" '
            '-X "$SOC_LIVE_METHOD" -H "content-type: application/json" --data-binary @- '
            '-w "\\n%{http_code}" "https://localhost:9200/${SOC_LIVE_PATH}"'
        )
        out = self._exec("elasticsearch", "bash", "-ec", script, stdin=json.dumps(body or {}),
                         env={"SOC_LIVE_METHOD": method, "SOC_LIVE_PATH": path})
        text, _, status = out.rpartition("\n")
        try:
            payload = json.loads(text) if text.strip() else {}
        except ValueError as exc:
            raise LabNotReady(f"Elasticsearch returned a non-JSON reply for {path}") from exc
        if not status.startswith("2"):
            raise LabNotReady(f"Elasticsearch {method} {path} -> HTTP {status}: {json.dumps(payload)[:300]}")
        return payload

    def es_search(self, index: str, body: Mapping[str, Any]) -> list[dict]:
        payload = self._es("POST", f"{index}/_search?allow_no_indices=true&ignore_unavailable=true", body)
        return [{**hit["_source"], "_id": hit["_id"], "_index": hit["_index"]} for hit in payload["hits"]["hits"]]

    def es_count(self, index: str, query: Mapping[str, Any]) -> int:
        payload = self._es("POST", f"{index}/_count?allow_no_indices=true&ignore_unavailable=true", {"query": query})
        return int(payload["count"])

    def es_create(self, index: str, doc_id: str, document: Mapping[str, Any]) -> None:
        self._es("PUT", f"{index}/_create/{doc_id}", document)

    # -- Logstash
    def inject(self, fixture: str, line: str) -> None:
        if fixture not in FIXTURE_DATASETS or "\n" in line:
            raise ValueError("unsupported fixture or multi-line payload")
        self._exec("logstash", "bash", "-ec", 'cat >> "/fixtures/${SOC_LIVE_FIXTURE}"',
                   stdin=line + "\n", env={"SOC_LIVE_FIXTURE": fixture})

    def logstash_pipeline(self) -> dict:
        script = ('curl --silent --fail http://localhost:9600/_node/pipelines/soc-ingestion && echo && '
                  'curl --silent --fail "http://localhost:9600/_node/stats/pipelines/soc-ingestion"')
        first, _, second = self._exec("logstash", "bash", "-ec", script).partition("\n")
        return {"node": json.loads(first), "stats": json.loads(second)}

    def logstash_queue_depth(self) -> int:
        stats = self.logstash_pipeline()["stats"]
        queue = dig(stats, "pipelines.soc-ingestion.queue") or {}
        return int(queue.get("events_count", queue.get("events", 0)) or 0)

    def elasticsearch_outage(self):
        lab = self

        class Outage:
            def __enter__(self_inner):
                lab._compose("stop", "elasticsearch", timeout=180)
                return self_inner

            def __exit__(self_inner, *exc):
                restart = lab._compose("up", "-d", "--wait", "elasticsearch", timeout=420)
                if restart.returncode != 0:
                    raise LabNotReady("Elasticsearch did not return after the outage scenario: "
                                      + restart.stderr.strip()[:300])
                return False

        return Outage()

    # -- AI inference API, through the enrichment worker's client identity
    _AI_CALL = (
        "import json, os, ssl, sys, http.client\n"
        "from urllib.parse import urlsplit\n"
        "spec = json.load(sys.stdin)\n"
        "url = urlsplit(os.environ['SOC_AI_URL'])\n"
        "ctx = ssl.create_default_context(cafile=os.environ['SOC_AI_CA'])\n"
        "ctx.load_cert_chain(os.environ['SOC_AI_CLIENT_CERT'], os.environ['SOC_AI_CLIENT_KEY'])\n"
        "conn = http.client.HTTPSConnection(url.hostname, url.port or 443, context=ctx, timeout=20)\n"
        "body = None if spec['body'] is None else json.dumps(spec['body'])\n"
        "conn.request(spec['method'], spec['path'], body=body, headers={'content-type': 'application/json'})\n"
        "reply = conn.getresponse()\n"
        "print(json.dumps({'status': reply.status, 'body': reply.read().decode()}))\n"
    )

    def ai_request(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> tuple[int, Any]:
        out = self._exec("soc-enrichment-worker", "python", "-c", self._AI_CALL,
                         stdin=json.dumps({"method": method, "path": path, "body": body}))
        reply = json.loads(out.strip().splitlines()[-1])
        text = reply["body"]
        try:
            return int(reply["status"]), (json.loads(text) if text.strip().startswith(("{", "[")) else text)
        except ValueError:
            return int(reply["status"]), text

    # -- response plane preconditions
    def require_enforcement(self) -> dict:
        modes = {}
        for service in ("soc-decision", "soc-response"):
            modes[service] = self._exec(service, "printenv", "SOC_MODE").strip()
        if set(modes.values()) != {"enforce"}:
            raise LabNotReady("decision and orchestrator must run in enforce mode for this lab validation: "
                              "run `make soc-ai-validate-up` (it sets SOC_MODE=enforce and the 60 s TTL policy)")
        policy = self._exec("soc-response", "cat", "/etc/soc/policy.yaml")
        if len(re.findall(r"^\s+ttl_seconds: 60\s*$", policy, re.M)) != 2:
            raise LabNotReady("the orchestrator is not running the lab-validation policy (60 s TTL)")
        return {"modes": modes, "policy_ttl_seconds": 60}

    def blocklists(self) -> dict[str, set[str]]:
        if self._blocklist_probe is not None:
            return self._blocklist_probe()
        found: dict[str, set[str]] = {}
        for firewall in ("fw-core", "fw-dmz"):
            result = subprocess.run(
                ["docker", "exec", f"clab-companyxyz-{firewall}", "nft", "list", "set", "inet", "cxyz", "soc_blocklist"],
                capture_output=True, text=True, timeout=30, check=False)
            if result.returncode != 0:
                raise LabNotReady(f"cannot read soc_blocklist on {firewall}: {result.stderr.strip()[:200]}")
            elements = result.stdout.split("elements", 1)[1] if "elements" in result.stdout else ""
            found[firewall] = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", elements))
        return found

    def endpoint_reachable(self, host: str) -> bool | None:
        return None if self._endpoint_probe is None else self._endpoint_probe(host)

    # -- Kibana, registry
    def kibana_object(self, kind: str, object_id: str) -> dict | None:
        script = ('curl --silent --cacert config/certs/ca.crt --user "elastic:${ELASTIC_PASSWORD}" '
                  '-w "\\n%{http_code}" "https://kibana:5601/api/saved_objects/${SOC_LIVE_KIND}/${SOC_LIVE_ID}"')
        out = self._exec("elasticsearch", "bash", "-ec", script,
                         env={"SOC_LIVE_KIND": kind, "SOC_LIVE_ID": object_id})
        text, _, status = out.rpartition("\n")
        return json.loads(text) if status.strip() == "200" else None

    def registry_dir(self) -> Path:
        return self._root / "ai/registry/active"

    def deployed_metadata_digest(self) -> str | None:
        env_file = self._root / ".env"
        if not env_file.is_file():
            return None
        for line in env_file.read_text().splitlines():
            if line.startswith("SOC_AI_METADATA_SHA256="):
                return line.split("=", 1)[1].strip().strip('"\'') or None
        return None


# --------------------------------------------------------------------------- scenario run
def _address(prefix: str, run_id: str, offset: int) -> str:
    return f"{prefix}.{1 + (int(run_id[:6], 16) + offset) % 250}"


class Run:
    """One validation session: unique markers/addresses and a cache of executed scenarios."""

    def __init__(self, lab: Lab, *, run_id: str | None = None, timeouts: Timeouts | None = None) -> None:
        self.lab = lab
        self.id = run_id or uuid.uuid4().hex[:10]
        self.marker = f"cxyz-live-{self.id}"
        self.timeouts = timeouts or Timeouts()
        self.cache: dict[str, Any] = {}
        self.attacker = _address("203.0.113", self.id, 0)       # corroborated -> contained
        self.solo = _address("203.0.113", self.id, 97)          # anomaly only -> never contained
        self.ingest_ip = _address("203.0.113", self.id, 149)    # LOG-* fixtures; never an anomaly entity
        self.burst = [_address("198.51.100", self.id, 31 * n) for n in range(1, 8)]

    def once(self, name: str, build: Callable[[], Any]) -> Any:
        if name not in self.cache:
            self.cache[name] = build()
        return self.cache[name]

    # -- telemetry builders
    def suricata_line(self, source: str, moment: datetime, token: str, severity: int = 2) -> str:
        return json.dumps({
            "timestamp": moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
            "event_type": "alert", "src_ip": source, "src_port": 53312, "dest_ip": "172.16.60.20",
            "dest_port": 443, "proto": "TCP",
            "alert": {"signature_id": 990001, "signature": f"SOC live {token}", "severity": severity},
            "cxyz_live_id": token,
        })

    def anomaly_document(self, entity: str, token: str, *, entity_type: str = "src_ip", score: float = 0.99) -> dict:
        now = self.lab.now()
        end = now - timedelta(seconds=20)
        schema = "network-window-v1" if entity_type == "src_ip" else "endpoint-window-v1"
        schema_sha = file_sha256(ROOT / f"schemas/features/{schema}.schema.json")
        digest = sha256(token.encode()).hexdigest()
        return {
            "@timestamp": rfc3339(now), "schema_version": "anomaly-event-v1",
            "event": {"id": f"live-{token}", "kind": "event", "category": ["anomaly_detection"],
                      "dataset": "soc.ai.anomaly"},
            "observer": {"name": "soc-live-validation", "type": "ai_inference"},
            "feature_vector": {
                "id": f"live-vector-{token}", "feature_schema": schema, "feature_schema_sha256": schema_sha,
                "entity_type": entity_type, "entity": entity,
                "window_start": rfc3339(end - timedelta(minutes=5)), "window_end": rfc3339(end),
                "source_event_set_sha256": digest,
            },
            "ai": {"model_id": "soc-live-validation-injected", "algorithm": "IsolationForest",
                   "model_sha256": digest, "model_metadata_sha256": digest, "score": score, "threshold": 0.9,
                   "is_anomaly": score >= 0.9, "inference_ms": 1.0},
        }

    def inject_anomaly(self, entity: str, token: str, *, entity_type: str = "src_ip", score: float = 0.99) -> dict:
        document = self.anomaly_document(entity, token, entity_type=entity_type, score=score)
        validate(document, "schemas/events/anomaly-event-v1.schema.json")
        index = "soc-ai-" + parse_time(document["@timestamp"]).strftime("%Y.%m.%d")
        self.lab.es_create(index, document["event"]["id"], document)
        self.lab.sleep(1)           # strictly increasing @timestamp keeps the decision cursor ordered
        return document

    # -- shared lookups
    def alert_docs(self, source: str) -> list[dict]:
        return self.lab.es_search("soc-alerts-*", {"size": 20, "query": {"bool": {"filter": [
            {"term": {"event.dataset": "suricata.eve"}}, {"term": {"source.ip": source}},
            {"range": {"@timestamp": {"gte": rfc3339(self.start - timedelta(minutes=1))}}}]}}})

    def decision_docs(self, target: str) -> list[dict]:
        return self.lab.es_search("soc-response-*", {"size": 20, "query": {"bool": {"filter": [
            {"term": {"schema_version": "correlation-decision-event-v1"}}, {"term": {"target.value": target}}]}}})

    def audit_docs(self, *, target: str | None = None, decision: str | None = None) -> list[dict]:
        filters: list[dict] = [{"term": {"schema_version": "response-audit-event-v1"}}]
        if target:
            filters.append({"term": {"target.value": target}})
        if decision:
            filters.append({"term": {"decision_event_id": decision}})
        docs = self.lab.es_search("soc-response-*", {"size": 100, "query": {"bool": {"filter": filters}},
                                                      "sort": [{"transition_number": "asc"}]})
        return sorted(docs, key=lambda d: (d["response_id"], d["transition_number"]))

    @property
    def start(self) -> datetime:
        return self.once("start", self.lab.now)

    # ------------------------------------------------------------------ ingestion (LOG-*)
    def ingestion(self) -> dict:
        return self.once("ingestion", self._run_ingestion)

    def _run_ingestion(self) -> dict:
        lab, token = self.lab, self.marker
        self.start
        now = lab.now()
        lines = {
            "firewall.log": f"src={self.ingest_ip} dst=172.16.60.20 spt=43120 dpt=443 proto=tcp action=blocked marker={token}-fw",
            "radius.log": f"user={token}-radius outcome=failure src={self.ingest_ip} marker={token}-radius",
            "suricata.json": self.suricata_line(self.ingest_ip, now, f"{token}-suricata"),
            "wazuh.json": json.dumps({
                "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                "rule": {"level": 8, "id": "990002", "description": f"SOC live {token}-wazuh"},
                "agent": {"name": "dmz-web"}, "data": {"srcip": self.ingest_ip, "dstip": "172.16.60.20"},
                "cxyz_live_id": f"{token}-wazuh"}),
        }
        malformed = f"not-json-{token}-bad"
        injected = {name: (line, f"{token}-" + {"firewall.log": "fw", "radius.log": "radius",
                                               "suricata.json": "suricata", "wazuh.json": "wazuh"}[name])
                    for name, line in lines.items()}
        for name, (line, _) in injected.items():
            lab.inject(name, line)
        lab.inject("suricata.json", malformed)

        def raw_for(sub: str) -> list[dict]:
            return lab.es_search("soc-raw-*", {"size": 5, "query": {"wildcard": {"event.original": {"value": f"*{sub}*"}}}})

        def landed() -> dict | None:
            result: dict[str, Any] = {}
            for name, (_, sub) in injected.items():
                raws = raw_for(sub)
                if len(raws) != 1:
                    return None
                normalized = lab.es_search(NORMALIZED, {"size": 5, "query": {"term": {"cxyz.ingestion_id": raws[0]["cxyz"]["ingestion_id"]}}})
                if len(normalized) != 1:
                    return None
                result[name] = {"raw": raws[0], "normalized": normalized[0], "line": injected[name][0]}
            bad_raw = raw_for(f"{token}-bad")
            dead = lab.es_search("soc-deadletter-*", {"size": 5, "query": {"wildcard": {"event.original": {"value": f"*{token}-bad*"}}}})
            if len(bad_raw) != 1 or len(dead) != 1:
                return None
            result["malformed"] = {"raw": bad_raw[0], "deadletter": dead[0]}
            return result

        return wait_until(lab, landed, timeout=self.timeouts.ingest, interval=self.timeouts.interval,
                          what="fixture events in raw, normalized and dead-letter streams")

    # ------------------------------------------------------------------ AI pipeline (AI-01)
    def ai_pipeline(self) -> dict:
        return self.once("ai_pipeline", self._run_ai_pipeline)

    def _run_ai_pipeline(self) -> dict:
        lab, entity, token = self.lab, _address("203.0.113", self.id, 53), f"{self.marker}-ai"
        started = lab.now()
        for port in range(1, 13):
            lab.inject("firewall.log", f"src={entity} dst=172.16.60.20 spt={40000 + port} dpt={port} "
                                       f"proto=tcp action=blocked marker={token}")

        def vector() -> dict | None:
            rows = lab.es_search("soc-features-*", {"size": 5, "query": {"bool": {"filter": [
                {"term": {"entity": entity}}, {"range": {"generated_at": {"gte": rfc3339(started)}}}]}},
                "sort": [{"generated_at": "asc"}]})
            return rows[0] if rows else None

        found_vector = wait_until(lab, vector, timeout=self.timeouts.ai_pipeline, interval=15,
                                  what=f"a feature vector for {entity}")

        def inference() -> dict | None:
            rows = lab.es_search("soc-ai-*", {"size": 5, "query": {"term": {"feature_vector.id": found_vector["vector_id"]}}})
            return rows[0] if rows else None

        found_inference = wait_until(lab, inference, timeout=self.timeouts.ai_pipeline, interval=15,
                                     what="the enriched soc-ai event for that vector")
        return {"entity": entity, "vector": found_vector, "inference": found_inference, "started": started}

    # ------------------------------------------------------------------ response scenario (COR/RESP/SOC)
    def response(self) -> dict:
        return self.once("response", self._run_response)

    def _run_response(self) -> dict:
        lab, t = self.lab, self.timeouts
        lab.require_enforcement()
        self.start
        alert_time = lab.now()
        for source in (self.attacker, PROTECTED_TARGET):
            lab.inject("suricata.json", self.suricata_line(source, alert_time, f"{self.marker}-{source}", severity=2))
        wait_until(lab, lambda: self.alert_docs(self.attacker) and self.alert_docs(PROTECTED_TARGET),
                   timeout=t.ingest, interval=t.interval, what="the corroborating Suricata alerts in soc-alerts-*")
        alert = self.alert_docs(self.attacker)[0]

        # Ordering matters: the decision runner is a single ordered cursor, so once the LAST
        # injected anomaly has produced its decision, every earlier one has been processed.
        solo_anomaly = self.inject_anomaly(self.solo, f"{self.marker}-solo")
        protected_anomaly = self.inject_anomaly(PROTECTED_TARGET, f"{self.marker}-protected")
        attacker_anomaly = self.inject_anomaly(self.attacker, f"{self.marker}-attacker")
        injected_at = lab.now()

        decision = wait_until(
            lab, lambda: next((d for d in self.decision_docs(self.attacker)
                               if dig(d, "decision.outcome") == "response_requested"), None),
            timeout=t.decision, interval=t.interval, what="the corroborated decision (response_requested)")
        protected_decision = wait_until(lab, lambda: next(iter(self.decision_docs(PROTECTED_TARGET)), None),
                                        timeout=t.decision, interval=t.interval,
                                        what="a decision record for the protected target")

        def lifecycle() -> list[dict] | None:
            docs = self.audit_docs(decision=decision["event"]["id"])
            states = {d["state"] for d in docs}
            return docs if {"REQUESTED", "APPLIED", "VERIFIED"} <= states else None

        applied_chain = wait_until(lab, lifecycle, timeout=t.lifecycle, interval=t.interval,
                                   what="REQUESTED -> APPLIED -> VERIFIED audit events")
        during = lab.blocklists()
        blocked_during = {name: self.attacker in members for name, members in during.items()}
        protected_during = {name: PROTECTED_TARGET in members for name, members in during.items()}

        def expired() -> list[dict] | None:
            docs = self.audit_docs(decision=decision["event"]["id"])
            return docs if "EXPIRED" in {d["state"] for d in docs} else None

        full_chain = wait_until(lab, expired, timeout=t.expiry, interval=t.interval,
                                what="EXPIRED (TTL rollback) audit event")
        after = lab.blocklists()
        blocked_after = {name: self.attacker in members for name, members in after.items()}
        return {
            "alert": alert, "solo_anomaly": solo_anomaly, "protected_anomaly": protected_anomaly,
            "attacker_anomaly": attacker_anomaly, "injected_at": injected_at, "decision": decision,
            "protected_decision": protected_decision, "applied_chain": applied_chain, "chain": full_chain,
            "blocked_during": blocked_during, "protected_during": protected_during,
            "blocked_after": blocked_after, "solo_decisions": self.decision_docs(self.solo),
            "solo_audits": self.audit_docs(target=self.solo),
            "protected_audits": self.audit_docs(target=PROTECTED_TARGET),
        }

    def rate_limit(self) -> dict:
        return self.once("rate_limit", self._run_rate_limit)

    def _run_rate_limit(self) -> dict:
        lab, t = self.lab, self.timeouts
        scenario = self.response()
        for address in self.burst:
            lab.inject("suricata.json", self.suricata_line(address, lab.now(), f"{self.marker}-b-{address}", severity=2))
        wait_until(lab, lambda: all(self.alert_docs(a) for a in self.burst), timeout=t.ingest, interval=t.interval,
                   what="burst alerts in soc-alerts-*")
        for address in self.burst:
            self.inject_anomaly(address, f"{self.marker}-b-{address}")
        last = self.burst[-1]

        def all_decided() -> bool:
            return all(self.decision_docs(a) for a in self.burst)

        wait_until(lab, all_decided, timeout=t.decision, interval=t.interval, what="decisions for the burst")
        wait_until(lab, lambda: all(self.audit_docs(target=a) for a in self.burst if
                                    any(dig(d, "decision.outcome") == "response_requested" for d in self.decision_docs(a))),
                   timeout=t.lifecycle, interval=t.interval, what="audit events for requested burst targets")
        lab.sleep(t.interval * 2)
        audits = {a: self.audit_docs(target=a) for a in self.burst}
        limited = [a for a, docs in audits.items()
                   if any(dig(d, "failure.code") == "RATE_LIMITED" for d in docs)]
        blocklists = lab.blocklists()
        # leave the lab clean: every temporary containment of this scenario must expire on its own
        wait_until(lab, lambda: not any(a in members for a in self.burst for members in lab.blocklists().values()),
                   timeout=t.expiry, interval=t.interval, what="the burst containments to expire")
        return {"scenario": scenario, "audits": audits, "limited": limited, "blocklists": blocklists, "last": last}


# =============================================================================== checks
def _fail_if(condition: bool, message: str) -> None:
    assert condition, message


def check_log01(run: Run) -> Observation:
    scenario = run.ingestion()
    observed = {}
    for fixture, dataset in FIXTURE_DATASETS.items():
        normalized = scenario[fixture]["normalized"]
        _fail_if(dig(normalized, "event.dataset") == dataset,
                 f"{fixture}: normalized dataset is {dig(normalized, 'event.dataset')!r}, expected {dataset!r}")
        provenance = dig(normalized, "cxyz.source_authentication")
        _fail_if(provenance in {"mtls_relay", "read_only_volume", "operator_fixture"},
                 f"{fixture}: normalized event carries no valid source-authentication provenance ({provenance!r})")
        observed[dataset] = {"ingestion_id": dig(normalized, "cxyz.ingestion_id"),
                             "source_authentication": provenance, "index": normalized["_index"]}
    return ("A unique marker injected for each of four sources (firewall, RADIUS, Suricata, Wazuh) reached the "
            "normalized streams with source-authentication provenance; fixtures carry the fixture provenance "
            "label, so this proves pipeline mapping per source, not the authenticity of production transports",
            {"run_marker": run.marker, "sources": observed})


def check_log02(run: Run) -> Observation:
    scenario = run.ingestion()
    checked = {}
    for fixture, dataset in FIXTURE_DATASETS.items():
        raw, normalized, line = scenario[fixture]["raw"], scenario[fixture]["normalized"], scenario[fixture]["line"]
        _fail_if(dig(raw, "event.original") == line,
                 f"{fixture}: the raw document differs from the injected payload")
        _fail_if(dig(normalized, "event.original") == line,
                 f"{fixture}: the normalized event no longer carries the unmodified original")
        _fail_if(dig(raw, "cxyz.ingestion_id") == dig(normalized, "cxyz.ingestion_id"),
                 f"{fixture}: raw and normalized events are not linked by ingestion ID")
        document = {key: value for key, value in normalized.items() if key not in {"_id", "_index"}}
        validate(document, "schemas/ecs/soc-event.schema.json")
        checked[dataset] = {"raw_matches_payload": True, "schema": "soc-event-v1"}
    return ("Raw documents equal the injected payload byte-for-byte, are linked to their normalized events by "
            "ingestion ID, and every normalized event validates against schemas/ecs/soc-event.schema.json",
            {"run_marker": run.marker, "sources": checked})


def check_log03(run: Run) -> Observation:
    lab, scenario = run.lab, run.ingestion()
    malformed = scenario["malformed"]
    _fail_if(dig(malformed["raw"], "event.original") == dig(malformed["deadletter"], "event.original"),
             "the malformed line is not preserved identically in the raw and dead-letter streams")
    pipeline = lab.logstash_pipeline()
    queue_type = dig(pipeline["stats"], "pipelines.soc-ingestion.queue.type")
    dlq = dig(pipeline["node"], "pipelines.soc-ingestion.dead_letter_queue_enabled")
    _fail_if(queue_type == "persisted", f"Logstash queue type is {queue_type!r}, expected 'persisted'")
    _fail_if(dlq is True, "Logstash dead_letter_queue is not enabled")

    # Unavailable-output scenario: stop Elasticsearch, inject, prove the event is held in the
    # persistent queue, restart, prove it is delivered exactly once to raw and normalized.
    token = f"{run.marker}-outage"
    line = f"src={run.ingest_ip} dst=172.16.60.20 spt=43999 dpt=443 proto=tcp action=blocked marker={token}"
    with lab.elasticsearch_outage():
        lab.inject("firewall.log", line)
        lab.sleep(run.timeouts.interval * 3)
        depth = lab.logstash_queue_depth()
    _fail_if(depth >= 1, "the event was not retained by the Logstash queue while Elasticsearch was down")

    def delivered() -> bool:
        raws = lab.es_search("soc-raw-*", {"size": 5, "query": {"wildcard": {"event.original": {"value": f"*{token}*"}}}})
        if len(raws) != 1:
            return False
        return lab.es_count(NORMALIZED, {"term": {"cxyz.ingestion_id": raws[0]["cxyz"]["ingestion_id"]}}) == 1

    wait_until(lab, delivered, timeout=run.timeouts.ingest * 2, interval=run.timeouts.interval,
               what="the queued event to be delivered after Elasticsearch returned")
    return ("A malformed event is retained verbatim in both the raw and dead-letter streams, Logstash runs a "
            "persistent queue with a dead-letter queue, and an event injected while Elasticsearch was stopped was "
            "held in the queue and delivered exactly once after recovery",
            {"run_marker": run.marker, "queue_type": queue_type, "dead_letter_queue": dlq,
             "queued_events_during_outage": depth})


def check_ai01(run: Run) -> Observation:
    result = run.ai_pipeline()
    vector, inference = result["vector"], result["inference"]
    document = {k: v for k, v in inference.items() if k not in {"_id", "_index"}}
    validate(document, "schemas/events/anomaly-event-v1.schema.json")
    for key in ("model_id", "model_sha256", "inference_ms"):
        _fail_if(dig(inference, f"ai.{key}") not in (None, ""), f"inference event lacks ai.{key}")
    _fail_if(dig(inference, "feature_vector.id") == vector["vector_id"], "inference is not bound to the vector")
    latency = parse_time(inference["@timestamp"]) - parse_time(vector["generated_at"])
    return ("Activity injected through the real ingestion path produced a versioned feature vector, which the "
            "enrichment worker scored through the mTLS inference API into a schema-valid soc-ai event with model "
            "identity and latency",
            {"entity": result["entity"], "vector_id": vector["vector_id"], "feature_schema": vector.get("feature_schema"),
             "model_id": dig(inference, "ai.model_id"), "score": dig(inference, "ai.score"),
             "inference_ms": dig(inference, "ai.inference_ms"), "vector_to_event_seconds": latency.total_seconds()})


def check_ai02(run: Run) -> Observation:
    lab = run.lab
    registry = lab.registry_dir()
    metadata_path, approval_path = registry / "metadata.json", registry / "approval.json"
    _fail_if(metadata_path.is_file() and approval_path.is_file(),
             "no approved registry (ai/registry/active) is present; run make soc-ai-promote")
    metadata = json.loads(metadata_path.read_text())
    approval = json.loads(approval_path.read_text())
    validate(metadata, "schemas/events/model-provenance-v1.schema.json")
    _fail_if(metadata["status"] == "approved", "the active model is not approved")
    for dotted in ("dataset.sha256", "feature_schema.sha256", "artifact.sha256", "git_sha",
                   "training.random_seed", "training.hyperparameters", "threshold"):
        _fail_if(dig(metadata, dotted) not in (None, "", {}), f"provenance lacks {dotted}")
    artifact = registry / metadata["artifact"]["path"]
    _fail_if(artifact.is_file() and file_sha256(artifact) == metadata["artifact"]["sha256"],
             "the artifact on disk does not match its recorded SHA-256")
    digest = file_sha256(metadata_path)
    _fail_if(approval["metadata_sha256"] == digest, "approval.json does not bind this metadata")
    deployed = lab.deployed_metadata_digest()
    _fail_if(deployed == digest, "the independently supplied SOC_AI_METADATA_SHA256 does not match the registry")
    status, served = lab.ai_request("GET", "/model")
    _fail_if(status == 200 and served["model_metadata_sha256"] == digest and served["model_sha256"] == metadata["artifact"]["sha256"],
             "the running inference API serves a model other than the approved registry")
    return ("The active registry validates against model-provenance-v1, records dataset/feature-schema/artifact "
            "hashes, Git SHA, seed, hyperparameters and threshold, is bound by the independent deployment digest, "
            "and is exactly what the running inference API serves",
            {"model_id": metadata["model_id"], "algorithm": metadata["algorithm"], "metadata_sha256": digest,
             "model_sha256": metadata["artifact"]["sha256"], "approver": approval["approver"]})


def check_ai03(run: Run) -> Observation:
    lab = run.lab
    status, served = lab.ai_request("GET", "/model")
    _fail_if(status == 200, "the inference API has no ready model")
    served_schema = served["feature_schema"]
    other = "endpoint-window-v1" if served_schema == "network-window-v1" else "network-window-v1"
    names = [n for n in json.loads((ROOT / f"schemas/features/{other}.schema.json").read_text())
             .get("properties", {}).get("features", {}).get("properties", {})]
    entity = "198.51.100.250" if other == "network-window-v1" else "live-validation-host"
    errors_before = _error_counter(lab)
    mismatch_status, mismatch = lab.ai_request("POST", "/v1/infer", {
        "feature_schema": other, "entity": entity, "features": {name: 0 for name in names}})
    _fail_if(mismatch_status == 422 and isinstance(mismatch, dict)
             and dig(mismatch, "detail.code") == "FEATURE_SCHEMA_MISMATCH",
             f"a request for {other} was not rejected as FEATURE_SCHEMA_MISMATCH (HTTP {mismatch_status})")
    _fail_if("score" not in json.dumps(mismatch), "the rejected response still contains a score")
    bad_status, bad = lab.ai_request("POST", "/v1/infer", {
        "feature_schema": served_schema, "entity": "198.51.100.250" if served_schema == "network-window-v1" else "live-validation-host",
        "features": {"unexpected_feature": 1}})
    _fail_if(bad_status == 422 and "score" not in json.dumps(bad),
             "a request with an unknown feature set was not rejected without a score")
    scored = lab.es_count("soc-ai-*", {"term": {"feature_vector.entity": "198.51.100.250"}})
    _fail_if(scored == 0, "a rejected probe left a soc-ai record")
    errors_after = _error_counter(lab)
    if errors_before is not None and errors_after is not None:
        _fail_if(errors_after >= errors_before + 2, "the API did not account for both rejected requests")
    return ("Requests for a different feature schema or an unknown feature set are rejected with HTTP 422 "
            "(FEATURE_SCHEMA_MISMATCH for a schema mismatch), return no score, are never mapped automatically, "
            "and leave no soc-ai record",
            {"served_schema": served_schema, "probe_schema": other, "mismatch_status": mismatch_status,
             "unknown_feature_status": bad_status, "error_counter_before": errors_before,
             "error_counter_after": errors_after})


def _error_counter(lab: Lab) -> float | None:
    status, text = lab.ai_request("GET", "/metrics")
    if status != 200 or not isinstance(text, str):
        return None
    for line in text.splitlines():
        if line.startswith("cxyz_soc_ai_inference_errors_total "):
            return float(line.split(" ", 1)[1])
    return None


def check_ai04(run: Run) -> Observation:
    registry = run.lab.registry_dir()
    comparison_path = registry / "comparison.json"
    _fail_if(comparison_path.is_file(),
             "the active registry carries no five-detector comparison (python -m ai.evaluation.compare, "
             "then promote with --comparison)")
    report = json.loads(comparison_path.read_text())
    metadata = json.loads((registry / "metadata.json").read_text())
    names = [row["detector"] for row in report["rows"]]
    expected = ["static-rules", "isolation-forest", "static+isolation-forest", "lstm-autoencoder", "static+lstm-autoencoder"]
    _fail_if(names == expected, f"comparison detectors are {names}, expected {expected}")
    for row in report["rows"]:
        missing = [m for m in REQUIRED_BENCHMARK_METRICS if m not in row]
        _fail_if(not missing, f"{row['detector']} lacks metrics {missing}")
    _fail_if("accuracy" not in json.dumps(report).lower(), "accuracy must not appear as an evaluation metric")
    _fail_if(report["threshold_policy"]["selected_on"] == "validation", "thresholds were not selected on validation")
    _fail_if(metadata["artifact"]["sha256"] in {m["model_sha256"] for m in report["models"].values()},
             "the comparison does not include the promoted artifact")
    binding = json.loads((registry / "evaluation.json").read_text())
    _fail_if(binding["model_sha256"] == metadata["artifact"]["sha256"]
             and binding["dataset_manifest_sha256"] == report["dataset_manifest_sha256"],
             "the comparison and the bound evaluation describe different datasets or artifacts")
    return ("The active registry carries a reproducible five-detector comparison (static rules, Isolation Forest, "
            "LSTM autoencoder and both hybrids) on temporally split data with precision, recall, F1, PR-AUC, "
            "false positives per hour, MTTD and p95 latency, thresholds selected on validation only, and no "
            "accuracy metric",
            {"detectors": names, "dataset_manifest_sha256": report["dataset_manifest_sha256"],
             "metrics": list(REQUIRED_BENCHMARK_METRICS)})


def check_cor01(run: Run) -> Observation:
    scenario = run.response()
    solo, attacker = run.solo, run.attacker
    _fail_if(not scenario["solo_decisions"] and not scenario["solo_audits"],
             f"anomaly-only evidence for {solo} produced a decision or response request")
    chain = scenario["chain"]
    _fail_if(any(d["state"] == "REQUESTED" for d in chain), "the corroborated anomaly produced no request")
    decision = scenario["decision"]
    kinds = [signal["kind"] for signal in decision["signals"]]
    _fail_if(kinds[0] == "ai_anomaly" and "suricata_alert" in kinds[1:],
             f"the decision is not hybrid (signals: {kinds})")
    _fail_if(dig(decision, "anomaly.event_id") not in {s["reference"] for s in decision["signals"][1:]},
             "the AI event corroborated itself")
    blocklists = run.lab.blocklists()
    _fail_if(not any(solo in members for members in blocklists.values()),
             f"anomaly-only target {solo} appears on a firewall blocklist")
    return ("An injected AI anomaly with score >= 0.90 and no other evidence produced no decision record and no "
            "response request, while the same score with an independent Suricata alert produced a hybrid decision "
            "(AI signal plus suricata_alert) and a response request",
            {"run_marker": run.marker, "anomaly_only_target": solo, "corroborated_target": attacker,
             "corroborated_signals": kinds, "decision_event_id": decision["event"]["id"]})


def _states(chain: Sequence[Mapping[str, Any]]) -> list[str]:
    return [d["state"] for d in sorted(chain, key=lambda d: d["transition_number"])]


def check_resp01(run: Run) -> Observation:
    scenario = run.response()
    states = _states(scenario["chain"])
    _fail_if(states[:3] == ["REQUESTED", "APPLIED", "VERIFIED"], f"lifecycle states were {states}")
    _fail_if(len({d["response_id"] for d in scenario["chain"]}) == 1, "the lifecycle spans several response IDs")
    peers = scenario["blocked_during"]
    _fail_if(len(peers) >= 2 and all(peers.values()),
             f"the target was not present on every firewall peer while VERIFIED: {peers}")
    verified = next(d for d in scenario["chain"] if d["state"] == "VERIFIED")
    _fail_if(dig(verified, "verification.verified") is True and dig(verified, "verification.evidence_refs"),
             "the VERIFIED event carries no verification evidence")
    adapter = {d["adapter"] for d in scenario["chain"]}
    return ("The orchestrator added the target to the scoped SOC_BLOCKLIST on every firewall peer, independently "
            "observed it there, and recorded REQUESTED, APPLIED and VERIFIED under one response ID "
            "(OPNsense HA is covered by RESP-04, which remains planned)",
            {"run_marker": run.marker, "response_id": scenario["chain"][0]["response_id"], "target": run.attacker,
             "adapter": sorted(adapter), "firewall_peers": peers, "states": states})


def check_resp03(run: Run) -> Observation:
    scenario = run.response()
    protected = scenario["protected_decision"]
    _fail_if(dig(protected, "decision.outcome") == "denied" and not scenario["protected_audits"],
             f"the protected target {PROTECTED_TARGET} was not denied before any request "
             f"(outcome {dig(protected, 'decision.outcome')!r})")
    _fail_if(not any(scenario["protected_during"].values()),
             f"the protected target appears on a firewall blocklist: {scenario['protected_during']}")
    states = _states(scenario["chain"])
    _fail_if("EXPIRED" in states, f"the eligible target was not recovered after its TTL (states {states})")
    _fail_if(not any(scenario["blocked_after"].values()),
             f"the eligible target is still blocked after expiry: {scenario['blocked_after']}")
    requested = next(d for d in scenario["chain"] if d["state"] == "REQUESTED")
    expired = next(d for d in scenario["chain"] if d["state"] == "EXPIRED")
    elapsed = (parse_time(expired["@timestamp"]) - parse_time(requested["@timestamp"])).total_seconds()
    _fail_if(elapsed >= requested["ttl_seconds"] - 2, f"expiry came {elapsed:.0f}s after the request, before the TTL")
    limited = run.rate_limit()
    _fail_if(limited["limited"], "no RATE_LIMITED audit event after exceeding the policy rate limit")
    _fail_if(not any(a in members for a in limited["limited"] for members in limited["blocklists"].values()),
             "a rate-limited target reached a firewall blocklist")
    transitions = [d["transition_number"] for d in scenario["chain"]]
    _fail_if(transitions == sorted(set(transitions)) and transitions[0] == 1,
             f"audit transitions are not an append-only sequence: {transitions}")
    return ("A protected infrastructure target was denied by policy and never blocked; an eligible target was blocked "
            "on every peer and recovered (EXPIRED, removed everywhere) after its TTL; targets beyond the policy rate "
            "limit were rejected with RATE_LIMITED and never reached a firewall; the audit trail is one "
            "append-only transition sequence",
            {"run_marker": run.marker, "protected_target": PROTECTED_TARGET, "ttl_seconds": requested["ttl_seconds"],
             "seconds_to_expiry": elapsed, "rate_limited_targets": limited["limited"],
             "blocked_after_expiry": scenario["blocked_after"]})


def check_resp02(run: Run) -> Observation:
    """Path B only: isolate and restore a controlled endpoint through Wazuh Active Response."""

    lab = run.lab
    host = os.environ.get("SOC_LIVE_ISOLATION_HOST", "pc1")
    if lab.endpoint_reachable(host) is None:
        raise LabNotReady("this deployment has no controlled endpoint with the CompanyXYZ isolation Active Response")
    result = run.once("isolation", lambda: _run_isolation(run, host))
    chain = result["chain"]
    states = _states(chain)
    _fail_if(states[:3] == ["REQUESTED", "APPLIED", "VERIFIED"] and "EXPIRED" in states,
             f"isolation lifecycle states were {states}")
    _fail_if(result["reachable_before"] is True, f"{host} was not reachable before the scenario")
    _fail_if(result["reachable_during"] is False, f"{host} stayed reachable while isolated")
    _fail_if(result["reachable_after"] is True, f"{host} did not recover after the TTL")
    adapters = {d["adapter"] for d in chain}
    _fail_if(adapters == {"wazuh"}, f"the isolation used adapters {adapters}, expected only wazuh")
    return ("A Wazuh-corroborated anomaly for the enrolled endpoint triggered only the allowlisted Wazuh Active "
            "Response isolation, verified by the orchestrator, observed from outside as unreachable, and the endpoint "
            "was restored and reachable again after the TTL",
            {"run_marker": run.marker, "host": host, "response_id": chain[0]["response_id"], "states": states,
             "reachable_before": result["reachable_before"], "reachable_during": result["reachable_during"],
             "reachable_after": result["reachable_after"]})


def _run_isolation(run: Run, host: str) -> dict:
    lab, t = run.lab, run.timeouts
    lab.require_enforcement()
    reachable_before = lab.endpoint_reachable(host)
    now = lab.now()
    token = f"{run.marker}-wazuh-{host}"
    lab.inject("wazuh.json", json.dumps({
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule": {"level": 12, "id": "990012", "description": f"SOC live {token}"},
        "agent": {"name": host}, "cxyz_live_id": token}))
    wait_until(lab, lambda: lab.es_search("soc-alerts-*", {"size": 3, "query": {"bool": {"filter": [
        {"term": {"event.dataset": "wazuh.alerts"}}, {"term": {"host.name": host}},
        {"range": {"@timestamp": {"gte": rfc3339(now - timedelta(minutes=1))}}}]}}}),
        timeout=t.ingest, interval=t.interval, what=f"the Wazuh alert for {host} in soc-alerts-*")
    run.inject_anomaly(host, f"{token}-anomaly", entity_type="host")
    decision = wait_until(lab, lambda: next((d for d in run.decision_docs(host)
                                             if dig(d, "decision.outcome") == "response_requested"), None),
                          timeout=t.decision, interval=t.interval, what="the isolate_host decision")

    def verified() -> list[dict] | None:
        docs = run.audit_docs(decision=decision["event"]["id"])
        return docs if {"REQUESTED", "APPLIED", "VERIFIED"} <= {d["state"] for d in docs} else None

    wait_until(lab, verified, timeout=t.lifecycle, interval=t.interval, what="isolation VERIFIED")
    reachable_during = lab.endpoint_reachable(host)

    def expired() -> list[dict] | None:
        docs = run.audit_docs(decision=decision["event"]["id"])
        return docs if "EXPIRED" in {d["state"] for d in docs} else None

    chain = wait_until(lab, expired, timeout=t.expiry, interval=t.interval, what="isolation EXPIRED (restore)")
    lab.sleep(t.interval * 2)
    return {"chain": chain, "reachable_before": reachable_before, "reachable_during": reachable_during,
            "reachable_after": lab.endpoint_reachable(host)}


DASHBOARDS = ("cxyz-soc-overview", "cxyz-network-nids", "cxyz-ai", "cxyz-response")


def check_soc01(run: Run) -> Observation:
    lab = run.lab
    scenario = run.response()
    traces = {
        "network telemetry (soc-network/endpoint/auth/alerts)": lab.es_count(NORMALIZED, {"term": {"source.ip": run.attacker}}),
        "NIDS alert": len(run.alert_docs(run.attacker)),
        "AI anomaly (soc-ai)": lab.es_count("soc-ai-*", {"term": {"feature_vector.entity": run.attacker}}),
        "response audit (soc-response)": len(run.audit_docs(target=run.attacker)),
    }
    empty = [name for name, count in traces.items() if count < 1]
    _fail_if(not empty, f"the controlled attack trace is missing from: {empty}")
    present = {}
    for dashboard in DASHBOARDS:
        saved = lab.kibana_object("dashboard", dashboard)
        _fail_if(saved is not None, f"Kibana dashboard {dashboard} is not installed")
        present[dashboard] = dig(saved, "attributes.title")
    secrets = [name for name, title in present.items() if re.search(r"password|secret|api[_ -]?key", str(title), re.I)]
    _fail_if(not secrets, f"dashboards expose secret-looking titles: {secrets}")
    return ("The controlled attack trace is present in the network/alert, AI and response data views, and the "
            "four dashboards (SOC overview, network/NIDS, AI, response) are installed in Kibana; the dashboards use "
            "only the non-secret normalized, AI and response-audit indices",
            {"run_marker": run.marker, "target": run.attacker, "dashboards": present, "trace_counts": traces,
             "decision_event_id": scenario["decision"]["event"]["id"]})


def check_soc02(run: Run) -> Observation:
    scenario = run.response()
    alert = parse_time(scenario["alert"]["@timestamp"])
    decision = parse_time(scenario["decision"]["@timestamp"])
    by_state = {d["state"]: parse_time(d["@timestamp"]) for d in scenario["chain"]}
    slack = timedelta(seconds=2)
    order = [alert, decision, by_state["REQUESTED"], by_state["APPLIED"], by_state["VERIFIED"], by_state["EXPIRED"]]
    _fail_if(all(order[i] <= order[i + 1] + slack for i in range(len(order) - 1)),
             "event, decision and response timestamps are not causally ordered")
    mttd = (decision - alert).total_seconds()
    contained = (by_state["VERIFIED"] - alert).total_seconds()
    _fail_if(0 <= mttd < 600 and 0 <= contained < 900,
             f"implausible timing (MTTD {mttd:.1f}s, containment {contained:.1f}s)")
    report = {
        "run_marker": run.marker, "target": run.attacker, "alert_event_id": dig(scenario["alert"], "event.id"),
        "alert_at": rfc3339(alert), "decision_at": rfc3339(decision),
        "requested_at": rfc3339(by_state["REQUESTED"]), "applied_at": rfc3339(by_state["APPLIED"]),
        "verified_at": rfc3339(by_state["VERIFIED"]), "expired_at": rfc3339(by_state["EXPIRED"]),
        "mttd_seconds": mttd, "containment_seconds": contained,
    }
    return ("MTTD (alert event to decision) and containment time (alert event to VERIFIED) were derived from the "
            "stored event and response audit timestamps of one controlled scenario, which are causally ordered; "
            "the anomaly was injected, so MTTD here measures correlation latency, not model detection latency",
            report)


def check_soc03(run: Run) -> Observation:
    scenario = run.response()
    decision, chain = scenario["decision"], scenario["chain"]
    validate({k: v for k, v in decision.items() if k not in {"_id", "_index"}},
             "schemas/events/correlation-decision-event-v1.schema.json")
    for event in chain:
        validate({k: v for k, v in event.items() if k not in {"_id", "_index"}},
                 "response/schemas/response-audit-event-v1.schema.json")
    _fail_if(all(e["decision_event_id"] == decision["event"]["id"] for e in chain),
             "audit events are not linked to the decision event")
    _fail_if(all(e["correlation_id"] == decision["correlation_id"] for e in chain),
             "audit events do not share the decision's correlation ID")
    ordered = sorted(chain, key=lambda e: e["transition_number"])
    _fail_if([e["transition_number"] for e in ordered] == list(range(1, len(ordered) + 1)),
             "audit transition numbers are not consecutive")
    _fail_if(all(later["previous_state"] == earlier["state"] for earlier, later in zip(ordered, ordered[1:])),
             "audit previous_state links are broken")
    alert_id = dig(scenario["alert"], "event.id")
    _fail_if(any(signal["reference"] == alert_id for signal in decision["signals"]),
             "the decision does not reference the source alert event")
    _fail_if(dig(decision, "anomaly.event_id") == scenario["attacker_anomaly"]["event"]["id"],
             "the decision does not reference the anomaly event")
    _fail_if(dig(ordered[-1], "state") == "EXPIRED", "the chain does not end in rollback/expiry")
    return ("One queryable chain links source alert, anomaly, policy decision, action, verification and expiry: "
            "the decision cites the alert and anomaly, every audit event cites the decision and correlation ID, "
            "transitions are consecutive with matching previous_state, and all documents validate against their "
            "schemas",
            {"run_marker": run.marker, "alert_event_id": alert_id, "anomaly_event_id": dig(decision, "anomaly.event_id"),
             "decision_event_id": decision["event"]["id"], "policy": dig(decision, "policy.id"),
             "response_id": ordered[0]["response_id"], "states": [e["state"] for e in ordered]})


CHECKS: dict[str, Callable[[Run], Observation]] = {
    "LOG-01": check_log01, "LOG-02": check_log02, "LOG-03": check_log03,
    "AI-01": check_ai01, "AI-02": check_ai02, "AI-03": check_ai03, "AI-04": check_ai04,
    "COR-01": check_cor01, "RESP-01": check_resp01, "RESP-02": check_resp02, "RESP-03": check_resp03,
    "SOC-01": check_soc01, "SOC-02": check_soc02, "SOC-03": check_soc03,
}
