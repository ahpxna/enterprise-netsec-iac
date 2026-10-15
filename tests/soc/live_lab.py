"""In-process stand-in for the deployed lab, used to test the live SOC verifiers offline.

It runs the REAL decision runner, policy catalog, signing, orchestrator, audit exporter
and inference API; only the periphery is simulated: Logstash normalisation of the four
fixture files, the feature/enrichment workers (a fixed-delay emulation), the firewall
and Wazuh endpoints, and Kibana.  Time is virtual: ``sleep`` advances the clock and
runs the services exactly as their real loops would.  This proves the verifiers'
queries, field names, ordering assumptions and verdict logic against the actual code;
it says nothing about the live Docker/VyOS stack.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import re

from fastapi.testclient import TestClient

from ai.api.main import create_app
from ai.features.contracts import NETWORK_FEATURES
from response.decision import DecisionEngine
from response.orchestrator import ResponseOrchestrator, SQLiteResponseStore
from response.policy import PolicyCatalog
from response.service.decision_runner import DecisionRunner, DecisionState
from response.service.runner import AuditExporter, ResponseService
from response.signing import Ed25519CommandAuthenticator, generate_key_pair
from soc.workers.common import ElasticClient
from soc.workers.https import DeliveryError

from fake_elastic import FakeElastic
from test_durable_response import FakeAdapter

ROOT = Path(__file__).resolve().parents[2]
START = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)
AI_PIPELINE_DELAY = timedelta(minutes=7)


class IpFirewall(FakeAdapter):
    """Records which addresses are on the (simulated) SOC_BLOCKLIST of both peers."""

    def __init__(self):
        super().__init__("nftables", "block_ip")
        self.ips: set[str] = set()

    def apply(self, command):
        self.ips.add(command["target"]["value"])
        return super().apply(command)

    def revert(self, command, *, adapter_reference):
        self.ips.discard(command["target"]["value"])
        return super().revert(command, adapter_reference=adapter_reference)


class EndpointIsolation(FakeAdapter):
    def __init__(self):
        super().__init__("wazuh", "isolate_host")
        self.isolated: set[str] = set()

    def apply(self, command):
        self.isolated.add(command["target"]["value"])
        return super().apply(command)

    def revert(self, command, *, adapter_reference):
        self.isolated.discard(command["target"]["value"])
        return super().revert(command, adapter_reference=adapter_reference)


def _stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _day(moment: datetime) -> str:
    return moment.strftime("%Y.%m.%d")


class InProcessLab:
    def __init__(self, tmp_path: Path, *, policy: str = "lab-validation", with_endpoint: bool = False,
                 registry=None, enforce: bool = True) -> None:
        self.environment = "path-b" if with_endpoint else "path-a"
        self.clock = START
        self.fake = FakeElastic()
        self.enforce = enforce
        self.registry = registry
        private, _ = generate_key_pair(tmp_path / "keys", "decision-live")
        signer = Ed25519CommandAuthenticator.signer(private, "decision-live")
        verifier = Ed25519CommandAuthenticator.verifier(tmp_path / "keys")
        catalog = PolicyCatalog.from_path(ROOT / f"response/policies/{policy}.yaml")
        self.firewall = IpFirewall()
        self.endpoint = EndpointIsolation()
        self.store = SQLiteResponseStore(tmp_path / "journal.sqlite")
        orchestrator = ResponseOrchestrator(catalog=catalog, authenticator=verifier, store=self.store,
                                            adapters=[self.firewall, self.endpoint])
        self.service = ResponseService(orchestrator=orchestrator,
                                       exporter=AuditExporter(self.store, ElasticClient(self.fake)),
                                       mode="enforce", clock=self.now, recover_every=1)
        self.service.start()
        self.state = DecisionState(tmp_path / "decision.sqlite")
        self.runner = DecisionRunner(
            elastic=ElasticClient(self.fake), engine=DecisionEngine(catalog, signer), state=self.state,
            mode="enforce", send_command=self._deliver, clock=self.now, protected_assets=["172.16.50.1"])
        self.held: list[tuple[str, str]] = []
        self.outage = False
        self.ai_pending: dict[str, datetime] = {}
        self.ai_done: set[str] = set()
        self.client = (TestClient(create_app(model_dir=registry.path, trusted_metadata_sha256=registry.digest))
                       if registry is not None else None)

    # -- Lab: time
    def now(self) -> datetime:
        return self.clock

    def sleep(self, seconds: float) -> None:
        remaining = float(seconds)
        while remaining > 0:
            step = min(remaining, 1.0)
            self.clock += timedelta(seconds=step)
            remaining -= step
            self._emulate_ai_pipeline()
            self.runner.run_once()
            self.service.tick()

    def _deliver(self, command) -> None:
        result = self.service.accept(command)
        if not result.get("accepted"):
            raise DeliveryError("COMMAND_NOT_ACCEPTED", retryable=False)

    # -- Lab: Elasticsearch
    def es_search(self, index: str, body) -> list[dict]:
        return [{**hit["_source"], "_id": hit["_id"], "_index": hit["_index"]}
                for hit in self.fake._search(index, dict(body))]

    def es_count(self, index: str, query) -> int:
        return len(self.fake._search(index, {"query": query, "size": 100000}))

    def es_create(self, index: str, doc_id: str, document) -> None:
        self.fake.request("PUT", f"/{index}/_create/{doc_id}", dict(document))

    # -- Lab: Logstash emulation
    def inject(self, fixture: str, line: str) -> None:
        if self.outage:
            self.held.append((fixture, line))
            return
        self._ingest(fixture, line)

    def _ingest(self, fixture: str, line: str) -> None:
        now = self.clock
        ingestion_id = sha256(f"{fixture}|{line}".encode()).hexdigest()
        source = {"firewall.log": "firewall", "radius.log": "freeradius", "suricata.json": "suricata",
                  "wazuh.json": "wazuh"}[fixture]
        common = {"@timestamp": _stamp(now), "cxyz": {"ingestion_id": ingestion_id,
                                                      "source_authentication": "operator_fixture"}}
        self.fake.add(f"soc-raw-{_day(now)}", ingestion_id, {
            **common, "event": {"id": ingestion_id, "kind": "event", "dataset": f"{source}.raw", "original": line},
            "cxyz": {**common["cxyz"], "schema_version": "soc-raw-v1"}})
        base = {
            "event": {"id": ingestion_id, "kind": "event", "original": line},
            "observer": {"name": f"{source}-01", "type": "ids" if source == "suricata" else "firewall"},
            "cxyz": {"schema_version": "soc-event-v1", "sensor": f"{source}-01", "zone": "soc", "vlan": None,
                     "asset_role": "network_sensor", "ingestion_id": ingestion_id,
                     "source_authentication": "operator_fixture"},
        }

        def put(family: str, moment: datetime, **fields) -> None:
            event = {**base["event"], **fields.pop("event")}
            document = {**base, "@timestamp": _stamp(moment), "event": event, **fields}
            self.fake.add(f"soc-{family}-{_day(moment)}", ingestion_id, document)

        if fixture == "firewall.log":
            pairs = dict(re.findall(r"(\w+)=(\S+)", line))
            put("network", now, event={"dataset": "firewall.syslog", "category": ["network"], "action": pairs["action"]},
                source={"ip": pairs["src"]}, destination={"ip": pairs["dst"], "port": int(pairs["dpt"])})
            if "-ai" in line:
                self.ai_pending.setdefault(pairs["src"], now)
        elif fixture == "radius.log":
            pairs = dict(re.findall(r"(\w+)=(\S+)", line))
            put("auth", now, event={"dataset": "freeradius.auth", "category": ["authentication"],
                                     "outcome": pairs["outcome"]},
                source={"ip": pairs["src"]}, user={"name": pairs["user"]})
        else:
            try:
                payload = json.loads(line)
            except ValueError:
                self.fake.add(f"soc-deadletter-{_day(now)}", ingestion_id, {
                    **common, "event": {"id": ingestion_id, "original": line}, "error": {"message": "parse failure"},
                    "tags": ["_parse_failure"]})
                return
            moment = datetime.strptime(payload["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
            if fixture == "suricata.json":
                put("alerts", moment, event={"dataset": "suricata.eve", "category": ["network", "intrusion_detection"]},
                    source={"ip": payload["src_ip"]}, destination={"ip": payload["dest_ip"]},
                    alert={"severity": payload["alert"]["severity"], "signature": payload["alert"]["signature"]})
            else:
                put("alerts", moment, event={"dataset": "wazuh.alerts", "category": ["intrusion_detection"],
                                              "severity": payload["rule"]["level"]},
                    host={"name": payload["agent"]["name"]},
                    **({"source": {"ip": payload["data"]["srcip"]}} if "data" in payload else {}))

    def logstash_pipeline(self) -> dict:
        return {"node": {"pipelines": {"soc-ingestion": {"dead_letter_queue_enabled": True}}},
                "stats": {"pipelines": {"soc-ingestion": {"queue": {"type": "persisted", "events_count": len(self.held)}}}}}

    def logstash_queue_depth(self) -> int:
        return len(self.held)

    @contextmanager
    def elasticsearch_outage(self):
        self.outage = True
        try:
            yield self
        finally:
            self.outage = False
            held, self.held = self.held, []
            for fixture, line in held:
                self._ingest(fixture, line)

    # -- Lab: AI pipeline emulation (fixed delay; scoring through the real inference API)
    def _emulate_ai_pipeline(self) -> None:
        if self.client is None:
            return
        for entity, first_seen in list(self.ai_pending.items()):
            if entity in self.ai_done or self.clock < first_seen + AI_PIPELINE_DELAY:
                continue
            self.ai_done.add(entity)
            features = dict.fromkeys(NETWORK_FEATURES, 0)
            features.update(connection_count=12, unique_dst_ip=1, unique_dst_port=12, blocked_ratio=1.0, bytes_out=720)
            reply = self.client.post("/v1/infer", json={"feature_schema": "network-window-v1", "entity": entity,
                                                         "features": features}).json()
            schema_sha = reply["feature_schema_sha256"]
            digest = sha256(f"{entity}|{first_seen}".encode()).hexdigest()
            vector_id = "v-" + digest[:24]
            end = self.clock - timedelta(minutes=1)
            self.fake.add(f"soc-features-{_day(self.clock)}", vector_id, {
                "schema_version": "feature-vector-v1", "feature_schema": "network-window-v1",
                "feature_schema_sha256": schema_sha, "vector_id": vector_id, "entity_type": "src_ip", "entity": entity,
                "window_start": _stamp(end - timedelta(minutes=5)), "window_end": _stamp(end),
                "generated_at": _stamp(self.clock), "features": features})
            self.fake.add(f"soc-ai-{_day(self.clock)}", "ai-" + digest[:24], {
                "@timestamp": _stamp(self.clock + timedelta(seconds=30)), "schema_version": "anomaly-event-v1",
                "event": {"id": "ai-" + digest[:24], "kind": "event", "category": ["anomaly_detection"],
                          "dataset": "soc.ai.anomaly"},
                "observer": {"name": "soc-ai-inference", "type": "ai_inference"},
                "feature_vector": {"id": vector_id, "feature_schema": "network-window-v1",
                                   "feature_schema_sha256": schema_sha, "entity_type": "src_ip", "entity": entity,
                                   "window_start": _stamp(end - timedelta(minutes=5)), "window_end": _stamp(end),
                                   "source_event_set_sha256": digest},
                "ai": {"model_id": reply["model_id"], "algorithm": reply["algorithm"],
                       "model_sha256": reply["model_sha256"], "model_metadata_sha256": reply["model_metadata_sha256"],
                       "score": reply["score"], "threshold": reply["threshold"], "is_anomaly": reply["is_anomaly"],
                       "inference_ms": reply["inference_ms"]}})

    def ai_request(self, method: str, path: str, body=None):
        if self.client is None:
            from soc_live import LabNotReady

            raise LabNotReady("no inference API in this lab")
        reply = self.client.request(method, path, json=body)
        try:
            return reply.status_code, reply.json()
        except ValueError:
            return reply.status_code, reply.text

    # -- Lab: response plane / network
    def require_enforcement(self) -> dict:
        if not self.enforce:
            from soc_live import LabNotReady

            raise LabNotReady("decision and orchestrator must run in enforce mode")
        return {"modes": {"soc-decision": "enforce", "soc-response": "enforce"}, "policy_ttl_seconds": 60}

    def blocklists(self) -> dict[str, set[str]]:
        return {"fw-core": set(self.firewall.ips), "fw-dmz": set(self.firewall.ips)}

    def endpoint_reachable(self, host: str):
        return None if self.environment == "path-a" else host not in self.endpoint.isolated

    def kibana_object(self, kind: str, object_id: str):
        for raw in (ROOT / "soc/kibana/saved-objects/soc-overview.ndjson").read_text().splitlines():
            document = json.loads(raw)
            if document["type"] == kind and document["id"] == object_id:
                return {"id": object_id, "type": kind, "attributes": document["attributes"]}
        return None

    def registry_dir(self) -> Path:
        return self.registry.path

    def deployed_metadata_digest(self) -> str:
        return self.registry.digest

    def close(self) -> None:
        self.state.close()
        self.store.close()

