"""Feature export -> durable outbox -> mutual-TLS inference -> soc-ai-*.

Run with python -m soc.workers.enrichment. Import and delivery are separate;
static Logstash ingestion never waits for this worker.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import time

from ai.features.contracts import FeatureSchemaError, validate_vector
from .common import ElasticClient, elastic_from_environment, elastic_transport_from_environment
from .https import DeliveryError, JsonHTTPS
from .outbox import Outbox


def anomaly_event(vector: dict, result: dict, *, identifier: str,
                  metadata_hash: str, observer: str) -> dict:
    """Bind a scored event to the exact feature vector and approved model."""
    expected = {
        "model_id", "algorithm", "feature_schema", "feature_schema_sha256", "model_sha256",
        "model_metadata_sha256", "score", "threshold", "is_anomaly", "inference_ms",
    }
    if set(result) != expected:
        raise DeliveryError("INFERENCE_RESPONSE_CONTRACT", retryable=False)
    if (result["feature_schema"] != vector["feature_schema"]
            or result["feature_schema_sha256"] != vector["feature_schema_sha256"]
            or result["model_metadata_sha256"] != metadata_hash):
        raise DeliveryError("MODEL_OR_SCHEMA_MISMATCH", retryable=False)
    for name in ("model_sha256", "model_metadata_sha256"):
        if not isinstance(result[name], str) or not re.fullmatch(r"[a-f0-9]{64}", result[name]):
            raise DeliveryError("INVALID_MODEL_HASH", retryable=False)
    if (result["algorithm"] != "IsolationForest" or not isinstance(result["model_id"], str)
            or not result["model_id"]):
        raise DeliveryError("INVALID_MODEL_IDENTITY", retryable=False)
    for name in ("score", "threshold", "inference_ms"):
        value = result[name]
        try:
            finite = type(value) in (int, float) and math.isfinite(value)
        except OverflowError:
            finite = False
        if (not finite or value < 0
                or (name != "inference_ms" and value > 1)):
            raise DeliveryError("INVALID_INFERENCE_NUMBER", retryable=False)
    if (not isinstance(result["is_anomaly"], bool)
            or result["is_anomaly"] != (result["score"] >= result["threshold"])):
        raise DeliveryError("INCONSISTENT_ANOMALY_DECISION", retryable=False)
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "schema_version": "anomaly-event-v1",
        "event": {"id": identifier, "kind": "event", "category": ["anomaly_detection"],
                  "dataset": "soc.ai.anomaly"},
        "observer": {"name": observer, "type": "ai_inference"},
        "feature_vector": {
            "id": vector["vector_id"],
            **{name: vector[name] for name in (
                "feature_schema", "feature_schema_sha256", "entity_type", "entity",
                "window_start", "window_end", "source_event_set_sha256")},
        },
        "ai": {name: result[name] for name in (
            "model_id", "algorithm", "model_sha256", "model_metadata_sha256",
            "score", "threshold", "is_anomaly", "inference_ms")},
    }


def make_history_fetcher(elastic: ElasticClient, length: int):
    """Fetch the ``length - 1`` windows before a vector for sequence-model scoring."""

    from ai.features.sequences import history_window_ends

    def fetch(vector: dict) -> list:
        ends = history_window_ends(vector["window_end"], length)
        hits = elastic.search("soc-features-*", {
            "size": len(ends),
            "query": {"bool": {"filter": [
                {"term": {"feature_schema": vector["feature_schema"]}},
                {"term": {"entity": vector["entity"]}},
                {"terms": {"window_end": ends}},
            ]}},
            "_source": ["window_end", "features"],
        })
        by_end = {hit["_source"]["window_end"]: hit["_source"]["features"] for hit in hits}
        return [by_end.get(end) for end in ends]

    return fetch


def serving_sequence_length(inference: JsonHTTPS) -> int:
    status, reply = inference.request("GET", "/model")
    length = reply.get("sequence_length", 1) if status == 200 else None
    if type(length) is not int or length < 1:
        raise DeliveryError("INFERENCE_MODEL_NOT_READY", retryable=True)
    return length


def drain(outbox: Outbox, inference: JsonHTTPS, elastic: JsonHTTPS, *, limit: int,
          history_fetcher=None) -> dict:
    """One bounded batch. Outer scheduler chooses when to invoke again.

    ``history_fetcher`` supplies the preceding windows for sequence models.
    """
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise ValueError("limit must be between 1 and 10000")
    with outbox.exclusive():
        for job in outbox.due(limit):
            try:
                event = json.loads(job["event"]) if job["event"] else None
                if event is None:
                    vector = json.loads(job["vector"])
                    validate_vector(vector)
                    body = {
                        "feature_schema": vector["feature_schema"], "entity": vector["entity"],
                        "features": vector["features"],
                    }
                    if history_fetcher is not None:
                        body["history"] = history_fetcher(vector)
                    status, result = inference.request("POST", "/v1/infer", body)
                    if status != 200:
                        raise DeliveryError("INFERENCE_NOT_ACKNOWLEDGED", retryable=True)
                    event = anomaly_event(vector, result, identifier=job["id"],
                                          metadata_hash=job["metadata_hash"], observer="soc-ai-inference")
                    outbox.save_event(job["id"], event)
                timestamp = datetime.fromisoformat(event["@timestamp"].replace("Z", "+00:00"))
                index = "soc-ai-" + timestamp.astimezone(timezone.utc).strftime("%Y.%m.%d")
                try:
                    status, reply = elastic.request("PUT", f"/{index}/_create/{job['id']}", event)
                except DeliveryError as exc:
                    if exc.status != 409:
                        raise
                    # With a dedicated create_doc identity, the content-derived
                    # ID denotes a prior successful delivery of this same job.
                else:
                    if status != 201 or reply.get("result") != "created":
                        raise DeliveryError("ES_CREATE_NOT_ACKNOWLEDGED", retryable=True)
                outbox.sent(job["id"])
            except FeatureSchemaError:
                outbox.failed(job["id"], code="FEATURE_CONTRACT_MISMATCH", retryable=False)
            except DeliveryError as exc:
                outbox.failed(job["id"], code=exc.code, retryable=exc.retryable)
    return outbox.status()


FEATURE_CURSOR = "features_cursor"


def pull_features(outbox: Outbox, elastic: ElasticClient, *, feature_schema: str,
                  metadata_hash: str, limit: int, page_size: int = 500) -> dict:
    """Move closed vectors from ``soc-features-*`` into the durable outbox.

    The cursor stores the last ``search_after`` tuple, so a restart resumes where
    it stopped.  Delivery stays at-least-once; the outbox ID is content-derived,
    so re-pulled vectors collapse into one job.
    """

    if type(limit) is not int or not 1 <= limit <= 100000:
        raise ValueError("limit must be between 1 and 100000")
    raw_cursor = outbox.get_meta(FEATURE_CURSOR + ":" + feature_schema)
    cursor = json.loads(raw_cursor) if raw_cursor else None
    added = duplicates = invalid = seen = 0
    query = {"bool": {"filter": [{"term": {"feature_schema": feature_schema}}]}}
    last = cursor
    for hit in elastic.scan(
        "soc-features-*", query, [{"window_end": "asc"}, {"vector_id": "asc"}],
        page_size=min(page_size, limit), after=cursor,
    ):
        if seen >= limit:
            break
        seen += 1
        last = hit.get("sort") or last
        vector = hit.get("_source")
        try:
            validate_vector(vector)
        except FeatureSchemaError:
            invalid += 1  # visible in the result; never delivered to the model
            continue
        if outbox.enqueue(vector, metadata_hash):
            added += 1
        else:
            duplicates += 1
    if last is not None:
        outbox.set_meta(FEATURE_CURSOR + ":" + feature_schema, json.dumps(last))
    return {"pulled": seen, "added": added, "duplicates": duplicates, "invalid": invalid}


def serving_schema(inference: JsonHTTPS) -> str:
    """Ask the inference service which feature schema its approved model serves."""

    status, reply = inference.request("GET", "/model")
    schema = reply.get("feature_schema") if status == 200 else None
    if not isinstance(schema, str):
        raise DeliveryError("INFERENCE_MODEL_NOT_READY", retryable=True)
    return schema


def _inference_from_environment() -> JsonHTTPS:
    return JsonHTTPS(
        os.environ["SOC_AI_URL"], ca=os.environ["SOC_AI_CA"],
        cert=os.environ["SOC_AI_CLIENT_CERT"], key=os.environ["SOC_AI_CLIENT_KEY"],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outbox", type=Path, default=Path("soc/runtime/enrichment/outbox.sqlite"))
    commands = parser.add_subparsers(dest="command", required=True)
    load = commands.add_parser("import")
    load.add_argument("vectors", type=Path)
    load.add_argument("--metadata-sha256", default=os.environ.get("SOC_AI_METADATA_SHA256", ""),
                      help="approved metadata digest (default: $SOC_AI_METADATA_SHA256)")
    send = commands.add_parser("drain")
    send.add_argument("--limit", type=int, default=100)
    pull = commands.add_parser("pull", help="copy closed vectors from soc-features-* into the outbox")
    pull.add_argument("--metadata-sha256", default=os.environ.get("SOC_AI_METADATA_SHA256", ""),
                      help="approved metadata digest (default: $SOC_AI_METADATA_SHA256)")
    pull.add_argument("--limit", type=int, default=5000)
    pull.add_argument("--feature-schema", choices=("network-window-v1", "endpoint-window-v1"),
                      help="default: the schema served by the approved model")
    serve = commands.add_parser("serve", help="pull + drain forever (container entrypoint)")
    serve.add_argument("--metadata-sha256", default=os.environ.get("SOC_AI_METADATA_SHA256", ""),
                      help="approved metadata digest (default: $SOC_AI_METADATA_SHA256)")
    serve.add_argument("--interval", type=int, default=30)
    serve.add_argument("--limit", type=int, default=500)
    commands.add_parser("status")
    retry = commands.add_parser("requeue")
    retry.add_argument("job_id")
    args = parser.parse_args()
    if args.command in {"import", "pull", "serve"} and not re.fullmatch(r"[a-f0-9]{64}", args.metadata_sha256):
        raise SystemExit("an approved metadata SHA-256 is required (--metadata-sha256 or SOC_AI_METADATA_SHA256)")
    # Prevent new state/lock/WAL files from becoming readable by other users.
    os.umask(0o077)
    outbox = Outbox(args.outbox)
    try:
        if args.command == "import":
            added, duplicates = 0, 0
            with outbox.exclusive(), args.vectors.open() as handle:
                for number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    try:
                        vector = json.loads(line)
                        validate_vector(vector)
                    except (ValueError, FeatureSchemaError) as exc:
                        # Source export is retained. Fail visibly at the exact
                        # line; rerunning imports deduplicates the saved prefix.
                        raise ValueError(f"invalid vector at line {number}; source file retained") from exc
                    inserted = outbox.enqueue(vector, args.metadata_sha256)
                    added += int(inserted)
                    duplicates += int(not inserted)
            print(json.dumps({"added": added, "duplicates": duplicates, **outbox.status()}))
        elif args.command == "drain":
            if not 1 <= args.limit <= 10000:
                raise ValueError("limit must be between 1 and 10000")
            inference = _inference_from_environment()
            elastic_raw = elastic_transport_from_environment()
            length = serving_sequence_length(inference)
            fetcher = make_history_fetcher(ElasticClient(elastic_raw), length) if length > 1 else None
            counts = drain(outbox, inference, elastic_raw, limit=args.limit, history_fetcher=fetcher)
            print(json.dumps(counts))
            if counts["deadletter"] or counts["pending"] or counts["scored"]:
                return 2
        elif args.command == "pull":
            inference = _inference_from_environment()
            schema = args.feature_schema or serving_schema(inference)
            with outbox.exclusive():
                result = pull_features(outbox, elastic_from_environment(), feature_schema=schema,
                                       metadata_hash=args.metadata_sha256, limit=args.limit)
            print(json.dumps({**result, "feature_schema": schema, **outbox.status()}))
        elif args.command == "serve":
            if not 5 <= args.interval <= 3600 or not 1 <= args.limit <= 10000:
                raise ValueError("interval must be 5..3600 seconds and limit 1..10000")
            inference = _inference_from_environment()
            elastic_raw = elastic_transport_from_environment()
            elastic = ElasticClient(elastic_raw)
            while True:
                try:
                    schema = serving_schema(inference)  # no model -> wait; static SOC detection continues
                    with outbox.exclusive():
                        pulled = pull_features(outbox, elastic, feature_schema=schema,
                                               metadata_hash=args.metadata_sha256, limit=args.limit)
                        length = serving_sequence_length(inference)
                        fetcher = make_history_fetcher(elastic, length) if length > 1 else None
                        counts = drain(outbox, inference, elastic_raw, limit=args.limit,
                                       history_fetcher=fetcher)
                    print(json.dumps({"pull": pulled, "outbox": counts}), flush=True)
                except DeliveryError as exc:
                    print(json.dumps({"waiting": exc.code}), flush=True)
                time.sleep(args.interval)
        elif args.command == "requeue":
            with outbox.exclusive():
                outbox.requeue(args.job_id)
            print(json.dumps(outbox.status()))
        else:
            print(json.dumps(outbox.status()))
        return 0
    finally:
        outbox.close()


if __name__ == "__main__":
    raise SystemExit(main())
