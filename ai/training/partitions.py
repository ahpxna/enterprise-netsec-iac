"""Fail-closed temporal and source/session separation for offline training."""

from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from ai.features.contracts import validate_vector, sha256_file
from ai.models.isolation_forest import ModelProvenanceError


def canonical_hash(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode()).hexdigest()


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed


def validate_partitions(manifest, vectors, paths, assignment_path: Path):
    """Check all three partitions against a hashed, per-vector membership ledger.

    The ledger is dataset evidence, not inferred from model features. Source IDs
    and session IDs must be stable across collectors/replays before extraction.
    """
    root = Path(__file__).resolve().parents[2]
    schema = json.loads((root / "schemas/events/dataset-manifest-v1.schema.json").read_text())
    try:
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(manifest)
        ledger_bytes = assignment_path.read_bytes()
        if sha256(ledger_bytes).hexdigest() != manifest["split"]["session_assignment_sha256"]:
            raise ValueError("session assignment digest mismatch")
        ledger = json.loads(ledger_bytes)
        if set(ledger) != {"schema_version", "partitions"} or ledger["schema_version"] != "partition-membership-v1":
            raise ValueError("unsupported membership ledger")
        if set(ledger["partitions"]) != {"train", "validation", "test"}:
            raise ValueError("all three partitions are required")
        outer_start = timestamp(manifest["time_range"]["start"])
        outer_end = timestamp(manifest["time_range"]["end"])
        previous_end = outer_start
        source_owners, session_owners = {}, {}
        for name in ("train", "validation", "test"):
            bounds = manifest["split"][name]
            start, end = timestamp(bounds["start"]), timestamp(bounds["end"])
            if not previous_end <= start < end <= outer_end:
                raise ValueError("partitions must be ordered, nonoverlapping and within dataset bounds")
            previous_end = end
            if name == "train" and bounds["label_profile"] != "benign_biased":
                raise ValueError("training must use the benign-biased partition")
            part = ledger["partitions"][name]
            if set(part) != {"vectors_sha256", "memberships"}:
                raise ValueError("invalid partition ledger fields")
            if sha256_file(paths[name]) != part["vectors_sha256"]:
                raise ValueError("vector file digest mismatch")
            rows = vectors[name]
            if len(rows) != bounds["vector_count"] or len(rows) != len(part["memberships"]):
                raise ValueError("vector count mismatch")
            seen, sessions = set(), set()
            for vector, member in zip(rows, part["memberships"]):
                validate_vector(vector)
                if vector["feature_schema"] != manifest["feature_schema"]:
                    raise ValueError("mixed feature schemas")
                if not start <= timestamp(vector["window_start"]) < timestamp(vector["window_end"]) <= end:
                    raise ValueError("vector crosses its temporal partition")
                key = (vector["entity"], timestamp(vector["window_start"]), timestamp(vector["window_end"]))
                if key in seen:
                    raise ValueError("duplicate entity/window vector")
                seen.add(key)
                if set(member) != {"vector_sha256", "source_event_ids", "session_ids"}:
                    raise ValueError("invalid membership fields")
                if member["vector_sha256"] != canonical_hash(vector):
                    raise ValueError("membership is not bound to vector")
                for field, owners in (("source_event_ids", source_owners), ("session_ids", session_owners)):
                    identifiers = member[field]
                    if not isinstance(identifiers, list) or not identifiers or any(
                        not isinstance(item, str) or not item for item in identifiers
                    ) or len(set(identifiers)) != len(identifiers):
                        raise ValueError("membership IDs must be nonempty unique strings")
                    for identifier in identifiers:
                        if owners.setdefault(identifier, name) != name:
                            raise ValueError("source/session leakage across partitions")
                sessions.update(member["session_ids"])
                source_digest = sha256("\n".join(sorted(member["source_event_ids"])).encode()).hexdigest()
                if source_digest != vector["source_event_set_sha256"]:
                    raise ValueError("source membership differs from vector provenance")
            if canonical_hash(sorted(sessions)) != bounds["session_ids_sha256"]:
                raise ValueError("partition session digest mismatch")
    except (ValueError, TypeError, KeyError, OSError) as exc:
        raise ModelProvenanceError(f"dataset partition validation refused: {exc}") from exc
    except Exception as exc:
        raise ModelProvenanceError("dataset partition schema validation refused") from exc
