"""Closed feature-schema definitions shared by generation, training, and inference."""

from __future__ import annotations

from hashlib import sha256
from datetime import datetime, timedelta
import json
import math
from pathlib import Path
from typing import Mapping, Sequence


NETWORK_FEATURES: tuple[str, ...] = (
    "connection_count",
    "unique_dst_ip",
    "unique_dst_port",
    "bytes_out",
    "bytes_in",
    "blocked_ratio",
    "dns_query_count",
    "unique_domain_count",
    "tls_count",
    "suricata_alert_count",
    "failed_auth_count",
)

ENDPOINT_FEATURES: tuple[str, ...] = (
    "process_count",
    "rare_process_count",
    "powershell_count",
    "failed_login_count",
    "fim_change_count",
    "account_change_count",
    "privilege_change_count",
)

FEATURES_BY_SCHEMA: Mapping[str, tuple[str, ...]] = {
    "network-window-v1": NETWORK_FEATURES,
    "endpoint-window-v1": ENDPOINT_FEATURES,
}

SCHEMA_FILENAMES: Mapping[str, str] = {
    "network-window-v1": "network-window-v1.schema.json",
    "endpoint-window-v1": "endpoint-window-v1.schema.json",
}

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class FeatureSchemaError(ValueError):
    """Raised when a caller attempts to use an unknown or mixed feature schema."""


def expected_feature_names(feature_schema: str) -> tuple[str, ...]:
    try:
        return FEATURES_BY_SCHEMA[feature_schema]
    except KeyError as exc:
        raise FeatureSchemaError(f"unsupported feature schema: {feature_schema}") from exc


def feature_schema_path(feature_schema: str, repository_root: Path | None = None) -> Path:
    root = repository_root or REPOSITORY_ROOT
    try:
        filename = SCHEMA_FILENAMES[feature_schema]
    except KeyError as exc:
        raise FeatureSchemaError(f"unsupported feature schema: {feature_schema}") from exc
    return root / "schemas" / "features" / filename


def sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def feature_schema_sha256(feature_schema: str, repository_root: Path | None = None) -> str:
    path = feature_schema_path(feature_schema, repository_root)
    if not path.is_file():
        raise FeatureSchemaError(f"feature schema is missing: {path}")
    return sha256_file(path)


def require_exact_features(feature_schema: str, features: Mapping[str, object]) -> None:
    if not isinstance(features, Mapping):
        raise FeatureSchemaError("features must be an object")
    expected = set(expected_feature_names(feature_schema))
    received = set(features)
    missing = sorted(expected - received)
    unexpected = sorted(received - expected)
    if missing or unexpected:
        details: list[str] = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if unexpected:
            details.append(f"unexpected={','.join(unexpected)}")
        raise FeatureSchemaError(
            f"feature keys do not match {feature_schema}: {'; '.join(details)}"
        )
    for name in expected_feature_names(feature_schema):
        value = features[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise FeatureSchemaError(f"feature {name} must be numeric")
        try:
            finite = math.isfinite(value)
        except OverflowError:
            finite = False
        if not finite:
            raise FeatureSchemaError(f"feature {name} must be finite")
        if value < 0:
            raise FeatureSchemaError(f"feature {name} must be non-negative")
        if name == "blocked_ratio":
            if value > 1:
                raise FeatureSchemaError("blocked_ratio must be in [0, 1]")
        elif value != int(value):
            raise FeatureSchemaError(f"feature {name} must be an integer count")


def ordered_feature_row(feature_schema: str, features: Mapping[str, object]) -> list[float]:
    require_exact_features(feature_schema, features)
    return [float(features[name]) for name in expected_feature_names(feature_schema)]


def validate_vector(vector: Mapping[str, object]) -> None:
    """Validate the complete local contract, including formats and window bounds."""
    from jsonschema import Draft202012Validator, FormatChecker

    if not isinstance(vector, Mapping):
        raise FeatureSchemaError("vector must be an object")
    schema_id = vector.get("feature_schema")
    if not isinstance(schema_id, str):
        raise FeatureSchemaError("vector lacks feature_schema")
    try:
        document = json.loads(feature_schema_path(schema_id).read_text())
        Draft202012Validator(document, format_checker=FormatChecker()).validate(dict(vector))
        require_exact_features(schema_id, vector["features"])
        start = datetime.fromisoformat(str(vector["window_start"]).replace("Z", "+00:00"))
        end = datetime.fromisoformat(str(vector["window_end"]).replace("Z", "+00:00"))
        if end - start != timedelta(minutes=5):
            raise FeatureSchemaError("feature window must span exactly five minutes")
        if vector["feature_schema_sha256"] != feature_schema_sha256(schema_id):
            raise FeatureSchemaError("feature schema hash differs from the local contract")
    except FeatureSchemaError:
        raise
    except Exception as exc:
        raise FeatureSchemaError("vector violates the versioned feature contract") from exc


def validate_feature_name_order(feature_schema: str, names: Sequence[str]) -> None:
    expected = expected_feature_names(feature_schema)
    if tuple(names) != expected:
        raise FeatureSchemaError(
            f"model feature order does not match {feature_schema}; retraining is required"
        )
