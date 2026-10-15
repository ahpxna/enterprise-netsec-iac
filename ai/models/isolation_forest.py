"""Isolation Forest model wrapper with artifact and provenance verification.

Artifacts are loaded only from a local registry directory after their digest,
feature contract, and approved provenance record are verified.  This module
does not create telemetry documents and has no network or response credentials.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
import json
import math
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from ai.features.contracts import (
    FeatureSchemaError,
    expected_feature_names,
    feature_schema_sha256,
    ordered_feature_row,
    sha256_file,
    validate_feature_name_order,
)


class ModelProvenanceError(RuntimeError):
    """Raised when a model cannot prove its integrity and reproducibility."""


@dataclass
class SocIsolationForest:
    """Serializable IF pipeline plus deterministic anomaly-score calibration."""

    feature_schema: str
    feature_schema_sha256: str
    feature_names: tuple[str, ...]
    pipeline: Any
    calibration_low: float
    calibration_high: float

    @classmethod
    def fit(
        cls,
        feature_schema: str,
        vectors: Sequence[Mapping[str, Any]],
        *,
        random_seed: int,
        n_estimators: int,
        contamination: float | str = "auto",
    ) -> "SocIsolationForest":
        """Fit on an explicitly benign-biased temporal training partition.

        Scaling is retained even though Isolation Forest is tree based: the
        persisted contract must be reusable by the comparative model pipeline.
        Threshold selection is intentionally not done here; it belongs to the
        held-out validation protocol and is recorded in model provenance.
        """

        if len(vectors) < 2:
            raise ModelProvenanceError("Isolation Forest requires at least two training vectors")
        try:
            from numpy import asarray, quantile
            from sklearn.ensemble import IsolationForest
            from sklearn.pipeline import Pipeline
            from sklearn.preprocessing import StandardScaler
        except ImportError as exc:  # pragma: no cover - deployment dependency error
            raise ModelProvenanceError(
                "AI dependencies are unavailable; install requirements-soc-ai.txt"
            ) from exc

        rows: list[list[float]] = []
        for vector in vectors:
            if vector.get("feature_schema") != feature_schema:
                raise ModelProvenanceError("training vectors must use exactly one feature schema")
            rows.append(ordered_feature_row(feature_schema, vector.get("features", {})))

        pipeline = Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "isolation_forest",
                    IsolationForest(
                        n_estimators=n_estimators,
                        contamination=contamination,
                        random_state=random_seed,
                        n_jobs=1,
                    ),
                ),
            ]
        )
        matrix = asarray(rows, dtype=float)
        pipeline.fit(matrix)
        raw_anomaly_scores = -pipeline.decision_function(matrix)
        calibration_low, calibration_high = (float(value) for value in quantile(raw_anomaly_scores, [0.01, 0.99]))
        if calibration_high <= calibration_low:
            # A degenerate benign sample must not turn every request into an
            # anomaly. Keep a finite, deterministic calibration interval.
            calibration_high = calibration_low + 1e-12

        try:
            schema_hash = feature_schema_sha256(feature_schema)
            names = expected_feature_names(feature_schema)
        except FeatureSchemaError as exc:
            raise ModelProvenanceError(str(exc)) from exc
        return cls(
            feature_schema=feature_schema,
            feature_schema_sha256=schema_hash,
            feature_names=names,
            pipeline=pipeline,
            calibration_low=calibration_low,
            calibration_high=calibration_high,
        )

    sequence_length = 1  # point-in-time model: no window history is consumed

    def score(self, features: Mapping[str, object], history: Sequence[object] = ()) -> float:
        """Return a calibrated 0..1 anomaly score; higher means less normal."""

        if history:
            raise FeatureSchemaError("the Isolation Forest scores one window; history is not accepted")
        row = ordered_feature_row(self.feature_schema, features)
        raw_score = -float(self.pipeline.decision_function([row])[0])
        if not math.isfinite(raw_score):
            raise ModelProvenanceError("model returned a non-finite score")
        score = (raw_score - self.calibration_low) / (self.calibration_high - self.calibration_low)
        return max(0.0, min(1.0, score))


@dataclass(frozen=True)
class ApprovedModel:
    """A verified artifact plus the metadata required to explain a score."""

    model: SocIsolationForest
    metadata: Mapping[str, Any]
    metadata_sha256: str
    model_sha256: str

    @property
    def model_id(self) -> str:
        return str(self.metadata["model_id"])

    @property
    def threshold(self) -> float:
        return float(self.metadata["threshold"])

    @property
    def algorithm(self) -> str:
        return str(self.metadata["algorithm"])

    @property
    def sequence_length(self) -> int:
        """Windows consumed per inference (1 for point models, T for sequence models)."""

        return int(getattr(self.model, "sequence_length", 1))

    def infer(
        self, features: Mapping[str, object], history: Sequence[object] = ()
    ) -> tuple[float, bool]:
        """Score one window; sequence models also take the ``T - 1`` preceding windows."""

        if self.sequence_length > 1:
            from ai.features.sequences import sequence_matrix

            if len(history) != self.sequence_length - 1:
                raise FeatureSchemaError(
                    f"{self.algorithm} requires exactly {self.sequence_length - 1} history windows"
                )
            score = self.model.score_matrix(
                sequence_matrix(self.model.feature_schema, history, features)  # type: ignore[arg-type]
            )
        else:
            score = self.model.score(features, history)
        return score, score >= self.threshold


def _load_json(path: Path) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelProvenanceError(f"cannot load JSON metadata {path}") from exc
    if not isinstance(payload, Mapping):
        raise ModelProvenanceError(f"metadata {path} must contain an object")
    return payload


def _validate_provenance(metadata: Mapping[str, Any], repository_root: Path) -> None:
    schema_path = repository_root / "schemas" / "events" / "model-provenance-v1.schema.json"
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as exc:  # pragma: no cover - deployment dependency error
        raise ModelProvenanceError(
            "jsonschema is required to validate model provenance"
        ) from exc
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(dict(metadata))
        json.dumps(metadata, allow_nan=False)
    except Exception as exc:  # validation must fail closed before unpickling
        raise ModelProvenanceError("model provenance does not satisfy model-provenance-v1") from exc


ARTIFACT_BY_ALGORITHM = {
    "IsolationForest": ("joblib", "model.joblib"),
    "LSTMAutoencoder": ("safetensors", "model.safetensors"),
}


def _safe_artifact_path(registry_dir: Path, relative_path: object, expected_name: str) -> Path:
    if not isinstance(relative_path, str) or not relative_path:
        raise ModelProvenanceError("model provenance is missing artifact.path")
    candidate = Path(relative_path)
    if candidate.is_absolute() or candidate.name != expected_name:
        raise ModelProvenanceError(f"model artifact must be the registry-local {expected_name} file")
    resolved_root = registry_dir.resolve()
    resolved = (resolved_root / candidate).resolve()
    if resolved.parent != resolved_root:
        raise ModelProvenanceError("model artifact path escapes its registry directory")
    return resolved


def load_approved_model(
    registry_dir: str | Path,
    *,
    repository_root: str | Path | None = None,
    trusted_metadata_sha256: str | None = None,
) -> ApprovedModel:
    """Verify and load the single promoted local artifact.

    The registry must be mounted read-only by a later service deployment.  The
    loader deliberately refuses candidate/retired models and checks hashes
    before deserializing joblib data.
    """

    if not isinstance(trusted_metadata_sha256, str) or not re.fullmatch(
        r"[a-f0-9]{64}", trusted_metadata_sha256
    ):
        raise ModelProvenanceError("an independently approved metadata SHA-256 is required")
    root = Path(registry_dir).resolve()
    repo = Path(repository_root).resolve() if repository_root else Path(__file__).resolve().parents[2]
    metadata_path = root / "metadata.json"
    try:
        metadata_bytes = metadata_path.read_bytes()
        metadata_hash = sha256(metadata_bytes).hexdigest()
        if metadata_hash != trusted_metadata_sha256:
            raise ModelProvenanceError("metadata digest does not match the deployment approval")
        metadata = json.loads(metadata_bytes)
    except (OSError, ValueError) as exc:
        raise ModelProvenanceError("cannot read approved model metadata") from exc
    _validate_provenance(metadata, repo)
    if metadata.get("status") != "approved":
        raise ModelProvenanceError("only an approved model may serve inference")
    algorithm = metadata.get("algorithm")
    if algorithm not in ARTIFACT_BY_ALGORITHM:
        raise ModelProvenanceError("this loader does not serve that model algorithm")
    expected_format, expected_name = ARTIFACT_BY_ALGORITHM[algorithm]

    artifact = metadata["artifact"]
    if not isinstance(artifact, Mapping) or artifact.get("format") != expected_format:
        raise ModelProvenanceError(f"model artifact must be a {expected_format} artifact")
    model_path = _safe_artifact_path(root, artifact.get("path"), expected_name)
    if not model_path.is_file():
        raise ModelProvenanceError("approved model artifact is missing")
    # Deserialize the same bytes that were verified, eliminating a path reopen
    # race. Bound allocation; large models require an explicit new contract.
    try:
        with model_path.open("rb") as handle:
            model_bytes = handle.read(128 * 1024 * 1024 + 1)
    except OSError as exc:
        raise ModelProvenanceError("cannot read approved artifact") from exc
    if len(model_bytes) > 128 * 1024 * 1024:
        raise ModelProvenanceError("model artifact exceeds 128 MiB limit")
    model_hash = sha256(model_bytes).hexdigest()
    if model_hash != artifact.get("sha256"):
        raise ModelProvenanceError("model artifact digest does not match provenance")
    if len(model_bytes) != artifact.get("size_bytes"):
        raise ModelProvenanceError("model artifact size does not match provenance")

    feature_metadata = metadata["feature_schema"]
    if not isinstance(feature_metadata, Mapping):
        raise ModelProvenanceError("model provenance is missing feature schema metadata")
    feature_schema = feature_metadata.get("id")
    if not isinstance(feature_schema, str):
        raise ModelProvenanceError("model provenance feature schema ID is invalid")
    try:
        actual_schema_hash = feature_schema_sha256(feature_schema, repo)
    except (FeatureSchemaError, OSError) as exc:
        raise ModelProvenanceError("repository feature contract is unavailable") from exc
    if actual_schema_hash != feature_metadata.get("sha256"):
        raise ModelProvenanceError("repository feature schema digest does not match provenance")
    registry_schema_path = root / "feature_schema.json"
    if not registry_schema_path.is_file() or sha256_file(registry_schema_path) != actual_schema_hash:
        raise ModelProvenanceError("registry feature schema copy does not match provenance")

    if algorithm == "IsolationForest":
        try:
            import joblib
        except ImportError as exc:  # pragma: no cover - deployment dependency error
            raise ModelProvenanceError(
                "joblib is unavailable; install requirements-soc-ai.txt"
            ) from exc
        try:
            loaded = joblib.load(BytesIO(model_bytes))
        except Exception as exc:  # only reached after hash verification
            raise ModelProvenanceError("verified model artifact could not be loaded") from exc
        if not isinstance(loaded, SocIsolationForest):
            raise ModelProvenanceError("joblib artifact is not a CompanyXYZ Isolation Forest")
    else:
        from .lstm_autoencoder import LstmModelError, SocLstmAutoencoder

        try:
            loaded = SocLstmAutoencoder.from_safetensors(model_bytes)
        except LstmModelError as exc:
            raise ModelProvenanceError(str(exc)) from exc
        declared = metadata["training"]["hyperparameters"]
        if declared.get("sequence_length") != loaded.sequence_length:
            raise ModelProvenanceError("LSTM sequence length does not match provenance")
    if not all(math.isfinite(v) for v in (loaded.calibration_low, loaded.calibration_high)):
        raise ModelProvenanceError("model calibration is not finite")
    if loaded.calibration_high <= loaded.calibration_low:
        raise ModelProvenanceError("model calibration interval is invalid")
    if loaded.feature_schema != feature_schema or loaded.feature_schema_sha256 != actual_schema_hash:
        raise ModelProvenanceError("model-internal feature contract does not match provenance")
    try:
        validate_feature_name_order(feature_schema, loaded.feature_names)
    except FeatureSchemaError as exc:
        raise ModelProvenanceError(str(exc)) from exc

    return ApprovedModel(
        model=loaded,
        metadata=metadata,
        metadata_sha256=metadata_hash,
        model_sha256=model_hash,
    )
