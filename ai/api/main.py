"""FastAPI boundary for scored SOC evidence.

This service accepts a closed feature vector and returns a model score. It has
no Elasticsearch, OPNsense, Wazuh, Decision Engine, or Response Orchestrator
credential. A separate bounded writer may turn a response plus feature-vector
references into an `anomaly-event-v1` document later in the pipeline.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from threading import Lock
from time import perf_counter
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt

from ai.features.contracts import FeatureSchemaError, require_exact_features
from ai.models.isolation_forest import ApprovedModel, ModelProvenanceError, load_approved_model


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FeatureNumber = StrictInt | StrictFloat


class InferenceRequest(BaseModel):
    """No schema mapping or feature inference is permitted at the API boundary."""

    model_config = ConfigDict(extra="forbid", strict=True)

    feature_schema: Literal["network-window-v1", "endpoint-window-v1"]
    entity: str = Field(min_length=1, max_length=255)
    features: dict[str, FeatureNumber] = Field(min_length=1)
    # Sequence models only: the T-1 preceding windows of the same entity, oldest
    # first; null means "no telemetry in that window" (an all-zero row).
    history: list[dict[str, FeatureNumber] | None] = Field(default_factory=list, max_length=287)


class InferenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model_id: str
    algorithm: str
    feature_schema: str
    feature_schema_sha256: str
    model_sha256: str
    model_metadata_sha256: str
    score: float = Field(ge=0.0, le=1.0)
    threshold: float = Field(ge=0.0, le=1.0)
    is_anomaly: bool
    inference_ms: float = Field(ge=0.0)


class ModelStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model_id: str
    algorithm: str
    feature_schema: str
    feature_schema_sha256: str
    model_sha256: str
    model_metadata_sha256: str
    threshold: float = Field(ge=0.0, le=1.0)
    status: str
    sequence_length: int = Field(ge=1, default=1)


class RuntimeMetrics:
    """Process-local operational counters; no feature values are retained."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._requests = 0
        self._errors = 0
        self._last_inference_ms = 0.0

    def record_success(self, inference_ms: float) -> None:
        with self._lock:
            self._requests += 1
            self._last_inference_ms = inference_ms

    def record_error(self) -> None:
        with self._lock:
            self._errors += 1

    def prometheus(self) -> str:
        with self._lock:
            return "\n".join(
                (
                    "# TYPE cxyz_soc_ai_inference_requests_total counter",
                    f"cxyz_soc_ai_inference_requests_total {self._requests}",
                    "# TYPE cxyz_soc_ai_inference_errors_total counter",
                    f"cxyz_soc_ai_inference_errors_total {self._errors}",
                    "# TYPE cxyz_soc_ai_last_inference_milliseconds gauge",
                    f"cxyz_soc_ai_last_inference_milliseconds {self._last_inference_ms:.6f}",
                    "",
                )
            )


class ModelProvider:
    """Load only a verified local approved artifact; retry safely after a fix."""

    def __init__(self, registry_dir: Path, trusted_metadata_sha256: str | None) -> None:
        self._registry_dir = registry_dir
        self._trusted_metadata_sha256 = trusted_metadata_sha256
        self._lock = Lock()
        self._model: ApprovedModel | None = None
        self._last_error: str | None = None

    def get(self) -> ApprovedModel:
        with self._lock:
            if self._model is not None:
                return self._model
            try:
                model = load_approved_model(
                    self._registry_dir, repository_root=REPOSITORY_ROOT,
                    trusted_metadata_sha256=self._trusted_metadata_sha256,
                )
            except ModelProvenanceError as exc:
                self._last_error = str(exc)
                raise
            self._model = model
            self._last_error = None
            return model

    def readiness_error(self) -> str | None:
        return self._last_error


def _validate_entity(feature_schema: str, entity: str) -> None:
    if feature_schema == "network-window-v1":
        try:
            ipaddress.ip_address(entity)
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail="network-window-v1 requires entity to be a valid IP address",
            ) from exc


def _unavailable(provider: ModelProvider, metrics: RuntimeMetrics) -> HTTPException:
    metrics.record_error()
    return HTTPException(
        status_code=503,
        detail={
            "code": "MODEL_NOT_READY",
            "message": "No verified approved model is available; static SOC detections continue independently.",
            "reason": provider.readiness_error() or "model registry unavailable",
        },
    )


def create_app(
    *, model_dir: str | Path | None = None, trusted_metadata_sha256: str | None = None,
) -> FastAPI:
    """Create the API without loading a model or opening any network connection."""

    registry_dir = Path(model_dir or os.environ.get("SOC_AI_MODEL_DIR", "/models/active"))
    provider = ModelProvider(
        registry_dir, trusted_metadata_sha256 or os.environ.get("SOC_AI_METADATA_SHA256")
    )
    metrics = RuntimeMetrics()
    app = FastAPI(
        title="CompanyXYZ SOC AI Inference",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json",
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    def ready() -> JSONResponse:
        try:
            model = provider.get()
        except ModelProvenanceError:
            return JSONResponse(
                status_code=503,
                content={
                    "ready": False,
                    "reason": provider.readiness_error() or "model registry unavailable",
                },
            )
        return JSONResponse(
            content={
                "ready": True,
                "model_id": model.model_id,
                "feature_schema": model.model.feature_schema,
            }
        )

    @app.get("/model", response_model=ModelStatus)
    def model_status() -> ModelStatus:
        try:
            model = provider.get()
        except ModelProvenanceError as exc:
            raise _unavailable(provider, metrics) from exc
        return ModelStatus(
            model_id=model.model_id,
            algorithm=model.algorithm,
            feature_schema=model.model.feature_schema,
            feature_schema_sha256=model.model.feature_schema_sha256,
            model_sha256=model.model_sha256,
            model_metadata_sha256=model.metadata_sha256,
            threshold=model.threshold,
            status=str(model.metadata["status"]),
            sequence_length=model.sequence_length,
        )

    @app.get("/metrics", response_class=PlainTextResponse)
    def model_metrics() -> PlainTextResponse:
        return PlainTextResponse(metrics.prometheus(), media_type="text/plain; version=0.0.4")

    @app.post("/v1/infer", response_model=InferenceResponse)
    def infer(request: InferenceRequest) -> InferenceResponse:
        _validate_entity(request.feature_schema, request.entity)
        try:
            require_exact_features(request.feature_schema, request.features)
        except FeatureSchemaError as exc:
            metrics.record_error()
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        try:
            model = provider.get()
        except ModelProvenanceError as exc:
            raise _unavailable(provider, metrics) from exc
        if request.feature_schema != model.model.feature_schema:
            metrics.record_error()
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "FEATURE_SCHEMA_MISMATCH",
                    "message": "request schema does not match the approved model; no automatic mapping exists",
                    "expected": model.model.feature_schema,
                    "received": request.feature_schema,
                },
            )
        expected_history = model.sequence_length - 1
        if len(request.history) != expected_history:
            metrics.record_error()
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "HISTORY_LENGTH_MISMATCH",
                    "message": f"the approved model needs exactly {expected_history} history windows",
                    "expected": expected_history,
                    "received": len(request.history),
                },
            )
        try:
            for item in request.history:
                if item is not None:
                    require_exact_features(request.feature_schema, item)
        except FeatureSchemaError as exc:
            metrics.record_error()
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        started = perf_counter()
        try:
            score, is_anomaly = model.infer(request.features, request.history)
        except ModelProvenanceError as exc:
            raise _unavailable(provider, metrics) from exc
        except (FeatureSchemaError, ValueError) as exc:
            metrics.record_error()
            raise HTTPException(
                status_code=422,
                detail={"code": "FEATURE_CONTRACT_MISMATCH", "message": str(exc)},
            ) from exc
        inference_ms = (perf_counter() - started) * 1000.0
        metrics.record_success(inference_ms)
        return InferenceResponse(
            model_id=model.model_id,
            algorithm=model.algorithm,
            feature_schema=model.model.feature_schema,
            feature_schema_sha256=model.model.feature_schema_sha256,
            model_sha256=model.model_sha256,
            model_metadata_sha256=model.metadata_sha256,
            score=score,
            threshold=model.threshold,
            is_anomaly=is_anomaly,
            inference_ms=inference_ms,
        )

    return app


app = create_app()
