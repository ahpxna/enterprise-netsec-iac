"""Mutual-TLS intake for signed response commands (FastAPI).

The only write route is ``POST /v1/commands``.  Authorisation does not rest on the
transport: every command must also carry a valid Ed25519 signature, a policy
hash matching the active policy, and an unexpired authorization window.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from ..errors import CommandRejected
from .runner import ResponseService

MAX_COMMAND_BYTES = 16 * 1024


def create_app(service: ResponseService) -> FastAPI:
    app = FastAPI(title="CompanyXYZ SOC Response Orchestrator", version="1.0.0",
                  docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    def ready() -> JSONResponse:
        ok = service.started and not service.last_export.get("blocked")
        return JSONResponse(status_code=200 if ok else 503,
                            content={"ready": ok, "mode": service.mode, "export": service.last_export})

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics() -> PlainTextResponse:
        return PlainTextResponse(service.metrics(), media_type="text/plain; version=0.0.4")

    @app.post("/v1/commands")
    async def submit(request: Request) -> JSONResponse:
        body = await request.body()
        if not 0 < len(body) <= MAX_COMMAND_BYTES:
            raise HTTPException(status_code=413, detail="command body size is outside the permitted range")
        try:
            command = await request.json()
        except ValueError:
            raise HTTPException(status_code=400, detail="command must be JSON") from None
        if not isinstance(command, dict):
            raise HTTPException(status_code=400, detail="command must be an object")
        try:
            result = service.accept(command)
        except RuntimeError:
            raise HTTPException(status_code=503, detail="service not ready") from None
        return JSONResponse(status_code=202 if result.get("accepted") else 422, content=result)

    @app.get("/v1/responses/{response_id}")
    def status(response_id: str) -> JSONResponse:
        try:
            return JSONResponse(content=dict(service.status(response_id)))
        except CommandRejected:
            raise HTTPException(status_code=404, detail="unknown response") from None

    return app
