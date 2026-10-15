"""Approved SOC model artifacts and safe inference wrappers."""

from .isolation_forest import (
    ApprovedModel,
    ModelProvenanceError,
    SocIsolationForest,
    load_approved_model,
)


def __getattr__(name: str):  # lazy: PyTorch is an optional dependency
    if name in {"SocLstmAutoencoder", "LstmModelError"}:
        from . import lstm_autoencoder

        return getattr(lstm_autoencoder, name)
    raise AttributeError(name)


__all__ = [
    "ApprovedModel",
    "ModelProvenanceError",
    "SocIsolationForest",
    "load_approved_model",
]

