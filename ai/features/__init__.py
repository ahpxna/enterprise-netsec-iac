"""Deterministic, versioned SOC feature-vector generation."""

from .contracts import ENDPOINT_FEATURES, NETWORK_FEATURES, feature_schema_sha256
from .engine import FeatureContractError, build_endpoint_vectors, build_network_vectors

__all__ = [
    "ENDPOINT_FEATURES",
    "NETWORK_FEATURES",
    "FeatureContractError",
    "build_endpoint_vectors",
    "build_network_vectors",
    "feature_schema_sha256",
]

