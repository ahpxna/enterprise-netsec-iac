"""Closed-loop SOC response contracts and fail-closed orchestration primitives.

This package deliberately contains no network-device credentials and no code
path from an AI model to a privileged adapter.  AI output must first pass the
policy-backed :mod:`response.decision` boundary before the response
orchestrator can accept a signed command.
"""

from .decision import DecisionEngine, DecisionResult, HmacCommandAuthenticator
from .policy import PolicyCatalog, PolicyError

__all__ = [
    "DecisionEngine",
    "DecisionResult",
    "HmacCommandAuthenticator",
    "PolicyCatalog",
    "PolicyError",
]
