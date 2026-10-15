"""Fail-closed exception types for the response control plane."""

from __future__ import annotations


class ResponseError(ValueError):
    """Base class for rejected SOC response-plane input."""


class PolicyError(ResponseError):
    """The declarative policy cannot safely be loaded or applied."""


class CorrelationRejected(ResponseError):
    """The evidence does not satisfy a policy for an automatic action."""


class CommandRejected(ResponseError):
    """The orchestrator refuses an invalid, expired, or unsafe command."""


class AdapterError(ResponseError):
    """A constrained adapter failed to apply, verify, or revert an action."""
