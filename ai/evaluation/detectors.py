"""Comparable detectors: static rules, Isolation Forest, LSTM autoencoder, and hybrids.

Every detector exposes the same ``score(vector, history)`` contract returning a
number in [0, 1]; a detector "fires" when ``score >= threshold``.  The static
detector returns exactly 0 or 1, so it needs no tuning and acts as the baseline
that the learned detectors must beat.  Hybrids combine the static verdict with a
model score with ``max``: they fire when either component fires, which is the
logical OR the SOC runs in practice (static rules plus anomaly detection).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol, Sequence

from ai.features.contracts import FeatureSchemaError

History = Sequence[Mapping[str, object] | None]


class Detector(Protocol):
    name: str
    default_threshold: float | None  # ``None`` means "tune on the validation partition"

    def score(self, vector: Mapping[str, object], history: History) -> float: ...


@dataclass(frozen=True)
class StaticRuleSet:
    """Documented static-rule equivalents of the Wazuh/Suricata detections.

    A vector fires when any listed counter reaches its limit.  The defaults
    mirror the lab rules: any Suricata alert, a burst of authentication
    failures, mostly-blocked firewall traffic (the DET-01 scan signature), and
    for endpoints any PowerShell, privilege or account change.
    """

    network: Mapping[str, float]
    endpoint: Mapping[str, float]

    @staticmethod
    def default() -> "StaticRuleSet":
        return StaticRuleSet(
            network={"suricata_alert_count": 1, "failed_auth_count": 20},
            endpoint={"powershell_count": 1, "privilege_change_count": 1, "account_change_count": 1},
        )

    def fires(self, vector: Mapping[str, object]) -> bool:
        features = vector["features"]
        assert isinstance(features, Mapping)
        schema = vector["feature_schema"]
        limits = self.network if schema == "network-window-v1" else self.endpoint
        if any(float(features[name]) >= limit for name, limit in limits.items()):
            return True
        if schema == "network-window-v1":
            # DET-01: a window that is mostly firewall drops across many ports is a scan.
            return (
                float(features["connection_count"]) >= 10
                and float(features["blocked_ratio"]) >= 0.5
                and float(features["unique_dst_port"]) >= 3
            )
        return False


class StaticRuleDetector:
    name = "static-rules"
    default_threshold: float | None = 0.5

    def __init__(self, rules: StaticRuleSet | None = None) -> None:
        self._rules = rules or StaticRuleSet.default()

    def score(self, vector: Mapping[str, object], history: History = ()) -> float:
        return 1.0 if self._rules.fires(vector) else 0.0


class ModelDetector:
    """Wraps an unapproved candidate model (``SocIsolationForest``/``SocLstmAutoencoder``)."""

    default_threshold: float | None = None

    def __init__(self, name: str, model: object) -> None:
        self.name = name
        self._model = model
        self.sequence_length = int(getattr(model, "sequence_length", 1))

    def score(self, vector: Mapping[str, object], history: History = ()) -> float:
        features = vector["features"]
        if self.sequence_length > 1:
            from ai.features.sequences import sequence_matrix

            if len(history) != self.sequence_length - 1:
                raise FeatureSchemaError("history length does not match the sequence model")
            return self._model.score_matrix(  # type: ignore[attr-defined]
                sequence_matrix(str(vector["feature_schema"]), history, features)  # type: ignore[arg-type]
            )
        return self._model.score(features)  # type: ignore[attr-defined]


class HybridDetector:
    """Static rules OR model: a vector fires if either component would."""

    default_threshold: float | None = None

    def __init__(self, static: StaticRuleDetector, model: ModelDetector) -> None:
        self.name = f"static+{model.name}"
        self._static = static
        self._model = model
        self.sequence_length = model.sequence_length

    def score(self, vector: Mapping[str, object], history: History = ()) -> float:
        return max(self._static.score(vector, history), self._model.score(vector, history))
