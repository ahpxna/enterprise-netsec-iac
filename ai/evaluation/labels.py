"""Scenario labels bound to vectors by digest (``labels-v1``).

Labels come from controlled attack scenarios (time window + entity), never from
a model.  Every row is bound to its vector by the same canonical hash used by the
partition membership ledger, and the file's own SHA-256 is recorded in the
dataset manifest (``label_source.sha256``), so neither side can be swapped
after the fact.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from ai.training.partitions import canonical_hash

LABELS_SCHEMA = "labels-v1"


class LabelError(ValueError):
    """Raised when labels are missing, malformed, or not bound to the evaluated vectors."""


@dataclass(frozen=True)
class Label:
    vector_sha256: str
    attack: bool
    scenario_id: str | None
    scenario_start: datetime | None


def _parse(value: object) -> datetime:
    if not isinstance(value, str):
        raise LabelError("scenario_start must be an RFC3339 string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise LabelError("scenario_start must include a UTC offset")
    return parsed


def load_labels(path: Path, *, expected_sha256: str | None = None) -> dict[str, Label]:
    data = Path(path).read_bytes()
    if expected_sha256 is not None and sha256(data).hexdigest() != expected_sha256:
        raise LabelError("label file digest does not match the dataset manifest")
    labels: dict[str, Label] = {}
    for number, line in enumerate(data.decode("utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise LabelError(f"label line {number} is not JSON") from exc
        if not isinstance(row, dict) or set(row) != {
            "schema_version", "vector_sha256", "label", "scenario_id", "scenario_start",
        }:
            raise LabelError(f"label line {number} has missing or unsupported fields")
        if row["schema_version"] != LABELS_SCHEMA:
            raise LabelError(f"label line {number} has an unsupported schema")
        digest = row["vector_sha256"]
        if not isinstance(digest, str) or len(digest) != 64:
            raise LabelError(f"label line {number} has an invalid vector digest")
        if row["label"] not in (0, 1) or isinstance(row["label"], bool):
            raise LabelError(f"label line {number} must be 0 or 1")
        attack = row["label"] == 1
        if attack:
            if not isinstance(row["scenario_id"], str) or not row["scenario_id"]:
                raise LabelError(f"attack label on line {number} needs a scenario_id")
            start = _parse(row["scenario_start"])
        else:
            if row["scenario_id"] is not None or row["scenario_start"] is not None:
                raise LabelError(f"benign label on line {number} must not name a scenario")
            start = None
        if digest in labels:
            raise LabelError(f"duplicate label for vector {digest}")
        labels[digest] = Label(digest, attack, row["scenario_id"], start)
    return labels


def labels_for(
    vectors: Sequence[Mapping[str, object]], labels: Mapping[str, Label]
) -> list[Label]:
    """One label per vector, in order; a missing label is an error, never "benign"."""

    result = []
    for vector in vectors:
        digest = canonical_hash(vector)
        try:
            result.append(labels[digest])
        except KeyError:
            raise LabelError("a vector in the evaluated partition has no label") from None
    return result


def scenario_ids(labels: Iterable[Label]) -> set[str]:
    return {item.scenario_id for item in labels if item.attack and item.scenario_id}
