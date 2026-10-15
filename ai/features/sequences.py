"""Deterministic fixed-length window sequences for sequence models.

A sequence is the ``length`` consecutive five-minute windows that end at the
current window.  An entity that produced no telemetry in a window has no vector
there; "no events" is a well defined all-zero feature row, so a missing window
is represented as zeros rather than guessed, interpolated, or dropped.  The same
function builds training sequences and serving requests, which keeps the two
bit-for-bit consistent.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Mapping, Sequence

from .contracts import expected_feature_names, ordered_feature_row

WINDOW = timedelta(minutes=5)


def _parse(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _rfc3339(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def history_window_ends(window_end: str, length: int) -> list[str]:
    """Window-end timestamps of the ``length - 1`` windows before ``window_end``, oldest first."""

    if length < 2:
        raise ValueError("sequence length must be at least 2")
    end = _parse(window_end)
    return [_rfc3339(end - WINDOW * offset) for offset in range(length - 1, 0, -1)]


def sequence_matrix(
    feature_schema: str,
    history: Sequence[Mapping[str, object] | None],
    features: Mapping[str, object],
) -> list[list[float]]:
    """Rows for ``history`` (oldest first, ``None`` = no events) plus the current window."""

    width = len(expected_feature_names(feature_schema))
    rows = [
        [0.0] * width if item is None else ordered_feature_row(feature_schema, item)
        for item in history
    ]
    rows.append(ordered_feature_row(feature_schema, features))
    return rows


def entity_history(
    vector: Mapping[str, object],
    index: Mapping[tuple[str, str], Mapping[str, object]],
    length: int,
) -> list[Mapping[str, object] | None]:
    """Features of the preceding windows for ``vector``'s entity (``None`` where absent).

    ``index`` comes from :func:`index_vectors_by_window_end`.
    """

    entity = str(vector["entity"])
    result: list[Mapping[str, object] | None] = []
    for end in history_window_ends(str(vector["window_end"]), length):
        earlier = index.get((entity, end))
        result.append(earlier["features"] if earlier is not None else None)  # type: ignore[index]
    return result


def index_vectors_by_window_end(
    vectors: Sequence[Mapping[str, object]],
) -> dict[tuple[str, str], Mapping[str, object]]:
    """Index vectors by ``(entity, window_end)`` for O(1) history lookups."""

    return {(str(item["entity"]), _rfc3339(_parse(str(item["window_end"])))): item for item in vectors}
