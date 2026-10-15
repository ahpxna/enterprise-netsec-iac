"""LSTM autoencoder over fixed-length window sequences (second model family).

The network reconstructs a sequence of consecutive five-minute feature rows of
one entity; a large reconstruction error means the recent behaviour is unlike
the benign training sequences.  Sequences, preprocessing and score calibration
are deterministic, and the artifact is a ``safetensors`` file: unlike a pickle
it can only contain tensors and string metadata, so loading it cannot execute
code even before the provenance digest has been checked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import struct
from typing import Any, Mapping, Sequence

from ai.features.contracts import (
    FeatureSchemaError,
    expected_feature_names,
    feature_schema_sha256,
)

SEQUENCE_LENGTH = 6
RATIO_FEATURES = frozenset({"blocked_ratio"})
_STD_FLOOR = 1e-6


class LstmModelError(RuntimeError):
    """Raised when the sequence model cannot be trained, loaded, or evaluated safely."""


def _torch():
    try:
        import torch
    except ImportError as exc:  # pragma: no cover - deployment dependency error
        raise LstmModelError(
            "PyTorch is unavailable; install requirements-soc-lstm.txt for the LSTM family"
        ) from exc
    return torch


def _transform(rows: Sequence[Sequence[float]], names: Sequence[str]) -> list[list[float]]:
    """log1p for counts, identity for ratios; keeps heavy-tailed counters trainable."""

    out: list[list[float]] = []
    for row in rows:
        out.append([
            value if name in RATIO_FEATURES else math.log1p(max(0.0, value))
            for value, name in zip(row, names)
        ])
    return out


def read_safetensors_metadata(data: bytes) -> dict[str, str]:
    """Return the ``__metadata__`` header of a safetensors blob without loading tensors."""

    if len(data) < 8:
        raise LstmModelError("safetensors artifact is truncated")
    (header_size,) = struct.unpack("<Q", data[:8])
    if header_size > 16 * 1024 * 1024 or 8 + header_size > len(data):
        raise LstmModelError("safetensors header is invalid")
    try:
        header = json.loads(data[8 : 8 + header_size])
    except ValueError as exc:
        raise LstmModelError("safetensors header is not JSON") from exc
    metadata = header.get("__metadata__", {})
    if not isinstance(metadata, dict) or not all(isinstance(v, str) for v in metadata.values()):
        raise LstmModelError("safetensors metadata must map strings to strings")
    return metadata


def canonical_safetensors(data: bytes) -> bytes:
    """Rewrite the JSON header with sorted keys so identical tensors give identical bytes.

    The safetensors writer emits header keys in hash-map order, which varies
    between processes; provenance digests require a byte-reproducible artifact.
    Tensor data and offsets are untouched, so the file stays a valid safetensors.
    """

    (size,) = struct.unpack("<Q", data[:8])
    header = json.loads(data[8 : 8 + size])
    body = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body += b" " * (-len(body) % 8)
    return struct.pack("<Q", len(body)) + body + data[8 + size :]


@dataclass
class SocLstmAutoencoder:
    """Preprocessing + calibrated autoencoder; scoring is pure and deterministic."""

    feature_schema: str
    feature_schema_sha256: str
    feature_names: tuple[str, ...]
    sequence_length: int
    hidden_size: int
    latent_size: int
    mean: list[float]
    std: list[float]
    calibration_low: float
    calibration_high: float
    state: dict[str, Any] = field(repr=False, default_factory=dict)
    _module: Any = field(repr=False, default=None)

    # ------------------------------------------------------------ network
    @staticmethod
    def _build(feature_count: int, hidden: int, latent: int, length: int):
        torch = _torch()
        nn = torch.nn

        class Net(nn.Module):
            def __init__(self) -> None:
                super().__init__()
                self.encoder = nn.LSTM(feature_count, hidden, batch_first=True)
                self.to_latent = nn.Linear(hidden, latent)
                self.from_latent = nn.Linear(latent, hidden)
                self.decoder = nn.LSTM(hidden, hidden, batch_first=True)
                self.output = nn.Linear(hidden, feature_count)

            def forward(self, batch):
                _, (hidden_state, _) = self.encoder(batch)
                code = self.to_latent(hidden_state[-1])
                seed = self.from_latent(code).unsqueeze(1).repeat(1, length, 1)
                decoded, _ = self.decoder(seed)
                return self.output(decoded)

        return Net()

    def _tensor(self, matrices: Sequence[Sequence[Sequence[float]]]):
        torch = _torch()
        array = [
            [
                [(value - m) / s for value, m, s in zip(row, self.mean, self.std)]
                for row in _transform(matrix, self.feature_names)
            ]
            for matrix in matrices
        ]
        return torch.tensor(array, dtype=torch.float32)

    @property
    def module(self):
        if self._module is None:
            module = self._build(
                len(self.feature_names), self.hidden_size, self.latent_size, self.sequence_length
            )
            module.load_state_dict(self.state)
            module.eval()
            self._module = module
        return self._module

    def raw_errors(self, matrices: Sequence[Sequence[Sequence[float]]]) -> list[float]:
        torch = _torch()
        for matrix in matrices:
            if len(matrix) != self.sequence_length:
                raise FeatureSchemaError(
                    f"sequence must contain exactly {self.sequence_length} windows"
                )
        with torch.no_grad():
            batch = self._tensor(matrices)
            reconstruction = self.module(batch)
            errors = ((reconstruction - batch) ** 2).mean(dim=(1, 2))
        values = [float(item) for item in errors]
        if not all(math.isfinite(item) for item in values):
            raise LstmModelError("model returned a non-finite reconstruction error")
        return values

    def score_matrix(self, matrix: Sequence[Sequence[float]]) -> float:
        raw = self.raw_errors([matrix])[0]
        span = self.calibration_high - self.calibration_low
        return max(0.0, min(1.0, (raw - self.calibration_low) / span))

    # ------------------------------------------------------------ training
    @classmethod
    def fit(
        cls,
        feature_schema: str,
        sequences: Sequence[Sequence[Sequence[float]]],
        *,
        random_seed: int,
        epochs: int = 60,
        hidden_size: int = 16,
        latent_size: int = 4,
        learning_rate: float = 0.01,
        batch_size: int = 64,
        sequence_length: int = SEQUENCE_LENGTH,
    ) -> "SocLstmAutoencoder":
        if len(sequences) < 4:
            raise LstmModelError("the LSTM autoencoder needs at least four training sequences")
        torch = _torch()
        names = expected_feature_names(feature_schema)
        for matrix in sequences:
            if len(matrix) != sequence_length or any(len(row) != len(names) for row in matrix):
                raise LstmModelError("every training sequence must be a full window matrix")
        flat = _transform([row for matrix in sequences for row in matrix], names)
        count = len(flat)
        mean = [sum(row[i] for row in flat) / count for i in range(len(names))]
        std = [
            max(_STD_FLOOR, math.sqrt(sum((row[i] - mean[i]) ** 2 for row in flat) / count))
            for i in range(len(names))
        ]
        torch.manual_seed(random_seed)
        torch.use_deterministic_algorithms(True)
        torch.set_num_threads(1)
        model = cls(
            feature_schema=feature_schema,
            feature_schema_sha256=feature_schema_sha256(feature_schema),
            feature_names=names,
            sequence_length=sequence_length,
            hidden_size=hidden_size,
            latent_size=latent_size,
            mean=mean,
            std=std,
            calibration_low=0.0,
            calibration_high=1.0,
        )
        data = model._tensor(sequences)
        module = cls._build(len(names), hidden_size, latent_size, sequence_length)
        optimizer = torch.optim.Adam(module.parameters(), lr=learning_rate)
        generator = torch.Generator().manual_seed(random_seed)
        module.train()
        for _ in range(epochs):
            order = torch.randperm(len(data), generator=generator)
            for offset in range(0, len(order), batch_size):
                batch = data[order[offset : offset + batch_size]]
                optimizer.zero_grad()
                loss = ((module(batch) - batch) ** 2).mean()
                loss.backward()
                optimizer.step()
        module.eval()
        model.state = {key: value.detach().clone() for key, value in module.state_dict().items()}
        model._module = module
        errors = sorted(model.raw_errors(sequences))
        low = errors[int(0.01 * (len(errors) - 1))]
        high = errors[int(math.ceil(0.99 * (len(errors) - 1)))]
        if high <= low:
            high = low + 1e-12
        model.calibration_low, model.calibration_high = float(low), float(high)
        return model

    # --------------------------------------------------------- serialization
    def to_safetensors(self) -> bytes:
        torch = _torch()
        try:
            from safetensors.torch import save
        except ImportError as exc:  # pragma: no cover - deployment dependency error
            raise LstmModelError("safetensors is required to write the LSTM artifact") from exc
        tensors = {key: value.contiguous() for key, value in self.state.items()}
        tensors["preprocess.mean"] = torch.tensor(self.mean, dtype=torch.float64)
        tensors["preprocess.std"] = torch.tensor(self.std, dtype=torch.float64)
        tensors["calibration"] = torch.tensor(
            [self.calibration_low, self.calibration_high], dtype=torch.float64
        )
        metadata = {
            "format": "cxyz-lstm-autoencoder-v1",
            "feature_schema": self.feature_schema,
            "feature_schema_sha256": self.feature_schema_sha256,
            "feature_names": json.dumps(list(self.feature_names)),
            "sequence_length": str(self.sequence_length),
            "hidden_size": str(self.hidden_size),
            "latent_size": str(self.latent_size),
        }
        return canonical_safetensors(save(tensors, metadata=metadata))

    @classmethod
    def from_safetensors(cls, data: bytes) -> "SocLstmAutoencoder":
        try:
            from safetensors.torch import load
        except ImportError as exc:  # pragma: no cover - deployment dependency error
            raise LstmModelError("safetensors is required to load the LSTM artifact") from exc
        meta = read_safetensors_metadata(data)
        if meta.get("format") != "cxyz-lstm-autoencoder-v1":
            raise LstmModelError("artifact is not a CompanyXYZ LSTM autoencoder")
        try:
            names = tuple(json.loads(meta["feature_names"]))
            length, hidden, latent = (int(meta[k]) for k in ("sequence_length", "hidden_size", "latent_size"))
            schema, schema_hash = meta["feature_schema"], meta["feature_schema_sha256"]
        except (KeyError, ValueError, TypeError) as exc:
            raise LstmModelError("LSTM artifact metadata is incomplete") from exc
        if not (2 <= length <= 288 and 1 <= latent <= hidden <= 512):
            raise LstmModelError("LSTM artifact dimensions are outside the supported range")
        tensors = load(data)
        try:
            mean = [float(v) for v in tensors.pop("preprocess.mean")]
            std = [float(v) for v in tensors.pop("preprocess.std")]
            low, high = (float(v) for v in tensors.pop("calibration"))
        except KeyError as exc:
            raise LstmModelError("LSTM artifact lacks preprocessing or calibration") from exc
        if len(mean) != len(names) or len(std) != len(names) or any(s <= 0 for s in std):
            raise LstmModelError("LSTM preprocessing does not match its feature names")
        return cls(
            feature_schema=schema,
            feature_schema_sha256=schema_hash,
            feature_names=names,
            sequence_length=length,
            hidden_size=hidden,
            latent_size=latent,
            mean=mean,
            std=std,
            calibration_low=low,
            calibration_high=high,
            state=dict(tensors),
        )
