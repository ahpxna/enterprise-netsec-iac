"""Asymmetric (Ed25519) command authentication for the decision -> orchestrator handoff.

The Decision Engine holds the only private key; the Orchestrator and any auditor
hold public keys.  A compromised orchestrator can therefore verify commands but
can never forge one, which the shared-key HMAC reference authenticator cannot
guarantee.  Key rotation is a key-ring change: commands name their ``key_id`` and
the verifier accepts any ring member until it is removed.
"""

from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime
import os
from pathlib import Path
import re
import stat
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .decision import _as_utc, _parse_rfc3339, _signature_payload
from .errors import CorrelationRejected

_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _b64(data: bytes) -> str:
    return urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    """Load a PEM private key, refusing group/world-readable key files."""

    path = Path(path)
    info = path.stat()
    own_private = info.st_uid == os.getuid() and not info.st_mode & 0o077
    # Kubernetes mounts Secrets root-owned with group access for the pod's fsGroup;
    # accept that shape only (no world bits, group read-only, process is in the group).
    orchestrated = (
        info.st_uid == 0
        and not info.st_mode & 0o037
        and (info.st_gid in os.getgroups() or info.st_gid == os.getgid())
    )
    if not stat.S_ISREG(info.st_mode) or not (own_private or orchestrated):
        raise ValueError("the signing key must be a regular file readable only by its owner (0600)")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("the signing key must be an Ed25519 key")
    return key


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("verification keys must be Ed25519 public keys")
    return key


def load_key_ring(directory: str | Path) -> dict[str, Ed25519PublicKey]:
    """``<key_id>.pub`` files in a directory form the verification key ring."""

    ring = {}
    for path in sorted(Path(directory).glob("*.pub")):
        if _KEY_ID.fullmatch(path.stem):
            ring[path.stem] = load_public_key(path)
    if not ring:
        raise ValueError("the verification key ring is empty")
    return ring


class Ed25519CommandAuthenticator:
    """Implements ``CommandAuthenticator`` with a signing key, a key ring, or both."""

    def __init__(
        self,
        *,
        verify_keys: Mapping[str, Ed25519PublicKey],
        signing_key: Ed25519PrivateKey | None = None,
        signing_key_id: str | None = None,
    ) -> None:
        if not verify_keys or any(not _KEY_ID.fullmatch(key_id) for key_id in verify_keys):
            raise ValueError("a non-empty ring of valid key IDs is required")
        if (signing_key is None) != (signing_key_id is None):
            raise ValueError("signing_key and signing_key_id must be supplied together")
        if signing_key_id is not None and signing_key_id not in verify_keys:
            raise ValueError("the signing key ID must be a member of the key ring")
        self._ring = dict(verify_keys)
        self._signing_key = signing_key
        self.signing_key_id = signing_key_id

    @classmethod
    def signer(cls, private_key_path: str | Path, key_id: str) -> "Ed25519CommandAuthenticator":
        key = load_private_key(private_key_path)
        return cls(verify_keys={key_id: key.public_key()}, signing_key=key, signing_key_id=key_id)

    @classmethod
    def verifier(cls, key_ring_dir: str | Path) -> "Ed25519CommandAuthenticator":
        return cls(verify_keys=load_key_ring(key_ring_dir))

    def sign(self, command: Mapping[str, object]) -> str:
        if self._signing_key is None:
            raise CorrelationRejected("this authenticator has no signing key")
        return _b64(self._signing_key.sign(_signature_payload(command)))

    def verify(self, command: Mapping[str, object], *, now: datetime | None = None) -> None:
        authorization = command.get("authorization")
        if not isinstance(authorization, Mapping):
            raise CorrelationRejected("response command has no authorization")
        key_id = authorization.get("key_id")
        signature = authorization.get("signature")
        if not isinstance(key_id, str) or key_id not in self._ring:
            raise CorrelationRejected("response command uses an unknown authorization key")
        if not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature):
            raise CorrelationRejected("response command has an invalid authorization signature")
        try:
            self._ring[key_id].verify(_unb64(signature), _signature_payload(command))
        except (InvalidSignature, ValueError):
            raise CorrelationRejected("response command signature verification failed") from None
        issued_at = _parse_rfc3339(authorization.get("issued_at"), "authorization.issued_at")
        expires_at = _parse_rfc3339(authorization.get("expires_at"), "authorization.expires_at")
        if expires_at <= issued_at or _as_utc(now) >= expires_at:
            raise CorrelationRejected("response command authorization is expired")


def generate_key_pair(directory: str | Path, key_id: str) -> tuple[Path, Path]:
    """Create ``<key_id>.key`` (0600) and ``<key_id>.pub``; refuses to overwrite."""

    if not _KEY_ID.fullmatch(key_id):
        raise ValueError("invalid key id")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_path, public_path = directory / f"{key_id}.key", directory / f"{key_id}.pub"
    key = Ed25519PrivateKey.generate()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(private_path, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ))
    public_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    return private_path, public_path


def main() -> int:  # pragma: no cover - thin CLI
    import argparse

    parser = argparse.ArgumentParser(description="Generate a decision-engine Ed25519 key pair")
    parser.add_argument("directory", type=Path)
    parser.add_argument("key_id")
    args = parser.parse_args()
    private_path, public_path = generate_key_pair(args.directory, args.key_id)
    print(f"private key {private_path} (0600); distribute only {public_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
