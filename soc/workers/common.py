"""Shared building blocks for SOC workers: private SQLite state and Elasticsearch access.

Every worker owns one private state directory (0700) and one single-owner
lock.  Nothing here holds credentials in source: the Elasticsearch API key is
read from a file named by the environment, and TLS verification is mandatory.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any, Iterator, Mapping, Sequence
from urllib.parse import quote

from .https import DeliveryError, JsonHTTPS

_INDEX = re.compile(r"^[a-z0-9_.*,-]{1,255}$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def rfc3339(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_rfc3339(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def open_private_sqlite(path: Path) -> sqlite3.Connection:
    """Open a worker-owned SQLite file inside a private directory, WAL + FULL sync."""

    path = Path(path).absolute()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or parent.st_mode & 0o077
    ):
        raise ValueError("worker state directory must be an owned private directory (0700)")
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
        ):
            raise ValueError("worker state file must be a private owned regular file")
    finally:
        os.close(fd)
    db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    return db


@contextmanager
def single_owner(path: Path) -> Iterator[None]:
    """Hold an exclusive non-blocking flock for the lifetime of one worker run."""

    lock_path = Path(path).absolute().with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("worker lock must be private and owned by the worker")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another worker owns this state directory") from None
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def elastic_authorization(credential: str) -> str:
    """``user:password`` -> Basic (service users, Kubernetes); otherwise an API key (Compose)."""

    if ":" in credential:
        from base64 import b64encode

        return "Basic " + b64encode(credential.encode()).decode("ascii")
    return "ApiKey " + credential


def address_toward(hostname: str, port: int = 9200) -> str:
    """Local address of the interface that routes to ``hostname``.

    Used to bind a multi-homed container's listener to one specific network
    instead of every interface; no packet is sent (UDP connect only selects a route).
    """

    import socket

    target = socket.gethostbyname(hostname)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((target, port))
        return probe.getsockname()[0]


def read_secret_file(path: str | Path, label: str) -> str:
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value or any(char.isspace() for char in value):
        raise ValueError(f"{label} must be a single token without whitespace")
    return value


def elastic_transport_from_environment() -> JsonHTTPS:
    """TLS-verified transport from SOC_ES_URL / SOC_ES_CA / SOC_ES_API_KEY_FILE."""

    key_file = os.environ.get("SOC_ES_API_KEY_FILE") or os.environ["SOC_AI_ES_API_KEY_FILE"]
    return JsonHTTPS(
        os.environ["SOC_ES_URL"], ca=os.environ["SOC_ES_CA"],
        authorization=elastic_authorization(read_secret_file(key_file, "Elasticsearch credential")),
    )


def elastic_from_environment() -> "ElasticClient":
    return ElasticClient(elastic_transport_from_environment())


class ElasticClient:
    """Minimal Elasticsearch facade: bounded search, deterministic create."""

    def __init__(self, transport: JsonHTTPS) -> None:
        self._transport = transport

    @staticmethod
    def _index(index: str) -> str:
        if not _INDEX.fullmatch(index):
            raise ValueError(f"invalid index expression: {index!r}")
        return quote(index, safe=",*")

    def search(self, index: str, body: Mapping[str, Any]) -> list[dict[str, Any]]:
        status, reply = self._transport.request(
            "POST",
            f"/{self._index(index)}/_search?allow_no_indices=true&ignore_unavailable=true",
            dict(body),
        )
        if status != 200:
            raise DeliveryError("ES_SEARCH_NOT_ACKNOWLEDGED", retryable=True)
        hits = reply.get("hits", {}).get("hits", [])
        if not isinstance(hits, list):
            raise DeliveryError("ES_SEARCH_RESPONSE_CONTRACT", retryable=False)
        return hits

    def scan(
        self,
        index: str,
        query: Mapping[str, Any],
        sort: Sequence[Mapping[str, str]],
        *,
        source: Sequence[str] | None = None,
        page_size: int = 1000,
        limit: int | None = None,
        after: Sequence[Any] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Yield every matching hit with ``search_after`` paging.

        ``limit`` is a hard cap that raises :class:`ScanLimitExceeded` instead
        of silently truncating the result set.
        """

        if not 1 <= page_size <= 10000:
            raise ValueError("page_size must be between 1 and 10000")
        emitted = 0
        after = list(after) if after is not None else None
        while True:
            body: dict[str, Any] = {
                "size": page_size,
                "query": dict(query),
                "sort": [dict(item) for item in sort],
                "track_total_hits": False,
            }
            if source is not None:
                body["_source"] = list(source)
            if after is not None:
                body["search_after"] = after
            hits = self.search(index, body)
            for hit in hits:
                emitted += 1
                if limit is not None and emitted > limit:
                    raise ScanLimitExceeded(limit)
                yield hit
            if len(hits) < page_size:
                return
            after = hits[-1].get("sort")
            if not isinstance(after, list):
                raise DeliveryError("ES_SEARCH_RESPONSE_CONTRACT", retryable=False)

    def create(self, index: str, doc_id: str, document: Mapping[str, Any]) -> bool:
        """Create one immutable document; ``False`` means it already existed."""

        if not _INDEX.fullmatch(index) or "*" in index or "," in index:
            raise ValueError(f"invalid concrete index: {index!r}")
        if not doc_id or len(doc_id) > 512:
            raise ValueError("document id must be 1..512 characters")
        try:
            status, reply = self._transport.request(
                "PUT", f"/{index}/_create/{quote(doc_id, safe='')}", dict(document)
            )
        except DeliveryError as exc:
            if exc.status == 409:
                return False
            raise
        if status != 201 or reply.get("result") != "created":
            raise DeliveryError("ES_CREATE_NOT_ACKNOWLEDGED", retryable=True)
        return True


class ScanLimitExceeded(RuntimeError):
    def __init__(self, limit: int) -> None:
        super().__init__(f"scan exceeded the configured limit of {limit} documents")
        self.limit = limit
