"""Single-writer SQLite outbox: immutable inputs/results survive process restart."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class Outbox:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Private directory also protects the SQLite WAL, SHM and lock files.
        parent = path.parent.stat()
        if path.parent.is_symlink() or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise ValueError("outbox parent directory must have mode 0700")
        self._lock_path = path.with_suffix(".lock")
        self._lock_depth = 0
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("outbox must be a private regular file owned by the worker")
        finally:
            os.close(fd)
        self.db = sqlite3.connect(path, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, metadata_hash TEXT NOT NULL,
                vector TEXT NOT NULL, event TEXT,
                state TEXT NOT NULL CHECK(state IN ('pending','scored','sent','deadletter')),
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0,
                error_code TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS jobs_due ON jobs(state, next_attempt);
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS immutable_input BEFORE UPDATE ON jobs
            WHEN NEW.vector != OLD.vector OR NEW.metadata_hash != OLD.metadata_hash OR NEW.id != OLD.id
            BEGIN SELECT RAISE(ABORT, 'outbox input is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS immutable_result BEFORE UPDATE ON jobs
            WHEN OLD.event IS NOT NULL AND (NEW.event IS NULL OR NEW.event != OLD.event)
            BEGIN SELECT RAISE(ABORT, 'outbox inference result is immutable'); END;
        """)

    @contextmanager
    def exclusive(self):
        # Re-entrant within one Outbox: `serve` holds the lock around pull + drain and
        # drain() takes it again. A second flock on a new descriptor would conflict with
        # our own first one; other processes are still refused below.
        if self._lock_depth:
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
            return
        fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("outbox lock must be private and owned by the worker")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("another outbox worker is active") from None
            self._lock_depth = 1
            try:
                yield
            finally:
                self._lock_depth = 0
                fcntl.flock(lock, fcntl.LOCK_UN)

    def enqueue(self, vector: dict, metadata_hash: str) -> bool:
        if not re.fullmatch(r"[a-f0-9]{64}", metadata_hash):
            raise ValueError("approved metadata SHA-256 is required")
        body = canonical(vector)
        identifier = sha256((metadata_hash + "\n" + body).encode()).hexdigest()
        now = time.time()
        with self.db:
            result = self.db.execute(
                "INSERT OR IGNORE INTO jobs(id,metadata_hash,vector,state,created_at,updated_at) "
                "VALUES(?,?,?,'pending',?,?)", (identifier, metadata_hash, body, now, now))
        return result.rowcount == 1

    def due(self, limit: int) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM jobs WHERE state IN ('pending','scored') AND next_attempt<=? "
            "ORDER BY created_at,id LIMIT ?", (time.time(), limit)).fetchall()

    def save_event(self, identifier: str, event: dict) -> None:
        with self.db:
            self.db.execute("UPDATE jobs SET event=?,state='scored',error_code=NULL,updated_at=? "
                            "WHERE id=? AND state='pending'", (canonical(event), time.time(), identifier))

    def sent(self, identifier: str) -> None:
        with self.db:
            self.db.execute("UPDATE jobs SET state='sent',error_code=NULL,updated_at=? "
                            "WHERE id=? AND state='scored'", (time.time(), identifier))

    def failed(self, identifier: str, *, code: str, retryable: bool) -> None:
        row = self.db.execute("SELECT attempts,state FROM jobs WHERE id=?", (identifier,)).fetchone()
        attempts = row["attempts"] + 1
        delay = min(3600, 5 * 2 ** min(attempts, 10))
        # Transient failure never drops a job or exhausts it into silent loss.
        state = row["state"] if retryable else "deadletter"
        with self.db:
            self.db.execute("UPDATE jobs SET state=?,attempts=?,next_attempt=?,error_code=?,updated_at=? "
                            "WHERE id=?", (state, attempts, time.time() + delay, code, time.time(), identifier))

    def requeue(self, identifier: str) -> None:
        with self.db:
            result = self.db.execute(
                "UPDATE jobs SET state=CASE WHEN event IS NULL THEN 'pending' ELSE 'scored' END, "
                "next_attempt=0,error_code=NULL,updated_at=? WHERE id=? AND state='deadletter'",
                (time.time(), identifier))
            if result.rowcount != 1:
                raise ValueError("unknown dead-letter job")

    def get_meta(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def status(self) -> dict:
        counts = {state: 0 for state in ("pending", "scored", "sent", "deadletter")}
        counts.update({row["state"]: row["n"] for row in self.db.execute(
            "SELECT state,count(*) AS n FROM jobs GROUP BY state")})
        return counts

    def close(self) -> None:
        self.db.close()
