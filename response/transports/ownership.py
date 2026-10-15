"""Durable ownership tracking so containment never removes someone else's entry.

A firewall set can already contain an address (an analyst's manual block, another
response, a prior operation).  Releasing "our" block with a blind delete would
silently lift that protection.  This ledger records, per peer, which operations
(idempotency keys) hold an address and whether the address pre-existed our first
claim.  An entry is physically removed only by the last owner of an address the
response plane itself added.

The intent is recorded *before* the side effect, so an add that times out after
the peer applied it is still owned and can be released; every operation is safe
to repeat.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import sqlite3
import stat
from threading import RLock
from typing import Protocol


class RawSet(Protocol):
    """The three set operations a backend must provide (all idempotent)."""

    def contains(self, address: str) -> bool: ...

    def add(self, address: str, max_lifetime_seconds: int | None) -> None: ...

    def remove(self, address: str) -> None: ...


def _private_db(path: Path) -> sqlite3.Connection:
    path = Path(path).absolute()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
        raise ValueError("ownership ledger directory must be an owned private directory (0700)")
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("ownership ledger must be a private owned regular file")
    finally:
        os.close(fd)
    db = sqlite3.connect(path, timeout=30, check_same_thread=False)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS owners (
            address TEXT NOT NULL, owner TEXT NOT NULL,
            mode TEXT NOT NULL CHECK(mode IN ('adding','owned')),
            PRIMARY KEY(address, owner)
        );
        CREATE TABLE IF NOT EXISTS foreign_entries (address TEXT PRIMARY KEY);
        """
    )
    return db


class OwnershipLedger:
    def __init__(self, path: Path) -> None:
        self.db = _private_db(path)

    def owners(self, address: str) -> dict[str, str]:
        return {
            row[0]: row[1]
            for row in self.db.execute("SELECT owner, mode FROM owners WHERE address=?", (address,))
        }

    def is_foreign(self, address: str) -> bool:
        return self.db.execute(
            "SELECT 1 FROM foreign_entries WHERE address=?", (address,)
        ).fetchone() is not None

    def claim(self, address: str, owner: str, mode: str, *, foreign: bool = False) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO owners(address, owner, mode) VALUES(?,?,?) "
                "ON CONFLICT(address, owner) DO UPDATE SET mode=excluded.mode",
                (address, owner, mode),
            )
            if foreign:
                self.db.execute("INSERT OR IGNORE INTO foreign_entries(address) VALUES(?)", (address,))

    def release(self, address: str, owner: str) -> None:
        with self.db:
            self.db.execute("DELETE FROM owners WHERE address=? AND owner=?", (address, owner))
            if not self.db.execute("SELECT 1 FROM owners WHERE address=?", (address,)).fetchone():
                # With no remaining claim the "pre-existing" mark is meaningless;
                # a later claim must re-observe the peer.
                self.db.execute("DELETE FROM foreign_entries WHERE address=?", (address,))

    def close(self) -> None:
        self.db.close()


class OwnedBlocklistClient:
    """Adapts a raw set backend to the adapter protocol with ownership semantics."""

    def __init__(self, raw: RawSet, ledger: OwnershipLedger) -> None:
        self._raw = raw
        self._ledger = ledger
        self._lock = RLock()

    @staticmethod
    def _norm(address: str) -> str:
        return str(ipaddress.ip_address(address))

    @staticmethod
    def _tag(kind: str, key: str) -> str:
        return f"{kind}:{key[-12:]}"

    def add_soc_blocklist_address(
        self, *, address: str, idempotency_key: str, max_lifetime_seconds: int | None = None
    ) -> str:
        address = self._norm(address)
        with self._lock:
            owners = self._ledger.owners(address)
            foreign = self._ledger.is_foreign(address)
            if idempotency_key in owners:
                if not self._raw.contains(address):
                    self._raw.add(address, max_lifetime_seconds)
                self._ledger.claim(address, idempotency_key, "owned")
                return self._tag("owned", idempotency_key)
            if not owners and not foreign:
                if self._raw.contains(address):
                    self._ledger.claim(address, idempotency_key, "owned", foreign=True)
                    return self._tag("preexisting", idempotency_key)
                self._ledger.claim(address, idempotency_key, "adding")  # intent before effect
                self._raw.add(address, max_lifetime_seconds)
                self._ledger.claim(address, idempotency_key, "owned")
                return self._tag("added", idempotency_key)
            self._ledger.claim(address, idempotency_key, "owned")
            if not self._raw.contains(address):  # e.g. the firewall-side backstop expired it
                self._raw.add(address, max_lifetime_seconds)
            return self._tag("shared", idempotency_key)

    def remove_soc_blocklist_address(self, *, address: str, idempotency_key: str) -> str:
        address = self._norm(address)
        with self._lock:
            owners = self._ledger.owners(address)
            if idempotency_key not in owners:
                return self._tag("absent", idempotency_key)
            others = set(owners) - {idempotency_key}
            if others or self._ledger.is_foreign(address):
                self._ledger.release(address, idempotency_key)
                return self._tag("shared" if others else "preexisting", idempotency_key)
            # Last owner of an entry this plane created: remove first, forget second,
            # so a crash in between simply repeats the (idempotent) removal.
            self._raw.remove(address)
            self._ledger.release(address, idempotency_key)
            return self._tag("removed", idempotency_key)

    def soc_blocklist_contains(self, *, address: str) -> bool:
        return self._raw.contains(self._norm(address))
