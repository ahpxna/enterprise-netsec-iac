"""Durable append-only local audit; not an orchestrator recovery store.

SQLite serializes writers and validates transitions inside the write transaction.
Database administrators can bypass triggers: export evidence to independent
immutable storage for adversarial tamper resistance.
"""

import json
import os
from pathlib import Path
import sqlite3
import stat
from datetime import datetime

from .audit import InMemoryAuditLedger
from ..errors import CommandRejected


class SQLiteAuditLedger:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = path.parent.stat()
        if path.parent.is_symlink() or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise ValueError("audit directory must be private and owned by the service")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("audit file must be private and owned by the service")
        finally:
            os.close(fd)
        self.db = sqlite3.connect(path, timeout=30)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS commands (
                response_id TEXT PRIMARY KEY, body TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS no_command_update BEFORE UPDATE ON commands
            BEGIN SELECT RAISE(ABORT, 'recovery command is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS no_command_delete BEFORE DELETE ON commands
            BEGIN SELECT RAISE(ABORT, 'recovery command is immutable'); END;
            CREATE TABLE IF NOT EXISTS apply_intents (
                response_id TEXT PRIMARY KEY
            );
            CREATE TRIGGER IF NOT EXISTS no_intent_update BEFORE UPDATE ON apply_intents
            BEGIN SELECT RAISE(ABORT, 'application intent is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS no_intent_delete BEFORE DELETE ON apply_intents
            BEGIN SELECT RAISE(ABORT, 'application intent is immutable'); END;
            CREATE TABLE IF NOT EXISTS audit (
                response_id TEXT NOT NULL, transition_number INTEGER NOT NULL,
                body TEXT NOT NULL,
                PRIMARY KEY(response_id, transition_number)
            );
            CREATE TRIGGER IF NOT EXISTS no_audit_update BEFORE UPDATE ON audit
            BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS no_audit_delete BEFORE DELETE ON audit
            BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
        """)

    def save_command(self, response_id, command):
        body = json.dumps(command, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            previous = self.db.execute("SELECT body FROM commands WHERE response_id=?", (response_id,)).fetchone()
            if previous and previous[0] != body:
                raise CommandRejected("recovery command is immutable")
            if not previous:
                self.db.execute("INSERT INTO commands VALUES(?,?)", (response_id, body))

    def commands(self):
        return tuple((row[0], json.loads(row[1])) for row in self.db.execute(
            "SELECT response_id,body FROM commands ORDER BY response_id"))

    def claim_apply(self, response_id):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            latest = self.latest(response_id)
            if latest is None or latest["state"] != "REQUESTED":
                raise CommandRejected("application intent requires REQUESTED audit state")
            try:
                self.db.execute("INSERT INTO apply_intents VALUES(?)", (response_id,))
            except sqlite3.IntegrityError as exc:
                raise CommandRejected("application already attempted; reconciliation required") from exc

    def append(self, event):
        # Round-trip isolates caller mutations and rejects nonfinite JSON values.
        body = json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False)
        payload = json.loads(body)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            reference = InMemoryAuditLedger()
            for previous in self.events(payload.get("response_id")):
                reference.append(previous)
            reference.append(payload)
            self.db.execute("INSERT INTO audit VALUES(?,?,?)", (
                payload["response_id"], payload["transition_number"], body))

    def latest(self, response_id):
        row = self.db.execute(
            "SELECT body FROM audit WHERE response_id=? ORDER BY transition_number DESC LIMIT 1",
            (response_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def recovery_queue(self):
        """Snapshot unresolved attempted writes; never infer enforcement success.

        An intent with no APPLIED evidence may still have changed a peer. Such
        entries require read-only peer reconciliation, not automatic replay.
        """
        rows = self.db.execute("""
            SELECT a.body FROM apply_intents i JOIN audit a
            ON a.response_id=i.response_id
            WHERE a.transition_number=(SELECT MAX(b.transition_number) FROM audit b
                                      WHERE b.response_id=a.response_id)
            ORDER BY a.response_id
        """)
        pending = []
        for row in rows:
            latest = json.loads(row[0])
            if latest["state"] in {"EXPIRED", "ROLLED_BACK"}:
                continue
            pending.append({
                "response_id": latest["response_id"],
                "state": latest["state"],
                "target": latest.get("target"),
                "action": latest.get("action"),
                "expires_at": latest.get("expires_at"),
                "automatic_replay_allowed": False,
                "requires_peer_reconciliation": True,
                "latest_audit": latest,
            })
        return tuple(pending)

    def requested_since(self, policy_id, since):
        count = 0
        for (body,) in self.db.execute("SELECT body FROM audit WHERE transition_number=1"):
            event = json.loads(body)
            if event.get("policy_id") == policy_id and datetime.fromisoformat(
                event["@timestamp"].replace("Z", "+00:00")
            ) > since:
                count += 1
        return count

    def events(self, response_id):
        return tuple(json.loads(row[0]) for row in self.db.execute(
            "SELECT body FROM audit WHERE response_id=? ORDER BY transition_number", (response_id,)))

    def close(self):
        self.db.close()
