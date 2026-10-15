"""Private, single-process SQLite response journal and immutable audit history."""

from contextlib import contextmanager
from datetime import datetime
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
from threading import RLock

from ..errors import CommandRejected
from .audit import validate_transition


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class SQLiteResponseStore:
    """Hold one owner lock for the store lifetime; checkpoint state with audit.

    Use a private local directory, not a shared/NFS volume. One orchestrator
    owns this instance until close. Multi-host coordination is not provided.
    """

    def __init__(self, path: str | Path):
        path = Path(path).absolute()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise ValueError("response store needs an owned, private directory (0700)")
        self._mutex = RLock()
        self._closed = False
        self._claimed = False
        self._lock_fd = self._private_file(path.with_name(path.name + ".lock"))
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self._lock_fd)
            raise RuntimeError("another response store owner is active") from None
        self.db = None
        try:
            fd = self._private_file(path)
            os.close(fd)
            self.db = sqlite3.connect(path, timeout=30, check_same_thread=False)
            self.db.row_factory = sqlite3.Row
            columns = {row["name"] for row in self.db.execute("PRAGMA table_info(audit)")}
            if columns and columns != {"id", "response_id", "transition_number", "payload"}:
                raise ValueError("incompatible audit database; use a separate response store path")
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript('''
                CREATE TABLE IF NOT EXISTS records (
                    id TEXT PRIMARY KEY, command TEXT NOT NULL,
                    expires_at TEXT NOT NULL, snapshot TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id TEXT PRIMARY KEY, response_id TEXT NOT NULL,
                    transition_number INTEGER NOT NULL, payload TEXT NOT NULL,
                    UNIQUE(response_id, transition_number)
                );
                CREATE TABLE IF NOT EXISTS apply_intents (
                    response_id TEXT PRIMARY KEY
                );
                CREATE TRIGGER IF NOT EXISTS intent_no_update BEFORE UPDATE ON apply_intents
                BEGIN SELECT RAISE(ABORT, 'apply intent is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS intent_no_delete BEFORE DELETE ON apply_intents
                BEGIN SELECT RAISE(ABORT, 'apply intent is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
                BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
                BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS record_input_immutable BEFORE UPDATE ON records
                WHEN NEW.command != OLD.command OR NEW.id != OLD.id OR NEW.expires_at != OLD.expires_at
                BEGIN SELECT RAISE(ABORT, 'response input is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS records_no_delete BEFORE DELETE ON records
                BEGIN SELECT RAISE(ABORT, 'response identities must be retained'); END;
                CREATE TABLE IF NOT EXISTS admissions (
                    response_id TEXT PRIMARY KEY, policy_id TEXT NOT NULL, admitted_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS admissions_policy_time ON admissions(policy_id, admitted_at);
                CREATE TRIGGER IF NOT EXISTS admissions_no_update BEFORE UPDATE ON admissions
                BEGIN SELECT RAISE(ABORT, 'admissions are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS admissions_no_delete BEFORE DELETE ON admissions
                BEGIN SELECT RAISE(ABORT, 'admissions are append-only'); END;
                CREATE TABLE IF NOT EXISTS exported (audit_id TEXT PRIMARY KEY);
                CREATE TRIGGER IF NOT EXISTS exported_no_update BEFORE UPDATE ON exported
                BEGIN SELECT RAISE(ABORT, 'export marks are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS exported_no_delete BEFORE DELETE ON exported
                BEGIN SELECT RAISE(ABORT, 'export marks are append-only'); END;
            ''')
            self._backfill_admissions()
        except BaseException:
            self.close()
            raise

    def _backfill_admissions(self):
        """Databases created before the admissions index get it populated once."""

        with self.db:
            if self.db.execute("SELECT 1 FROM admissions LIMIT 1").fetchone():
                return
            for row in self.db.execute("SELECT payload FROM audit WHERE transition_number=1").fetchall():
                self._record_admission(json.loads(row["payload"]))

    def _record_admission(self, event):
        when = datetime.fromisoformat(event["@timestamp"].replace("Z", "+00:00")).timestamp()
        self.db.execute(
            "INSERT OR IGNORE INTO admissions(response_id, policy_id, admitted_at) VALUES(?,?,?)",
            (event["response_id"], event.get("policy_id"), when),
        )

    @staticmethod
    def _private_file(path):
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            os.close(fd)
            raise ValueError("response journal files must be private owned regular files")
        return fd

    @contextmanager
    def exclusive(self):
        with self._mutex:
            if self._closed:
                raise RuntimeError("response store is closed")
            yield

    def claim(self):
        with self.exclusive():
            if self._claimed:
                raise RuntimeError("store already belongs to an orchestrator")
            self._claimed = True

    def load(self):
        with self.exclusive():
            records = [json.loads(row["snapshot"]) for row in self.db.execute("SELECT snapshot FROM records")]
            for record in records:
                latest = self.latest(record["response_id"])
                if (latest is None or latest["state"] != record["state"]
                        or latest["transition_number"] != record["transition_number"]):
                    raise CommandRejected("response checkpoint differs from its audit history")
            return records

    def checkpoint(self, record, *, event=None):
        with self.exclusive(), self.db:
            if event is None and record["pending_operation"] == "apply":
                try:
                    self.db.execute("INSERT INTO apply_intents VALUES(?)", (record["response_id"],))
                except sqlite3.IntegrityError as exc:
                    raise CommandRejected("application already attempted; recovery required") from exc
            if event is not None:
                history = self.events(record["response_id"])
                validate_transition(event, history)
                self.db.execute(
                    "INSERT INTO audit(id,response_id,transition_number,payload) VALUES(?,?,?,?)",
                    (event["audit_event_id"], record["response_id"], event["transition_number"], canonical(event)),
                )
                if event["transition_number"] == 1:
                    self._record_admission(event)
            latest = self.latest(record["response_id"])
            if (latest is None or latest["state"] != record["state"]
                    or latest["transition_number"] != record["transition_number"]):
                raise CommandRejected("checkpoint must match the latest audit event")
            self.db.execute(
                "INSERT INTO records(id,command,expires_at,snapshot) VALUES(?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET command=excluded.command, "
                "expires_at=excluded.expires_at,snapshot=excluded.snapshot",
                (record["response_id"], canonical(record["command"]), record["expires_at"], canonical(record)),
            )

    def claim_apply(self, response_id):
        raise RuntimeError("apply intent must be committed atomically through checkpoint")

    def requested_since(self, policy_id, since):
        """Committed submissions (including denied ones) newer than ``since``; indexed."""

        with self.exclusive():
            row = self.db.execute(
                "SELECT COUNT(*) FROM admissions WHERE policy_id=? AND admitted_at>?",
                (policy_id, since.timestamp()),
            ).fetchone()
            return int(row[0])

    def unexported_events(self, limit):
        """Audit events not yet delivered to the external audit stream, oldest first."""

        with self.exclusive():
            return tuple(
                (row["id"], json.loads(row["payload"])) for row in self.db.execute(
                    "SELECT a.id AS id, a.payload AS payload FROM audit a "
                    "LEFT JOIN exported e ON e.audit_id = a.id WHERE e.audit_id IS NULL "
                    "ORDER BY a.rowid LIMIT ?", (int(limit),))
            )

    def mark_exported(self, audit_id):
        with self.exclusive(), self.db:
            self.db.execute("INSERT OR IGNORE INTO exported(audit_id) VALUES(?)", (audit_id,))

    def append(self, event):
        raise RuntimeError("response audit must be committed atomically through checkpoint")

    def save_command(self, response_id, command):
        raise RuntimeError("response command must be committed atomically through checkpoint")

    def commands(self):
        with self.exclusive():
            return tuple((row["id"], json.loads(row["command"])) for row in self.db.execute(
                "SELECT id,command FROM records ORDER BY id"))

    def events(self, response_id):
        with self.exclusive():
            return tuple(json.loads(row["payload"]) for row in self.db.execute(
                "SELECT payload FROM audit WHERE response_id=? ORDER BY transition_number", (response_id,)))

    def latest(self, response_id):
        with self.exclusive():
            row = self.db.execute("SELECT payload FROM audit WHERE response_id=? "
                                  "ORDER BY transition_number DESC LIMIT 1", (response_id,)).fetchone()
            return json.loads(row["payload"]) if row else None

    def close(self):
        with self._mutex:
            if self._closed:
                return
            self._closed = True
            try:
                if self.db is not None:
                    self.db.close()
            finally:
                os.close(self._lock_fd)
