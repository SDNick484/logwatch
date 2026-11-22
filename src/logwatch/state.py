"""SQLite-backed state: file cursors, alerts, events, findings, outbox."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .events import Event, Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cursors (path TEXT PRIMARY KEY, inode INTEGER NOT NULL, offset INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alerts (key TEXT PRIMARY KEY, severity TEXT NOT NULL, title TEXT NOT NULL,
    message TEXT NOT NULL, opened REAL NOT NULL);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, source TEXT NOT NULL, kind TEXT NOT NULL, ts REAL NOT NULL);
CREATE INDEX IF NOT EXISTS events_idx ON events (source, kind, ts);
CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, ts REAL NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
    message TEXT NOT NULL, severity TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS remainder (id INTEGER PRIMARY KEY, body TEXT NOT NULL);
"""


@dataclass(frozen=True)
class Cursor:
    inode: int
    offset: int


class State:
    def __init__(self, db_path: Path):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(db_path), isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        self._db.close()

    def _many(self, sql: str, rows: list[tuple]) -> None:
        """Bulk insert in one transaction (one fsync, not one per row)."""
        if not rows:
            return
        self._db.execute("BEGIN")
        try:
            self._db.executemany(sql, rows)
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        self._db.execute("COMMIT")

    # cursors
    def get_cursor(self, path: str) -> Cursor | None:
        row = self._db.execute("SELECT inode, offset FROM cursors WHERE path=?", (path,)).fetchone()
        return Cursor(*row) if row else None

    def set_cursor(self, path: str, cursor: Cursor) -> None:
        self._db.execute(
            "INSERT INTO cursors (path, inode, offset) VALUES (?,?,?) "
            "ON CONFLICT(path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset",
            (path, cursor.inode, cursor.offset),
        )

    # alerts
    def open_alert(self, key: str, severity: str, title: str, message: str, now: datetime) -> bool:
        cur = self._db.execute(
            "INSERT OR IGNORE INTO alerts (key, severity, title, message, opened) VALUES (?,?,?,?,?)",
            (key, severity, title, message, now.timestamp()),
        )
        return cur.rowcount == 1

    def clear_alert(self, key: str, now: datetime) -> bool:
        return self._db.execute("DELETE FROM alerts WHERE key=?", (key,)).rowcount == 1

    def open_alerts(self) -> list[tuple[str, str]]:
        return list(self._db.execute("SELECT key, severity FROM alerts ORDER BY key"))

    # events (service down / respawn history)
    def record_event(self, source: str, kind: str, ts: datetime) -> None:
        self._db.execute("INSERT INTO events (source, kind, ts) VALUES (?,?,?)", (source, kind, ts.timestamp()))

    def count_events(self, source: str, kind: str, since: datetime) -> int:
        return self._db.execute(
            "SELECT COUNT(*) FROM events WHERE source=? AND kind=? AND ts>=?", (source, kind, since.timestamp())
        ).fetchone()[0]

    def prune_events(self, before: datetime) -> None:
        self._db.execute("DELETE FROM events WHERE ts<?", (before.timestamp(),))

    # findings
    def add_findings(self, findings: list[Finding], now: datetime) -> None:
        self._many(
            "INSERT INTO findings (ts, body) VALUES (?,?)",
            [(now.timestamp(), json.dumps(f.__dict__)) for f in findings],
        )

    def findings_since(self, since: datetime) -> list[Finding]:
        out = []
        for (body,) in self._db.execute("SELECT body FROM findings WHERE ts>=? ORDER BY id", (since.timestamp(),)):
            d = json.loads(body)
            d["samples"] = tuple(d["samples"])
            out.append(Finding(**d))
        return out

    def prune_findings(self, before: datetime) -> None:
        self._db.execute("DELETE FROM findings WHERE ts<?", (before.timestamp(),))

    # outbox
    def outbox_put(self, title: str, message: str, severity: str) -> int:
        return self._db.execute(
            "INSERT INTO outbox (title, message, severity) VALUES (?,?,?)", (title, message, severity)
        ).lastrowid

    def outbox_pending(self) -> list[tuple[int, str, str, str]]:
        return list(self._db.execute("SELECT id, title, message, severity FROM outbox ORDER BY id"))

    def outbox_done(self, id: int) -> None:
        self._db.execute("DELETE FROM outbox WHERE id=?", (id,))

    # small key/value store
    def get_kv(self, key: str) -> str | None:
        row = self._db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_kv(self, key: str, value: str) -> None:
        self._db.execute(
            "INSERT INTO kv (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # remainder events held between digests
    def add_remainder(self, events: list[Event]) -> None:
        self._many(
            "INSERT INTO remainder (body) VALUES (?)",
            [(json.dumps([e.source, e.file, e.text, dict(e.fields)]),) for e in events],
        )

    def take_remainder(self) -> list[Event]:
        rows = list(self._db.execute("SELECT id, body FROM remainder ORDER BY id"))
        out = []
        for _, body in rows:
            source, file, text, fields = json.loads(body)
            out.append(Event(source=source, file=file, ts=None, text=text, fields=fields))
        if rows:
            self._db.execute("DELETE FROM remainder WHERE id<=?", (rows[-1][0],))
        return out
