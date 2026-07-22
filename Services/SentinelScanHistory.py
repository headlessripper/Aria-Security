"""
SentinelScanHistory — SQLite-backed scan event log.

Every completed scan verdict is written here. The UI reads it for the
Scan History page. Thread-safe via a module-level lock.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional
from Config import paths as _paths

_DB_PATH = _paths.sub("scan_history.db")
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    """Open a fresh connection against the CURRENT module-level _DB_PATH.

    Reads the global on every call (not captured at import time) so tests
    can monkeypatch ``SentinelScanHistory._DB_PATH`` and have it take
    effect immediately. WAL mode + a busy timeout let the scanner (writer)
    and the UI (reader) hit the db concurrently from different threads.
    """
    conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _ensure_schema(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   REAL    NOT NULL,
            file_path   TEXT    NOT NULL,
            verdict     TEXT    NOT NULL,
            reasons     TEXT,
            md5         TEXT,
            sha256      TEXT,
            ml_label    TEXT,
            ml_conf     INTEGER,
            yara_hits   TEXT,
            llm_verdict TEXT,
            layer_hits  INTEGER DEFAULT 0
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ts  ON scan_events(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vrd ON scan_events(verdict)")
    conn.commit()


def record(file_path: str, result: dict):
    """Persist one scan result. Non-blocking — silently ignores errors."""
    try:
        d = result.get("details", {})
        yara = ",".join(m["rule"] for m in d.get("yara_matches", []))
        with _lock:
            conn = _connect()
            _ensure_schema(conn)
            conn.execute(
                """INSERT INTO scan_events
                   (timestamp, file_path, verdict, reasons, md5, sha256,
                    ml_label, ml_conf, yara_hits, llm_verdict, layer_hits)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    time.time(),
                    str(file_path),
                    result.get("verdict", "UNKNOWN"),
                    "; ".join(result.get("reasons", [])),
                    d.get("md5"),
                    d.get("sha256"),
                    d.get("ml_label"),
                    d.get("ml_confidence"),
                    yara or None,
                    d.get("llm_verdict"),
                    d.get("layer_hits", 0),
                ),
            )
            conn.commit()
            conn.close()
    except Exception:
        pass


def query(
    limit: int = 200,
    verdict_filter: Optional[str] = None,
    search: Optional[str] = None,
) -> list[dict]:
    """Return rows newest-first, optionally filtered by verdict or filename search."""
    try:
        with _lock:
            conn = _connect()
            _ensure_schema(conn)
            clauses, params = [], []
            if verdict_filter:
                clauses.append("verdict = ?")
                params.append(verdict_filter.upper())
            if search:
                clauses.append("file_path LIKE ?")
                params.append(f"%{search}%")
            where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
            params.append(limit)
            rows = conn.execute(
                f"SELECT * FROM scan_events {where} ORDER BY timestamp DESC LIMIT ?",
                params,
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
    except Exception:
        return []


def stats() -> dict:
    """Return aggregate counts by verdict."""
    try:
        with _lock:
            conn = _connect()
            _ensure_schema(conn)
            rows = conn.execute(
                "SELECT verdict, COUNT(*) as cnt FROM scan_events GROUP BY verdict"
            ).fetchall()
            conn.close()
            return {r["verdict"]: r["cnt"] for r in rows}
    except Exception:
        return {}


def clear():
    """Delete all records."""
    try:
        with _lock:
            conn = _connect()
            conn.execute("DELETE FROM scan_events")
            conn.commit()
            conn.close()
    except Exception:
        pass
