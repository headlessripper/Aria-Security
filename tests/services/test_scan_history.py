"""
Tests for Services.SentinelScanHistory — WAL mode + thread-safe per-call
connections, and robust record() against partial result dicts.

Note: the module-level DB-path constant is genuinely named ``_DB_PATH``
(matches the brief's assumption). ``_connect()`` reads it from the module
namespace on every call rather than capturing it at import time, so
monkeypatching ``hist._DB_PATH`` before each test takes effect immediately.
The real ``query()`` signature is ``query(limit=200, verdict_filter=None,
search=None)`` — not ``query(verdict=..., search=..., limit=...)`` — so
calls below use ``verdict_filter=``.
"""
import Services.SentinelScanHistory as hist


def test_record_query_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(hist, "_DB_PATH", str(tmp_path / "hist.db"))
    hist.clear()
    hist.record("C:/x.exe", {"verdict": "MALWARE", "reasons": ["y"], "details": {"sha256": "ab"}})
    rows = hist.query(verdict_filter="MALWARE")
    assert len(rows) == 1 and rows[0]["file_path"] == "C:/x.exe"
    assert rows[0]["sha256"] == "ab"
    assert hist.query(verdict_filter="CLEAN") == []


def test_stats_and_search(tmp_path, monkeypatch):
    monkeypatch.setattr(hist, "_DB_PATH", str(tmp_path / "h2.db"))
    hist.clear()
    hist.record("C:/evil.exe", {"verdict": "MALWARE"})
    hist.record("C:/ok.dll", {"verdict": "CLEAN"})
    assert hist.stats().get("MALWARE") == 1
    assert len(hist.query(search="evil")) == 1


def test_record_tolerates_partial_result(tmp_path, monkeypatch):
    """record() must not raise when the result dict is missing keys."""
    monkeypatch.setattr(hist, "_DB_PATH", str(tmp_path / "h3.db"))
    hist.clear()
    hist.record("C:/mystery.bin", {})
    rows = hist.query()
    assert len(rows) == 1
    assert rows[0]["verdict"] == "UNKNOWN"


def test_connections_are_wal_mode(tmp_path, monkeypatch):
    """_connect() must enable WAL journal mode on every connection it opens."""
    monkeypatch.setattr(hist, "_DB_PATH", str(tmp_path / "h4.db"))
    conn = hist._connect()
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
    finally:
        conn.close()
