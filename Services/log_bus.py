"""In-app log bus — the source of truth for the Console page.

The Console used to tail files in logs/, which meant anything the engine and
services printed to the terminal (SentinelCompiler_v5 and ~40 other print sites)
never reached the UI. This module keeps a bounded, thread-safe ring buffer of
lines and installs a stdout/stderr tee so ordinary `print()` calls anywhere in
the app are captured *and* still show in the terminal.

No Flask imports: the web layer subscribes via `subscribe()`.
"""
from __future__ import annotations

import re
import sys
import threading
import time
from collections import deque
from typing import Callable, List, Optional

_MAX_LINES = 2000

# Lines commonly look like "[MLScanner] score error: ..." — use the bracketed
# prefix as the source/module so the console can filter by it.
_SOURCE_RE = re.compile(r"^\s*\[([A-Za-z0-9_.\- ]{1,32})\]\s*(.*)$", re.S)


class LogBus:
    def __init__(self, max_lines: int = _MAX_LINES):
        self._lines: deque = deque(maxlen=max_lines)
        self._lock = threading.Lock()
        self._subscribers: List[Callable[[dict], None]] = []

    # -- writing -------------------------------------------------------------

    def emit(self, text: str, source: str = "app") -> Optional[dict]:
        """Record one line. Blank lines are ignored. Returns the stored record."""
        if text is None:
            return None
        text = str(text).rstrip("\r\n")
        if not text.strip():
            return None
        m = _SOURCE_RE.match(text)
        if m:
            source, text = m.group(1).strip(), m.group(2)
        rec = {"ts": time.time(), "source": source, "text": text}
        with self._lock:
            self._lines.append(rec)
            subs = list(self._subscribers)
        for cb in subs:
            try:
                cb(rec)
            except Exception:
                pass
        return rec

    # -- reading -------------------------------------------------------------

    def lines(self, n: int = 400, module: str = "") -> List[str]:
        """Formatted `[source] text` lines, newest last, optionally filtered."""
        module = (module or "").lower()
        with self._lock:
            recs = list(self._lines)
        if module:
            recs = [r for r in recs if module in r["source"].lower()]
        return [f"[{r['source']}] {r['text']}" for r in recs[-n:]]

    def records(self, n: int = 400, module: str = "") -> List[dict]:
        module = (module or "").lower()
        with self._lock:
            recs = list(self._lines)
        if module:
            recs = [r for r in recs if module in r["source"].lower()]
        return recs[-n:]

    def sources(self) -> List[str]:
        with self._lock:
            return sorted({r["source"] for r in self._lines})

    def clear(self) -> int:
        with self._lock:
            n = len(self._lines)
            self._lines.clear()
        return n

    def __len__(self) -> int:
        with self._lock:
            return len(self._lines)

    # -- live push -----------------------------------------------------------

    def subscribe(self, callback: Callable[[dict], None]) -> None:
        with self._lock:
            self._subscribers.append(callback)


_bus: Optional[LogBus] = None
_bus_lock = threading.Lock()


def get_log_bus() -> LogBus:
    global _bus
    if _bus is None:
        with _bus_lock:
            if _bus is None:
                _bus = LogBus()
    return _bus


class _Tee:
    """File-like proxy: forwards to the real stream and mirrors into the bus."""

    def __init__(self, stream, bus: LogBus, source: str):
        self._stream = stream
        self._bus = bus
        self._source = source
        self._buf = ""
        self._lock = threading.Lock()
        self._reentry = threading.local()

    def write(self, data):
        try:
            if self._stream is not None:
                self._stream.write(data)
        except Exception:
            pass
        # Guard against a subscriber (or the bus) printing and recursing.
        if getattr(self._reentry, "busy", False):
            return len(data) if data else 0
        self._reentry.busy = True
        try:
            with self._lock:
                self._buf += str(data)
                parts = self._buf.split("\n")
                self._buf = parts.pop()          # keep the partial tail
            for line in parts:
                self._bus.emit(line, self._source)
        except Exception:
            pass
        finally:
            self._reentry.busy = False
        return len(data) if data else 0

    def flush(self):
        try:
            if self._stream is not None:
                self._stream.flush()
        except Exception:
            pass

    def isatty(self):
        try:
            return bool(self._stream and self._stream.isatty())
        except Exception:
            return False

    def __getattr__(self, item):
        return getattr(self._stream, item)


_tee_installed = False


def install_stdout_tee(bus: Optional[LogBus] = None) -> bool:
    """Mirror stdout/stderr into the bus. Idempotent; returns True if installed."""
    global _tee_installed
    if _tee_installed:
        return False
    bus = bus or get_log_bus()
    try:
        sys.stdout = _Tee(sys.stdout, bus, "app")
        sys.stderr = _Tee(sys.stderr, bus, "error")
        _tee_installed = True
        return True
    except Exception:
        return False
