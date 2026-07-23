"""Passive filesystem journal — records what gets created under the install
roots so a newly-detected application can be attributed its footprint.

Always-on watchdog observers on %ProgramFiles%, %ProgramFiles(x86)%,
%ProgramData%, %LOCALAPPDATA%, %APPDATA% and %TEMP%. Every creation is appended
to a bounded in-memory ring buffer as (path, timestamp, is_dir); the buffer is
read by Services/Sense/attribution.py when an install is detected.

Degrades gracefully: if watchdog is unavailable or a root can't be watched, the
journal simply stays empty and SentinelSense falls back to install-location-only
attribution. No Flask imports.
"""
from __future__ import annotations

import os
import threading
import time
from collections import deque
from typing import List, Optional, Tuple

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    _WATCHDOG = True
except Exception:                                    # pragma: no cover
    Observer = None                                  # type: ignore
    FileSystemEventHandler = object                  # type: ignore
    _WATCHDOG = False

_MAX_ENTRIES = 50000

# Paths we never journal: our own data/quarantine and VCS noise.
_IGNORE_TOKENS = (
    os.path.normcase(str(os.path.join(os.path.expanduser("~"), ".AriaSecurity"))),
    os.path.normcase(os.sep + ".git" + os.sep),
    os.path.normcase(os.sep + "__pycache__" + os.sep),
)


def journal_roots() -> List[str]:
    raw = [
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("ProgramData"),
        os.environ.get("LOCALAPPDATA"),
        os.environ.get("APPDATA"),
        os.environ.get("TEMP"),
    ]
    seen, out = set(), []
    for r in raw:
        if not r:
            continue
        n = os.path.normcase(os.path.abspath(r))
        if n not in seen and os.path.isdir(n):
            seen.add(n)
            out.append(n)
    return out


def _ignored(path: str) -> bool:
    n = os.path.normcase(path)
    return any(tok and tok in n for tok in _IGNORE_TOKENS)


class FsJournal:
    """Bounded record of recently-created filesystem paths."""

    def __init__(self, max_entries: int = _MAX_ENTRIES):
        self._entries: deque = deque(maxlen=max_entries)
        self._lock = threading.Lock()
        self._observer = None
        self._running = False

    # -- recording -----------------------------------------------------------

    def record(self, path: str, is_dir: bool = False, ts: Optional[float] = None) -> None:
        if not path or _ignored(path):
            return
        with self._lock:
            self._entries.append((path, float(ts if ts is not None else time.time()), bool(is_dir)))

    def entries(self) -> List[Tuple[str, float, bool]]:
        with self._lock:
            return list(self._entries)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> bool:
        """Begin watching the install roots. Returns False if unavailable."""
        if self._running or not _WATCHDOG:
            return False
        journal = self

        class _Handler(FileSystemEventHandler):          # type: ignore[misc]
            def on_created(self, event):
                try:
                    journal.record(event.src_path, getattr(event, "is_directory", False))
                except Exception:
                    pass

            def on_moved(self, event):
                # a move into a watched root is effectively a creation there
                try:
                    dest = getattr(event, "dest_path", None)
                    if dest:
                        journal.record(dest, getattr(event, "is_directory", False))
                except Exception:
                    pass

        try:
            obs = Observer()
            handler = _Handler()
            watched = 0
            for root in journal_roots():
                try:
                    obs.schedule(handler, root, recursive=True)
                    watched += 1
                except Exception:
                    pass
            if not watched:
                return False
            obs.daemon = True
            obs.start()
            self._observer = obs
            self._running = True
            return True
        except Exception:
            self._observer = None
            self._running = False
            return False

    def stop(self) -> None:
        obs, self._observer, self._running = self._observer, None, False
        if obs is not None:
            try:
                obs.stop()
                obs.join(timeout=3)
            except Exception:
                pass

    @property
    def running(self) -> bool:
        return self._running


_instance: Optional[FsJournal] = None
_inst_lock = threading.Lock()


def get_journal() -> FsJournal:
    global _instance
    if _instance is None:
        with _inst_lock:
            if _instance is None:
                _instance = FsJournal()
    return _instance
