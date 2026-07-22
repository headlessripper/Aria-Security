"""Residual detection and *guarded* permanent deletion.

`is_safe_to_delete` is the safety core: SentinelSense will permanently delete
files, so every candidate must pass a strict allow-list check first. The rule is
deliberately conservative — a path is deletable ONLY if the app itself recorded
it, it lives under a tracked root, and it is not a root/system location.

Pure functions (no Flask, no service state) so the rails are directly testable.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Iterable, List, Tuple

# Roots an installer may legitimately write into. Deletion is confined to these.
def tracked_roots() -> List[str]:
    raw = [
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("ProgramData"),
        os.environ.get("LOCALAPPDATA"),
        os.environ.get("APPDATA"),
        os.environ.get("TEMP"),
    ]
    return [os.path.normcase(os.path.abspath(r)) for r in raw if r]


# Never delete these, even if somehow recorded in a footprint.
def _forbidden() -> List[str]:
    win = os.environ.get("SystemRoot") or r"C:\Windows"
    win = os.path.normcase(os.path.abspath(win))
    return [win, os.path.join(win, "system32"), os.path.join(win, "syswow64")]


def _norm(p: str) -> str:
    return os.path.normcase(os.path.abspath(p))


def _is_within(path: str, parent: str) -> bool:
    """True if `path` is strictly inside `parent` (not equal to it)."""
    path, parent = _norm(path), _norm(parent)
    if path == parent:
        return False
    return path.startswith(parent.rstrip(os.sep) + os.sep)


def is_safe_to_delete(path: str, footprint: Iterable[str]) -> bool:
    """The deletion gate. ALL of these must hold:

    1. `path` is one of the app's own recorded footprint entries.
    2. It contains no '..' traversal.
    3. It resolves strictly inside one of the tracked roots.
    4. It is not itself a tracked root, a drive root, or a Windows/system dir.
    """
    if not path:
        return False
    if ".." in Path(path).parts:
        return False

    target = _norm(path)

    # 1 — must be explicitly recorded by this app
    if target not in {_norm(f) for f in footprint if f}:
        return False

    # 4a — never a drive root (e.g. "C:\")
    drive, tail = os.path.splitdrive(target)
    if tail in ("", os.sep, "/"):
        return False

    # 4b — never a tracked root itself, never a Windows/system dir (or above one)
    roots = tracked_roots()
    if target in roots:
        return False
    for bad in _forbidden():
        if target == bad or _is_within(bad, target):
            return False

    # 3 — must live strictly under some tracked root
    return any(_is_within(target, r) for r in roots)


def _size_of(path: str) -> int:
    try:
        if os.path.isdir(path):
            total = 0
            for root, _dirs, files in os.walk(path):
                for f in files:
                    try:
                        total += os.path.getsize(os.path.join(root, f))
                    except OSError:
                        pass
            return total
        return os.path.getsize(path)
    except OSError:
        return 0


def find_residuals(footprint: Iterable[str]) -> Tuple[List[str], int]:
    """Footprint entries that still exist on disk, plus their total size."""
    found, total = [], 0
    for p in footprint:
        if not p:
            continue
        try:
            if os.path.exists(p):
                found.append(p)
                total += _size_of(p)
        except OSError:
            pass
    return sorted(set(found)), total


def delete_residuals(footprint: Iterable[str]) -> Tuple[List[str], List[str], int]:
    """Permanently delete the app's residual paths.

    Every path is re-checked through `is_safe_to_delete` immediately before
    removal. Returns (deleted, failed, bytes_freed). Deepest paths first so
    children go before their parents.
    """
    fp = [p for p in footprint if p]
    deleted: List[str] = []
    failed: List[str] = []
    freed = 0

    for path in sorted(set(fp), key=lambda p: len(Path(p).parts), reverse=True):
        if not os.path.exists(path):
            continue
        if not is_safe_to_delete(path, fp):
            failed.append(path)
            continue
        size = _size_of(path)
        try:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=False)
            else:
                os.remove(path)
            deleted.append(path)
            freed += size
        except Exception:
            failed.append(path)

    return deleted, failed, freed
