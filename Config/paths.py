"""Single source of truth for where Aria keeps its state.

Why this exists: as a Windows service Aria runs as LocalSystem, whose home is
C:\\Windows\\System32\\config\\systemprofile. Every module that hardcoded
`Path.home() / ".AriaSecurity"` would therefore write somewhere the signed-in
user can't see — the whitelist, vault, scan history and quarantine would all
silently appear empty the moment the backend became a service.

Resolution order:
  1. ARIA_DATA_DIR             — explicit override (set by the service/installer)
  2. %ProgramData%\\AriaSecurity — when running as SYSTEM (i.e. as the service),
                                 machine-wide and reachable by both the service
                                 and the user
  3. ~/.AriaSecurity           — normal desktop run

Never raises: falls back to ~/.AriaSecurity if anything goes wrong.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

_LEGACY_DIR = Path.home() / ".AriaSecurity"


def _running_as_system() -> bool:
    """True when the process is LocalSystem (i.e. running as the service)."""
    try:
        import ctypes
        if os.name != "nt":
            return False
        # LocalSystem's profile lives under the Windows dir; cheap and reliable
        # without needing pywin32 in every consumer.
        home = str(Path.home()).lower()
        windir = (os.environ.get("SystemRoot") or r"C:\Windows").lower()
        if home.startswith(windir):
            return True
        return bool(os.environ.get("ARIA_RUN_AS_SERVICE"))
    except Exception:
        return False


def program_data_dir() -> Path:
    base = os.environ.get("ProgramData") or r"C:\ProgramData"
    return Path(base) / "AriaSecurity"


def data_dir() -> Path:
    """The directory Aria stores state in. Created on demand."""
    try:
        override = os.environ.get("ARIA_DATA_DIR")
        if override:
            d = Path(override)
        elif _running_as_system():
            d = program_data_dir()
        else:
            d = _LEGACY_DIR
    except Exception:
        d = _LEGACY_DIR
    try:
        d.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return d


def sub(*parts) -> Path:
    """Path inside the data dir, e.g. sub('SecureVault')."""
    return data_dir().joinpath(*parts)


def migrate_legacy_data(dest: Path | None = None) -> list:
    """Copy a desktop ~/.AriaSecurity into the machine-wide dir, once.

    Only copies entries that don't already exist at the destination, so it can
    be run repeatedly and never clobbers newer service-side state. Returns the
    names it copied.
    """
    dest = Path(dest) if dest else data_dir()
    moved = []
    try:
        if not _LEGACY_DIR.exists() or _LEGACY_DIR.resolve() == dest.resolve():
            return moved
        dest.mkdir(parents=True, exist_ok=True)
        for item in _LEGACY_DIR.iterdir():
            target = dest / item.name
            if target.exists():
                continue
            try:
                if item.is_dir():
                    shutil.copytree(item, target)
                else:
                    shutil.copy2(item, target)
                moved.append(item.name)
            except Exception:
                pass
    except Exception:
        pass
    return moved
