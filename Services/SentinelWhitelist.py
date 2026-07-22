# SentinelWhitelist.py
# Unified whitelist: trusted files/directories, IP addresses, SHA256 hashes.
# Thread-safe, JSON-backed, singleton accessor.
# Consulted by scanner (SentinelCompiler_v5) and network engine (NetProtectionNG2).

from __future__ import annotations
import json
import os
import threading
from pathlib import Path
from typing import List

# The whitelist lives with the rest of the user's Aria data, NOT in the install
# directory — it is user state, it must survive reinstalls, and keeping it under
# Config/ meant the running app kept rewriting a file inside the repo.
_ARIA_HOME = Path.home() / ".AriaSecurity"
_WHITELIST_PATH = _ARIA_HOME / "sentinel_whitelist.json"
_LEGACY_PATH = Path("Config") / "sentinel_whitelist.json"
_INSTANCE: "SentinelWhitelist | None" = None


def norm_path(p: str) -> str:
    """Pure path normalizer: absolute + case-folded, so mixed-case/slash
    variants of the same path compare equal. Empty/falsy input -> ''."""
    return os.path.normcase(os.path.abspath(p)) if p else ""


def _norm_dir(p: str) -> str:
    """Normalized dir path guaranteed to end with os.sep (empty -> '')."""
    n = norm_path(p)
    if n and not n.endswith(os.sep):
        n += os.sep
    return n


def get_whitelist() -> "SentinelWhitelist":
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = SentinelWhitelist()
    return _INSTANCE


class SentinelWhitelist:
    """
    Manages a JSON whitelist of trusted files/dirs, IP addresses, and hashes.
    All set-based checks are O(1); dir-prefix scan is O(len(dirs)) which
    is tiny in practice.
    """

    def __init__(self, path=_WHITELIST_PATH):
        self._path   = Path(path)
        self._lock   = threading.Lock()
        self._files:  set  = set()
        self._dirs:   list = []
        self._ips:    set  = set()
        self._hashes: set  = set()
        # Bumped on every mutation. Consumers that cache a copy can compare this
        # and refresh, so a whitelist edit takes effect immediately instead of
        # after a restart.
        self._version: int = 0
        self._migrate_legacy()
        self._load()

    @property
    def version(self) -> int:
        return self._version

    def _migrate_legacy(self) -> None:
        """One-time move of the old Config/sentinel_whitelist.json into ~/.AriaSecurity."""
        try:
            if self._path.exists() or not _LEGACY_PATH.exists():
                return
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(_LEGACY_PATH.read_text(encoding="utf-8"),
                                  encoding="utf-8")
            try:
                _LEGACY_PATH.unlink()
            except Exception:
                pass
        except Exception:
            pass

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        try:
            if self._path.exists():
                with self._path.open("r", encoding="utf-8") as f:
                    d = json.load(f)
                self._files  = {norm_path(x) for x in d.get("files",  [])}
                self._dirs   = [_norm_dir(x) for x in d.get("dirs",   []) if x]
                self._ips    = {x.strip() for x in d.get("ips",    [])}
                self._hashes = {x.lower().strip() for x in d.get("hashes", [])}
        except Exception:
            pass

    def _save(self) -> None:
        """Atomic write: build the JSON in a sibling temp file, then
        os.replace it over the real path so a crash mid-write never
        leaves a truncated/corrupt whitelist on disk."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self._path.with_name(self._path.name + f".{os.getpid()}.tmp")
            with tmp_path.open("w", encoding="utf-8") as f:
                json.dump({
                    "files":  sorted(self._files),
                    "dirs":   sorted(self._dirs),
                    "ips":    sorted(self._ips),
                    "hashes": sorted(self._hashes),
                }, f, indent=2)
            os.replace(tmp_path, self._path)
            self._version += 1      # signal consumers to refresh
        except Exception:
            pass

    def reload(self) -> None:
        with self._lock:
            self._load()

    # ── Check methods ─────────────────────────────────────────────────────────

    def is_whitelisted_file(self, path: str) -> bool:
        n = norm_path(path)
        with self._lock:
            if n in self._files:
                return True
            return any(n.startswith(d) for d in self._dirs)

    def is_whitelisted_ip(self, ip: str) -> bool:
        with self._lock:
            return ip.strip() in self._ips

    def is_whitelisted_hash(self, sha256: str) -> bool:
        with self._lock:
            return sha256.lower().strip() in self._hashes

    # ── Add methods ───────────────────────────────────────────────────────────

    def add_file(self, path: str) -> bool:
        n = norm_path(path)
        if not n:
            return False
        with self._lock:
            if n in self._files:
                return False
            self._files.add(n)
            self._save()
            return True

    def add_dir(self, dir_path: str) -> bool:
        n = _norm_dir(dir_path)
        if not n:
            return False
        with self._lock:
            if n in self._dirs:
                return False
            self._dirs.append(n)
            self._save()
            return True

    def add_ip(self, ip: str) -> bool:
        ip = ip.strip()
        with self._lock:
            if ip in self._ips:
                return False
            self._ips.add(ip)
            self._save()
            return True

    def add_hash(self, sha256: str) -> bool:
        h = sha256.lower().strip()
        with self._lock:
            if h in self._hashes:
                return False
            self._hashes.add(h)
            self._save()
            return True

    # ── Remove ────────────────────────────────────────────────────────────────

    def remove_entry(self, value: str) -> bool:
        """Remove from whichever list the value belongs to."""
        n = norm_path(value)
        with self._lock:
            if n in self._files:
                self._files.discard(n)
                self._save()
                return True
            for i, d in enumerate(self._dirs):
                if d == n or d == n + os.sep:
                    self._dirs.pop(i)
                    self._save()
                    return True
            ip = value.strip()
            if ip in self._ips:
                self._ips.discard(ip)
                self._save()
                return True
            h = value.lower().strip()
            if h in self._hashes:
                self._hashes.discard(h)
                self._save()
                return True
            return False

    # ── List methods ──────────────────────────────────────────────────────────

    def list_files(self) -> List[str]:
        with self._lock:
            return sorted(self._files) + sorted(self._dirs)

    def list_ips(self) -> List[str]:
        with self._lock:
            return sorted(self._ips)

    def list_hashes(self) -> List[str]:
        with self._lock:
            return sorted(self._hashes)
