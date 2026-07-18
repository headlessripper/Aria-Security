# SentinelWhitelist.py
# Unified whitelist: trusted files/directories, IP addresses, SHA256 hashes.
# Thread-safe, JSON-backed, singleton accessor.
# Consulted by scanner (SentinelCompiler_v5) and network engine (NetProtectionNG2).

from __future__ import annotations
import json
import threading
from pathlib import Path
from typing import List

_WHITELIST_PATH = "Config/sentinel_whitelist.json"
_LOCK = threading.Lock()
_INSTANCE: "SentinelWhitelist | None" = None


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

    def __init__(self, path: str = _WHITELIST_PATH):
        self._path   = Path(path)
        self._files:  set  = set()
        self._dirs:   list = []
        self._ips:    set  = set()
        self._hashes: set  = set()
        self._load()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _norm_path(self, p: str) -> str:
        return p.lower().replace("\\", "/").strip()

    def _load(self) -> None:
        try:
            if self._path.exists():
                with self._path.open("r", encoding="utf-8") as f:
                    d = json.load(f)
                self._files  = {self._norm_path(x) for x in d.get("files",  [])}
                self._dirs   = [self._norm_path(x) for x in d.get("dirs",   [])]
                self._ips    = {x.strip() for x in d.get("ips",    [])}
                self._hashes = {x.lower().strip() for x in d.get("hashes", [])}
        except Exception:
            pass

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("w", encoding="utf-8") as f:
                json.dump({
                    "files":  sorted(self._files),
                    "dirs":   sorted(self._dirs),
                    "ips":    sorted(self._ips),
                    "hashes": sorted(self._hashes),
                }, f, indent=2)
        except Exception:
            pass

    def reload(self) -> None:
        with _LOCK:
            self._load()

    # ── Check methods ─────────────────────────────────────────────────────────

    def is_whitelisted_file(self, path: str) -> bool:
        n = self._norm_path(path)
        with _LOCK:
            if n in self._files:
                return True
            return any(n.startswith(d) for d in self._dirs)

    def is_whitelisted_ip(self, ip: str) -> bool:
        with _LOCK:
            return ip.strip() in self._ips

    def is_whitelisted_hash(self, sha256: str) -> bool:
        with _LOCK:
            return sha256.lower().strip() in self._hashes

    # ── Add methods ───────────────────────────────────────────────────────────

    def add_file(self, path: str) -> bool:
        n = self._norm_path(path)
        with _LOCK:
            if n in self._files:
                return False
            self._files.add(n)
            self._save()
            return True

    def add_dir(self, dir_path: str) -> bool:
        n = self._norm_path(dir_path)
        if not n.endswith("/"):
            n += "/"
        with _LOCK:
            if n in self._dirs:
                return False
            self._dirs.append(n)
            self._save()
            return True

    def add_ip(self, ip: str) -> bool:
        ip = ip.strip()
        with _LOCK:
            if ip in self._ips:
                return False
            self._ips.add(ip)
            self._save()
            return True

    def add_hash(self, sha256: str) -> bool:
        h = sha256.lower().strip()
        with _LOCK:
            if h in self._hashes:
                return False
            self._hashes.add(h)
            self._save()
            return True

    # ── Remove ────────────────────────────────────────────────────────────────

    def remove_entry(self, value: str) -> bool:
        """Remove from whichever list the value belongs to."""
        n = self._norm_path(value)
        with _LOCK:
            if n in self._files:
                self._files.discard(n)
                self._save()
                return True
            for i, d in enumerate(self._dirs):
                if d == n or d == n + "/":
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
        with _LOCK:
            return sorted(self._files) + sorted(self._dirs)

    def list_ips(self) -> List[str]:
        with _LOCK:
            return sorted(self._ips)

    def list_hashes(self) -> List[str]:
        with _LOCK:
            return sorted(self._hashes)
