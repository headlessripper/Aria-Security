"""Sense_Map — the persisted per-application footprint store.

Records what each installed application put on the machine (files, dirs,
registry keys) so that, after an uninstall, the leftovers can be shown to the
user as a data tree and optionally removed. Declined residuals are NOT deleted
but stay tracked here.

Atomic JSON write so a crash can't corrupt the map. No Flask imports.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional
from Config import paths as _paths

_DEFAULT_PATH = _paths.sub("Sense_Map.json")

# Lifecycle of a tracked app.
STATUS_INSTALLED = "installed"
STATUS_UNINSTALLED = "uninstalled"      # uninstalled, residuals pending a decision
STATUS_RESIDUAL_KEPT = "residual_kept"  # user declined cleanup; still tracked
STATUS_CLEANED = "cleaned"              # residuals permanently deleted


class SenseMap:
    def __init__(self, path=None):
        self._path = Path(path) if path else _DEFAULT_PATH
        self._lock = threading.Lock()
        self._apps: Dict[str, dict] = {}
        self._load()

    # ── persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        try:
            if self._path.exists():
                data = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and isinstance(data.get("apps"), dict):
                    self._apps = data["apps"]
        except Exception:
            self._apps = {}

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_name(self._path.name + f".{os.getpid()}.tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump({"apps": self._apps}, f, indent=2)
            os.replace(tmp, self._path)
        except Exception:
            pass

    # ── mutations ────────────────────────────────────────────────────────────

    def upsert_app(self, key: str, info: dict) -> dict:
        """Create (or refresh) a tracked app entry from registry app_info."""
        with self._lock:
            rec = self._apps.get(key) or {
                "files": [], "dirs": [], "registry": [],
                "residuals": [], "residual_bytes": 0,
                "installed_at": time.time(), "uninstalled_at": None,
                "status": STATUS_INSTALLED,
            }
            rec["name"] = info.get("name") or info.get("display_name") or key
            rec["publisher"] = info.get("publisher") or ""
            rec["install_location"] = info.get("install_location") or ""
            self._apps[key] = rec
            self._save()
            return dict(rec)

    def set_footprint(self, key: str, files: List[str], dirs: List[str],
                      registry: Optional[List[str]] = None) -> None:
        with self._lock:
            rec = self._apps.get(key)
            if rec is None:
                return
            rec["files"] = sorted(set(files))
            rec["dirs"] = sorted(set(dirs))
            if registry is not None:
                rec["registry"] = sorted(set(registry))
            self._save()

    def mark_uninstalled(self, key: str) -> None:
        with self._lock:
            rec = self._apps.get(key)
            if rec is None:
                return
            rec["status"] = STATUS_UNINSTALLED
            rec["uninstalled_at"] = time.time()
            self._save()

    def set_residuals(self, key: str, residuals: List[str], total_bytes: int) -> None:
        with self._lock:
            rec = self._apps.get(key)
            if rec is None:
                return
            rec["residuals"] = sorted(set(residuals))
            rec["residual_bytes"] = int(total_bytes)
            self._save()

    def mark_kept(self, key: str) -> None:
        """User declined cleanup: leave the files on disk, keep tracking them."""
        with self._lock:
            rec = self._apps.get(key)
            if rec is None:
                return
            rec["status"] = STATUS_RESIDUAL_KEPT
            self._save()

    def mark_cleaned(self, key: str, freed_bytes: int = 0) -> None:
        with self._lock:
            rec = self._apps.get(key)
            if rec is None:
                return
            rec["status"] = STATUS_CLEANED
            rec["residuals"] = []
            rec["residual_bytes"] = 0
            rec["freed_bytes"] = int(freed_bytes)
            self._save()

    def remove(self, key: str) -> bool:
        with self._lock:
            existed = key in self._apps
            self._apps.pop(key, None)
            if existed:
                self._save()
            return existed

    # ── reads ────────────────────────────────────────────────────────────────

    def get(self, key: str) -> Optional[dict]:
        with self._lock:
            rec = self._apps.get(key)
            return dict(rec) if rec else None

    def all(self) -> Dict[str, dict]:
        with self._lock:
            return {k: dict(v) for k, v in self._apps.items()}

    def pending_residuals(self) -> Dict[str, dict]:
        """Apps that are uninstalled and still awaiting a cleanup decision."""
        with self._lock:
            return {k: dict(v) for k, v in self._apps.items()
                    if v.get("status") == STATUS_UNINSTALLED and v.get("residuals")}


_instance: Optional[SenseMap] = None
_inst_lock = threading.Lock()


def get_sense_map() -> SenseMap:
    global _instance
    if _instance is None:
        with _inst_lock:
            if _instance is None:
                _instance = SenseMap()
    return _instance
