"""
SentinelScheduler — persistent cron-style scan scheduler.

Schedules are stored in ~/.AriaSecurity/schedules.json.
A background BaseService worker fires the appropriate scan at the right time.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Callable

from Services.framework.base_service import BaseService
from Config import paths as _paths

_SCHED_PATH = _paths.sub("schedules.json")
_SCHED_PATH.parent.mkdir(parents=True, exist_ok=True)


# ── Data helpers ──────────────────────────────────────────────────────────────

def load_schedules() -> list[dict]:
    try:
        if _SCHED_PATH.exists():
            return json.loads(_SCHED_PATH.read_text())
    except Exception:
        pass
    return []


def save_schedules(schedules: list[dict]):
    try:
        _SCHED_PATH.write_text(json.dumps(schedules, indent=2))
    except Exception:
        pass


def add_schedule(
    label: str,
    scan_path: str,
    interval_hours: float,
    enabled: bool = True,
) -> str:
    sid = str(uuid.uuid4())[:8]
    scheds = load_schedules()
    scheds.append({
        "id":             sid,
        "label":          label,
        "scan_path":      scan_path,
        "interval_hours": interval_hours,
        "enabled":        enabled,
        "last_run":       0.0,
        "next_run":       time.time() + interval_hours * 3600,
    })
    save_schedules(scheds)
    return sid


def remove_schedule(sid: str):
    scheds = [s for s in load_schedules() if s["id"] != sid]
    save_schedules(scheds)


def toggle_schedule(sid: str, enabled: bool):
    scheds = load_schedules()
    for s in scheds:
        if s["id"] == sid:
            s["enabled"] = enabled
            break
    save_schedules(scheds)


def update_last_run(sid: str, interval_hours: float):
    scheds = load_schedules()
    now = time.time()
    for s in scheds:
        if s["id"] == sid:
            s["last_run"] = now
            s["next_run"] = now + interval_hours * 3600
            break
    save_schedules(scheds)


# ── Pure logic ─────────────────────────────────────────────────────────────────

def due_schedules(schedules: list[dict], now: float) -> list[dict]:
    """Return the schedules that are enabled and whose next_run has passed. Pure; no I/O."""
    out = []
    for s in schedules or []:
        try:
            if s.get("enabled", True) and float(s.get("next_run", float("inf"))) <= now:
                out.append(s)
        except (TypeError, ValueError):
            continue
    return out


# ── Background runner ─────────────────────────────────────────────────────────

class Scheduler(BaseService):
    """Polls schedules and calls on_scan_due(schedule_id, scan_path) when one fires."""

    name = "Scheduler"

    def __init__(self, config: dict | None = None, brain=None,
                 on_scan_due: Callable[[str, str], None] | None = None):
        cfg = {"check_interval": 60.0}
        cfg.update(config or {})
        super().__init__(cfg, brain)
        self._on_scan_due = on_scan_due

    def _fire(self, sched: dict):
        sid = sched.get("id")
        path = sched.get("scan_path") or sched.get("path")
        if self._on_scan_due:
            self._on_scan_due(sid, path)
        update_last_run(sid, float(sched.get("interval_hours", 24)))

    def _run(self):
        self._heartbeat()
        while not self._stopping():
            try:
                for sched in due_schedules(load_schedules(), time.time()):
                    try:
                        self._fire(sched)
                    except Exception as e:
                        self._log(f"schedule fire error: {e}", "ERROR")
            except Exception as e:
                self._log(f"scheduler tick error: {e}", "ERROR")
            self._heartbeat()
            if not self._sleep(self.config.get("check_interval", 60.0)):
                break
