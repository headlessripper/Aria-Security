"""
SentinelScheduler — persistent cron-style scan scheduler.

Schedules are stored in ~/.AriaSecurity/schedules.json.
A background QThread fires the appropriate scan at the right time.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Callable

import threading

_SCHED_PATH = Path.home() / ".AriaSecurity" / "schedules.json"
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


# ── Background runner ─────────────────────────────────────────────────────────

class SchedulerThread(threading.Thread):
    """Polls schedules every 60 s and calls on_scan_due(schedule_id, scan_path) when one fires."""

    def __init__(self, on_scan_due: Callable[[str, str], None] | None = None):
        super().__init__(daemon=True, name="SentinelScheduler")
        self._running = True
        self._on_due  = on_scan_due or (lambda sid, path: None)

    def stop(self):
        self._running = False

    def run(self):
        while self._running:
            try:
                now = time.time()
                for sched in load_schedules():
                    if not sched.get("enabled", True):
                        continue
                    if now >= sched.get("next_run", 0):
                        self._on_due(sched["id"], sched["scan_path"])
                        update_last_run(sched["id"], sched["interval_hours"])
            except Exception:
                pass
            # Sleep in 1-second ticks so stop() is noticed quickly
            for _ in range(60):
                if not self._running:
                    return
                time.sleep(1)
