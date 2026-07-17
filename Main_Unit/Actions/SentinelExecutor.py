"""
SentinelExecutor.py — headless threat executor (no Qt / no GUI event loop).

Drop-in replacement for the Qt `Executioner` when running under the Flask UI
or a Windows service, where `QApplication.exec()` never runs. Exposes the same
`handle_threat(file_path)` entry point used by the scanner, ransom engine and
behavioural engine.

On a confirmed threat it will (best-effort, each step independent):
  1. Terminate any running process whose image is the threat file  (auto-kill)
  2. Move + Fernet-encrypt the file into the quarantine vault         (auto-quarantine)
  3. Write the per-item .key and metadata in the SAME layout the
     Action Center reads  (~/.AriaSecurity/.SentinelQuarantine/)
  4. Emit a ThreatEvent on SentinelBrain so the UI feed / Action Center
     reflect the action immediately

Auto-quarantine can be toggled via settings.json key "auto_quarantine"
(default True). When disabled, the file is left in place but the process is
still terminated and the event is still raised, so the user can act manually.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

# Quarantine vault — identical layout to the Qt Executioner / Action Center
QUARANTINE_ROOT = Path.home() / ".AriaSecurity" / ".SentinelQuarantine"
QUARANTINE_ROOT.mkdir(parents=True, exist_ok=True)
METADATA_FILE = QUARANTINE_ROOT / "quarantine_metadata.json"

_SETTINGS_PATH = Path.home() / ".AriaSecurity" / "settings.json"
_META_LOCK = threading.Lock()


# ── settings ──────────────────────────────────────────────────────────────────

def _auto_quarantine_enabled() -> bool:
    try:
        if _SETTINGS_PATH.exists():
            data = json.loads(_SETTINGS_PATH.read_text(encoding="utf-8"))
            return bool(data.get("auto_quarantine", True))
    except Exception:
        pass
    return True  # secure default — quarantine confirmed malware automatically


# ── metadata (compatible with Flask _quar_load_meta) ──────────────────────────

def _save_metadata(quar_dir: str, basename: str, orig_path: str) -> None:
    with _META_LOCK:
        try:
            meta = {}
            if METADATA_FILE.exists():
                meta = json.loads(METADATA_FILE.read_text(encoding="utf-8"))
            meta[quar_dir] = {"basename": basename, "orig_path": orig_path}
            METADATA_FILE.write_text(json.dumps(meta, indent=2, ensure_ascii=False),
                                     encoding="utf-8")
        except Exception as e:
            print(f"[Executor] metadata save failed: {e}")


# ── process termination ───────────────────────────────────────────────────────

def _terminate_matching_processes(file_path: str) -> int:
    """Kill any running process whose executable image == file_path. Returns count."""
    killed = 0
    try:
        import psutil
    except Exception:
        return 0
    target = os.path.normcase(os.path.abspath(file_path))
    for proc in psutil.process_iter(["pid", "exe", "name"]):
        try:
            exe = proc.info.get("exe")
            if exe and os.path.normcase(os.path.abspath(exe)) == target:
                proc.kill()
                killed += 1
                print(f"[Executor] Terminated PID {proc.info['pid']} "
                      f"({proc.info.get('name')}) — running threat image")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue
    return killed


# ── quarantine ────────────────────────────────────────────────────────────────

def _quarantine_file(file_path: str) -> Optional[Path]:
    """Move + Fernet-encrypt file into the vault. Returns the quarantine dir."""
    if not os.path.exists(file_path):
        return None
    try:
        from cryptography.fernet import Fernet
    except Exception as e:
        print(f"[Executor] cryptography unavailable — cannot quarantine: {e}")
        return None

    ts       = datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")[:-3]
    quar_dir = QUARANTINE_ROOT / f"Quarantine-Hazard_{ts}"
    quar_dir.mkdir(parents=True, exist_ok=True)
    basename = os.path.basename(file_path)
    dest     = quar_dir / basename

    try:
        shutil.move(file_path, dest)
    except Exception as e:
        print(f"[Executor] move to quarantine failed: {e}")
        try:
            quar_dir.rmdir()
        except Exception:
            pass
        return None

    try:
        key    = Fernet.generate_key()
        fernet = Fernet(key)
        data   = dest.read_bytes()
        dest.write_bytes(fernet.encrypt(data))
        (QUARANTINE_ROOT / f"{quar_dir.name}.key").write_bytes(key)
        _save_metadata(str(quar_dir), basename, file_path)
        print(f"[Executor] Quarantined & encrypted: {file_path} -> {quar_dir}")
        return quar_dir
    except Exception as e:
        print(f"[Executor] encryption/key write failed: {e}")
        return quar_dir


# ── brain event ───────────────────────────────────────────────────────────────

def _emit_event(file_path: str, action: str, killed: int) -> None:
    try:
        from Main_Unit.Engine.Service.SentinelBrain import (
            get_brain, ThreatEvent, ThreatCategory, ThreatSeverity,
        )
        detail = f"{action}"
        if killed:
            detail += f" · terminated {killed} running process(es)"
        get_brain().emit_event(ThreatEvent(
            category     = ThreatCategory.MALWARE,
            severity     = ThreatSeverity.CRITICAL,
            title        = f"Malware neutralized: {os.path.basename(file_path)}",
            detail       = detail,
            source_module= "Executor",
            file_path    = str(file_path),
        ))
    except Exception as e:
        print(f"[Executor] brain emit failed: {e}")


# ── public executor ───────────────────────────────────────────────────────────

class SentinelExecutor:
    """
    Headless threat handler. API-compatible with the Qt Executioner's
    `handle_threat(file_path) -> task_id`.
    """

    def __init__(self):
        self._counter = 0
        self._lock = threading.Lock()

    def handle_threat(self, file_path: str):
        if not file_path or not os.path.exists(file_path):
            print(f"[Executor] file not found: {file_path}")
            return None

        with self._lock:
            task_id = self._counter
            self._counter += 1

        # Run the full response off the caller's thread.
        threading.Thread(
            target=self._respond, args=(file_path, task_id),
            daemon=True, name=f"ExecutorTask-{task_id}",
        ).start()
        return task_id

    def _respond(self, file_path: str, task_id: int):
        # 1. Always terminate a running instance of the threat first.
        killed = _terminate_matching_processes(file_path)

        # 2. Quarantine (unless disabled in settings).
        if _auto_quarantine_enabled():
            qdir = _quarantine_file(file_path)
            action = "Auto-quarantined" if qdir else "Quarantine failed (left in place)"
        else:
            action = "Detected (auto-quarantine disabled)"

        # 3. Tell the brain / Action Center.
        _emit_event(file_path, action, killed)
        print(f"[Executor] Task {task_id} complete: {action} — {file_path}")

    # Compatibility no-ops for code paths that expect the Qt API surface.
    def show_action_center(self):  # pragma: no cover
        pass

    def hide_action_center(self):  # pragma: no cover
        pass


# Singleton accessor
_INSTANCE: Optional[SentinelExecutor] = None


def get_executor() -> SentinelExecutor:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = SentinelExecutor()
    return _INSTANCE
