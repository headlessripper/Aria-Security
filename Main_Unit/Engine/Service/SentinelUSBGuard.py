"""
SentinelUSBGuard.py — block-until-scanned USB protection + smart port locker.

Behaviour requested:
  When the USB Monitor is active and a removable storage device is connected,
  the user is BLOCKED from accessing it until its directory has been scanned and
  confirmed threat-free. After a clean scan the device moves to the "USB Guard"
  pending-trust queue and waits for the user to lift the access ban by *trusting*
  the device. If a threat is found the device stays locked and the threat is
  auto-quarantined.

Enforcement (reversible, user-space):
  Access is blocked with an `icacls` DENY ACE for the well-known *Interactive*
  group SID (S-1-5-4). Processes launched from the interactive desktop (Explorer,
  user double-clicks) carry the Interactive SID and are denied; a Windows service
  running as LocalSystem does not, so the engine can still scan. Trusting the
  device removes the DENY ACE, restoring normal access. This is fully reversible
  and leaves no permanent ACL changes.

  Smart Port Locker: a global switch that disables/enables the USBSTOR driver so
  NO new USB storage device can mount at all (registry Start=4 + Disable-PnpDevice).
  Independent of the per-device block-until-scanned flow.

State machine per drive letter:
  scanning      → lock applied, scan in progress
  threat        → threats found, device stays locked, threats quarantined
  clean_pending → scan clean, waiting for the user to Trust & Unlock
  trusted       → user trusted it, lock removed, access restored

State is persisted to ~/.AriaSecurity/usb_guard_state.json so the UI can
render it. The USB Guard page polls /api/usb_guard/state.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional

_STATE_PATH = Path.home() / ".AriaSecurity" / "usb_guard_state.json"
_ALLOW_PATH = Path.home() / ".AriaSecurity" / "usb_allowlist.json"
_LOCK = threading.RLock()

# Well-known Interactive group SID — every interactively-launched process has it.
_INTERACTIVE_SID = "*S-1-5-4"

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# File types worth scanning on a removable drive.
_SCAN_EXTS = {
    ".exe", ".dll", ".sys", ".scr", ".ocx", ".com", ".pif",
    ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi",
    ".lnk", ".hta", ".inf",
}
_MAX_FILES = 5000


# ── state persistence ─────────────────────────────────────────────────────────

def _load_state() -> dict:
    with _LOCK:
        try:
            if _STATE_PATH.exists():
                return json.loads(_STATE_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

def _save_state(state: dict) -> None:
    with _LOCK:
        try:
            _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
            _STATE_PATH.write_text(json.dumps(state, indent=2, ensure_ascii=False),
                                   encoding="utf-8")
        except Exception as e:
            print(f"[USBGuard] state save failed: {e}")

def get_state() -> dict:
    """Public: current guard state for the UI."""
    return _load_state()

def _set_drive(letter: str, **fields) -> None:
    st = _load_state()
    entry = st.get(letter, {})
    entry.update(fields)
    entry["letter"] = letter
    entry["updated"] = time.time()
    st[letter] = entry
    _save_state(st)

def _remove_drive(letter: str) -> None:
    st = _load_state()
    st.pop(letter, None)
    _save_state(st)


# ── access lock (icacls Interactive deny) ─────────────────────────────────────

def _apply_access_lock(letter: str) -> bool:
    """Deny the Interactive group access to the drive root. Returns True on success."""
    root = letter.rstrip("\\") + "\\"
    try:
        r = subprocess.run(
            ["icacls", root, "/deny", f"{_INTERACTIVE_SID}:(OI)(CI)F"],
            capture_output=True, text=True, timeout=15, creationflags=_NO_WINDOW,
        )
        ok = r.returncode == 0
        if not ok:
            print(f"[USBGuard] lock icacls failed for {root}: {r.stderr or r.stdout}")
        return ok
    except Exception as e:
        print(f"[USBGuard] lock error {root}: {e}")
        return False

def _remove_access_lock(letter: str) -> bool:
    """Remove the Interactive deny ACE, restoring normal access."""
    root = letter.rstrip("\\") + "\\"
    try:
        r = subprocess.run(
            ["icacls", root, "/remove:d", _INTERACTIVE_SID],
            capture_output=True, text=True, timeout=15, creationflags=_NO_WINDOW,
        )
        ok = r.returncode == 0
        if not ok:
            print(f"[USBGuard] unlock icacls failed for {root}: {r.stderr or r.stdout}")
        return ok
    except Exception as e:
        print(f"[USBGuard] unlock error {root}: {e}")
        return False


# ── allowlist integration ─────────────────────────────────────────────────────

def _load_allowlist() -> list:
    try:
        if _ALLOW_PATH.exists():
            data = json.loads(_ALLOW_PATH.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
    except Exception:
        pass
    return []

def _save_allowlist(lst: list) -> None:
    _ALLOW_PATH.parent.mkdir(parents=True, exist_ok=True)
    _ALLOW_PATH.write_text(json.dumps(lst, indent=2, ensure_ascii=False), encoding="utf-8")

def _is_allowed(instance_id: str) -> bool:
    if not instance_id:
        return False
    for e in _load_allowlist():
        iid = e.get("id") or e.get("instance_id") or e.get("serial") or ""
        if iid and iid == instance_id:
            return True
    return False

def _add_to_allowlist(instance_id: str, label: str) -> None:
    if not instance_id:
        return
    lst = _load_allowlist()
    if any((e.get("id") == instance_id) for e in lst):
        return
    lst.append({"id": instance_id, "label": label or "USB Drive",
                "added": time.strftime("%Y-%m-%d %H:%M")})
    _save_allowlist(lst)


# ── the guard ─────────────────────────────────────────────────────────────────

class USBGuard:
    """
    Orchestrates block-until-scanned for a single inserted drive.
    `scanner` must expose scan_file(path) -> {"verdict": ...}.
    """

    def __init__(self, scanner, executor=None,
                 on_event: Optional[Callable[[str, dict], None]] = None):
        self.scanner  = scanner
        self.executor = executor
        self.on_event = on_event  # optional callback(letter, state_entry)

    # --- public entry point, called by USBDriveMonitor on insertion ---
    def handle_insertion(self, letter: str, name: str, instance_id: str = "") -> None:
        letter = letter.rstrip("\\")
        # Trusted devices skip the whole flow.
        if instance_id and _is_allowed(instance_id):
            print(f"[USBGuard] {letter} ({name}) is trusted — no lock applied")
            _set_drive(letter, status="trusted", name=name, instance_id=instance_id,
                       threats=[], locked=False)
            self._notify(letter)
            return

        locked = _apply_access_lock(letter)
        _set_drive(letter, status="scanning", name=name, instance_id=instance_id,
                   threats=[], locked=locked, scanned=0)
        self._notify(letter)
        print(f"[USBGuard] {letter} ({name}) inserted — access "
              f"{'LOCKED' if locked else 'lock-FAILED'}, scanning…")

        threading.Thread(target=self._scan, args=(letter, name, instance_id),
                         daemon=True, name=f"USBGuardScan-{letter}").start()

    # --- scan worker ---
    def _scan(self, letter: str, name: str, instance_id: str) -> None:
        root = letter + "\\"
        threats: list[str] = []
        scanned = 0
        if not os.path.isdir(root):
            _set_drive(letter, status="clean_pending", threats=[], scanned=0)
            self._notify(letter)
            return

        candidates: list[str] = []
        try:
            for dpath, _dirs, fnames in os.walk(root):
                for fn in fnames:
                    if Path(fn).suffix.lower() in _SCAN_EXTS:
                        candidates.append(os.path.join(dpath, fn))
                    if len(candidates) >= _MAX_FILES:
                        break
                if len(candidates) >= _MAX_FILES:
                    break
        except Exception as e:
            print(f"[USBGuard] walk error on {root}: {e}")

        for fpath in candidates:
            try:
                result = self.scanner.scan_file(fpath) if self.scanner else {}
                scanned += 1
                verdict = (result or {}).get("verdict", "CLEAN")
                if verdict in ("MALWARE", "SUSPICIOUS"):
                    threats.append(fpath)
                    # Auto-quarantine confirmed malware immediately.
                    if verdict == "MALWARE" and self.executor:
                        try:
                            self.executor.handle_threat(fpath)
                        except Exception as e:
                            print(f"[USBGuard] quarantine call failed: {e}")
                if scanned % 25 == 0:
                    _set_drive(letter, scanned=scanned)
            except Exception:
                pass

        if threats:
            _set_drive(letter, status="threat", threats=threats, scanned=scanned,
                       locked=True)
            print(f"[USBGuard] {letter}: {len(threats)} threat(s) — staying LOCKED")
        else:
            _set_drive(letter, status="clean_pending", threats=[], scanned=scanned,
                       locked=True)
            print(f"[USBGuard] {letter}: clean ({scanned} files) — awaiting user Trust")
        self._notify(letter)
        self._emit_brain(letter, name, threats, scanned)

    # --- user action: trust & unlock ---
    def trust_and_unlock(self, letter: str) -> dict:
        letter = letter.rstrip("\\")
        st = _load_state()
        entry = st.get(letter)
        if not entry:
            return {"error": "drive not tracked"}
        removed = _remove_access_lock(letter)
        iid = entry.get("instance_id", "")
        if iid:
            _add_to_allowlist(iid, entry.get("name", "USB Drive"))
        _set_drive(letter, status="trusted", locked=not removed)
        self._notify(letter)
        return {"status": "trusted", "unlocked": removed, "letter": letter}

    # --- user action: unlock only (no trust / allowlist) ---
    def unlock(self, letter: str) -> dict:
        letter = letter.rstrip("\\")
        removed = _remove_access_lock(letter)
        _set_drive(letter, status="trusted", locked=not removed)
        self._notify(letter)
        return {"status": "unlocked", "unlocked": removed, "letter": letter}

    # --- housekeeping when a drive is removed ---
    def handle_removal(self, letter: str) -> None:
        _remove_drive(letter.rstrip("\\"))
        self._notify(letter)

    # --- helpers ---
    def _notify(self, letter: str) -> None:
        if self.on_event:
            try:
                self.on_event(letter, _load_state().get(letter.rstrip("\\"), {}))
            except Exception:
                pass

    def _emit_brain(self, letter: str, name: str, threats: list, scanned: int) -> None:
        try:
            from Main_Unit.Engine.Service.SentinelBrain import (
                get_brain, ThreatEvent, ThreatCategory, ThreatSeverity,
            )
            if threats:
                get_brain().emit_event(ThreatEvent(
                    category=ThreatCategory.USB, severity=ThreatSeverity.CRITICAL,
                    title=f"USB threat blocked on {letter} ({name})",
                    detail=f"{len(threats)} threat(s) quarantined; drive locked until trusted",
                    source_module="USBGuard", file_path=threats[0],
                ))
            else:
                get_brain().emit_event(ThreatEvent(
                    category=ThreatCategory.USB, severity=ThreatSeverity.INFO,
                    title=f"USB clean: {letter} ({name})",
                    detail=f"Scanned {scanned} files — clean. Awaiting user trust to unlock.",
                    source_module="USBGuard", file_path=letter,
                ))
        except Exception:
            pass


# ── Smart Port Locker (global USB-storage enable/disable) ─────────────────────

def port_locker_status() -> Optional[bool]:
    """True = USB storage enabled, False = disabled (locked), None = unknown."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\USBSTOR") as k:
            val, _ = winreg.QueryValueEx(k, "Start")
            return val == 3  # 3 enabled, 4 disabled
    except Exception:
        return None

def set_port_locker(enabled: bool) -> dict:
    """Enable or DISABLE all USB mass-storage. Disabled = no new USB drive can mount."""
    reg_val = "3" if enabled else "4"
    try:
        subprocess.run(
            ["reg", "add",
             r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR",
             "/v", "Start", "/t", "REG_DWORD", "/d", reg_val, "/f"],
            capture_output=True, timeout=15, creationflags=_NO_WINDOW,
        )
        # Apply live to already-bound USBSTOR devices.
        ps = ("Get-PnpDevice -Class USB -ErrorAction SilentlyContinue | "
              "Where-Object { $_.InstanceId -like 'USBSTOR\\*' } | ")
        ps += ("Enable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue"
               if enabled else
               "Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue")
        subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, timeout=30, creationflags=_NO_WINDOW)
        return {"status": "ok", "enabled": enabled}
    except Exception as e:
        return {"error": str(e)}


# Singleton guard accessor (wired by the service with the live scanner/executor)
_GUARD: Optional[USBGuard] = None

def init_guard(scanner, executor=None, on_event=None) -> USBGuard:
    global _GUARD
    _GUARD = USBGuard(scanner, executor, on_event)
    return _GUARD

def get_guard() -> Optional[USBGuard]:
    return _GUARD
