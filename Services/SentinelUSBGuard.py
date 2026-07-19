"""
SentinelUSBGuard.py — StorageGuard: external/removable storage detection core.

Pure detection logic for classifying newly-mounted drives as external or
internal storage. Covers external HDD/SSD (not just USB flash drives): an
external SSD enclosure on USB typically reports Windows drive_type
DRIVE_FIXED(3) but bus_type USB(7) — this must still be classified external.

The service wrapper (polling, locking, quarantine, state persistence) is
built on top of this core in a later task.
"""
from __future__ import annotations

# Windows GetDriveType() values
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5

# STORAGE_BUS_TYPE: 6=1394 (FireWire), 7=USB, 12=SD, 13=MMC — all external/removable transports
EXTERNAL_BUS_TYPES = {6, 7, 12, 13}


def is_external_storage(drive_info: dict) -> bool:
    """True if drive_info describes external/removable storage.

    drive_info: {letter, drive_type, bus_type, removable_media?}. An external
    HDD/SSD on USB reports drive_type=FIXED but bus_type=USB -> still external.
    """
    dt = drive_info.get("drive_type")
    if dt == DRIVE_REMOTE:
        return False
    if dt == DRIVE_REMOVABLE:
        return True
    if drive_info.get("removable_media"):
        return True
    return drive_info.get("bus_type") in EXTERNAL_BUS_TYPES


def diff_drives(before: set, after: set) -> tuple:
    """Return (new, removed) drive letters between two drive-letter sets."""
    return (after - before, before - after)


def is_allowlisted(drive_info: dict, allowlist: set) -> bool:
    """True if drive_info's serial or label is present in the allowlist."""
    return (drive_info.get("serial") in allowlist) or (drive_info.get("label") in allowlist)


# ---------------------------------------------------------------------------
# StorageGuard service — scan-then-warn wrapper over the detection core above.
# ---------------------------------------------------------------------------
import ctypes
import json
import os
import shutil
import subprocess
import threading
import time

from pathlib import Path

try:
    from Services.framework.base_service import BaseService
except Exception:  # keep the pure core importable in isolation
    BaseService = object  # type: ignore

try:
    from Services.SentinelBrain import ThreatCategory, ThreatSeverity
except Exception:  # pragma: no cover - defensive
    ThreatCategory = None  # type: ignore
    ThreatSeverity = None  # type: ignore

_ARIA_HOME = Path.home() / ".AriaSecurity"
_STATE_PATH = _ARIA_HOME / "usb_guard_state.json"
_QUARANTINE_DIR = _ARIA_HOME / "quarantine"
_SCAN_EXTS = {
    ".exe", ".dll", ".scr", ".com", ".sys", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".jar", ".msi", ".lnk", ".hta",
}
_GUARD_SINGLETON = None

# IOCTL_STORAGE_QUERY_PROPERTY plumbing
_IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
_StorageDeviceProperty = 0
_PropertyStandardQuery = 0


class StorageGuard(BaseService):
    """Guards ALL external/removable storage. Poll -> classify -> scan -> warn.

    On a newly-mounted external (and not-allowlisted) drive, enumerate risky
    files, scan each with the VirusScanner, and on a MALWARE verdict emit a
    threat and best-effort quarantine the file.
    """

    name = "USBMonitor"

    def __init__(self, config=None, brain=None):
        cfg = {
            "allowlist": set(),
            "block_until_scanned": False,
            "poll_interval": 3.0,
            "max_files": 5000,
        }
        cfg.update(config or {})
        super().__init__(cfg, brain)
        self._scanner = None
        self._known = set()
        self._drive_states = {}
        self._state_lock = threading.Lock()
        global _GUARD_SINGLETON
        _GUARD_SINGLETON = self

    # -- classification ------------------------------------------------------
    def _should_scan(self, drive_info):
        """True if the drive is external AND not allowlisted."""
        if not is_external_storage(drive_info):
            return False
        return not is_allowlisted(drive_info, self.config.get("allowlist", set()))

    # -- scanner -------------------------------------------------------------
    def _ensure_scanner(self):
        if self._scanner is None:
            from Engine.Compiler.SentinelCompiler_v5 import VirusScanner
            self._scanner = VirusScanner(max_workers=2)
        return self._scanner

    def _scan_files(self, files, letter):
        scanner = self._scanner or self._ensure_scanner()
        for f in files:
            if self._stopping():
                break
            try:
                r = scanner.scan_file(f)
                if r.get("verdict") == "MALWARE":
                    self.emit_threat(
                        ThreatCategory.USB, ThreatSeverity.HIGH,
                        "Malware on external drive",
                        "; ".join(r.get("reasons", [])),
                        file_path=f,
                        extra={"drive": letter},
                    )
                    self._quarantine(f)
            except Exception as e:
                self._log(f"scan error {f}: {e}", "ERROR")

    def _scan_drive(self, letter, drive_info):
        self._set_drive_state(letter, "scanning")
        try:
            files = self._enumerate(letter)
            self._scan_files(files, letter)
            self._set_drive_state(letter, "scanned")
        except Exception as e:
            self._log(f"scan_drive {letter} error: {e}", "ERROR")
            self._set_drive_state(letter, "error")

    # -- quarantine ----------------------------------------------------------
    def _quarantine(self, path):
        """Move an infected file into ~/.AriaSecurity/quarantine/ (best-effort)."""
        try:
            _QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
            dest = _QUARANTINE_DIR / (str(int(time.time() * 1000)) + "_" + os.path.basename(path))
            shutil.move(path, str(dest))
            self._log(f"quarantined {path} -> {dest}")
        except Exception as e:
            self._log(f"quarantine failed {path}: {e}", "ERROR")

    # -- enumeration ---------------------------------------------------------
    def _enumerate(self, letter):
        """Walk the drive root; keep files whose ext is in _SCAN_EXTS; cap max_files."""
        root = letter if letter.endswith("\\") else letter + "\\"
        cap = int(self.config.get("max_files", 5000))
        found = []
        try:
            for dirpath, _dirs, filenames in os.walk(root):
                for fn in filenames:
                    if os.path.splitext(fn)[1].lower() in _SCAN_EXTS:
                        found.append(os.path.join(dirpath, fn))
                        if len(found) >= cap:
                            return found
                if self._stopping():
                    break
        except Exception as e:
            self._log(f"enumerate {letter} error: {e}", "ERROR")
        return found

    # -- state persistence ---------------------------------------------------
    def _set_drive_state(self, letter, state):
        with self._state_lock:
            self._drive_states[letter] = {"state": state, "ts": time.time()}
            snapshot = dict(self._drive_states)
        try:
            _ARIA_HOME.mkdir(parents=True, exist_ok=True)
            _STATE_PATH.write_text(json.dumps(snapshot), encoding="utf-8")
        except Exception as e:
            self._log(f"state persist error: {e}", "ERROR")

    # -- drive probing -------------------------------------------------------
    def _probe_bus_type(self, letter):
        """Query bus_type + removable via IOCTL_STORAGE_QUERY_PROPERTY.

        Fiddly ctypes; fully guarded. Any failure -> (0, False) so drive_type
        classification still applies.
        """
        try:
            drive = letter.rstrip("\\").rstrip(":")
            device = "\\\\.\\" + drive + ":"
            kernel32 = ctypes.windll.kernel32
            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3
            INVALID = ctypes.c_void_p(-1).value

            handle = kernel32.CreateFileW(
                ctypes.c_wchar_p(device), 0,
                FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None,
            )
            if handle == INVALID or handle is None:
                return 0, False

            try:
                class STORAGE_PROPERTY_QUERY(ctypes.Structure):
                    _fields_ = [
                        ("PropertyId", ctypes.c_ulong),
                        ("QueryType", ctypes.c_ulong),
                        ("AdditionalParameters", ctypes.c_byte * 1),
                    ]

                query = STORAGE_PROPERTY_QUERY()
                query.PropertyId = _StorageDeviceProperty
                query.QueryType = _PropertyStandardQuery

                buf = ctypes.create_string_buffer(1024)
                returned = ctypes.c_ulong(0)
                ok = kernel32.DeviceIoControl(
                    handle, _IOCTL_STORAGE_QUERY_PROPERTY,
                    ctypes.byref(query), ctypes.sizeof(query),
                    buf, ctypes.sizeof(buf), ctypes.byref(returned), None,
                )
                if not ok:
                    return 0, False
                # STORAGE_DEVICE_DESCRIPTOR: BusType is the 5th DWORD field,
                # RemovableMedia is a BOOLEAN at offset 16.
                bus_type = ctypes.cast(
                    ctypes.byref(buf, 28), ctypes.POINTER(ctypes.c_ulong)
                ).contents.value
                removable = bool(ctypes.cast(
                    ctypes.byref(buf, 16), ctypes.POINTER(ctypes.c_byte)
                ).contents.value)
                return bus_type, removable
            finally:
                kernel32.CloseHandle(handle)
        except Exception:
            return 0, False

    def _drive_info_for(self, letter):
        info = {"letter": letter, "drive_type": 0, "bus_type": 0,
                "removable_media": False, "serial": None, "label": None}
        try:
            root = letter if letter.endswith("\\") else letter + "\\"
            info["drive_type"] = int(
                ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
            )
        except Exception:
            pass
        bus_type, removable = self._probe_bus_type(letter)
        info["bus_type"] = bus_type
        info["removable_media"] = removable
        return info

    def _current_drive_letters(self):
        try:
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        except Exception:
            return set()
        letters = set()
        for i in range(26):
            if bitmask & (1 << i):
                letters.add(chr(65 + i) + ":")
        return letters

    # -- main loop -----------------------------------------------------------
    def _run(self):
        self._known = self._current_drive_letters()
        while not self._stopping():
            current = self._current_drive_letters()
            new, _removed = diff_drives(self._known, current)
            for letter in new:
                try:
                    info = self._drive_info_for(letter)
                    if self._should_scan(info):
                        self._log(f"external drive detected: {letter} -> scanning")
                        t = threading.Thread(
                            target=self._scan_drive, args=(letter, info),
                            daemon=True, name=f"scan-{letter}")
                        t.start()
                except Exception as e:
                    self._log(f"drive probe {letter} error: {e}", "ERROR")
            self._known = current
            self._heartbeat()
            if not self._sleep(float(self.config.get("poll_interval", 3.0))):
                break


# ---------------------------------------------------------------------------
# Module-level API (imported by SentinelUI_Flask + SentinelService_v2).
# ---------------------------------------------------------------------------
def get_state() -> dict:
    """Read the persisted per-drive scan state from _STATE_PATH."""
    try:
        if _STATE_PATH.exists():
            return json.loads(_STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def get_guard():
    """Return the StorageGuard singleton, or None if not yet created."""
    return _GUARD_SINGLETON


def init_guard(brain=None) -> "StorageGuard":
    """Create (or return) the StorageGuard singleton — called by SentinelService_v2."""
    global _GUARD_SINGLETON
    if _GUARD_SINGLETON is None:
        _GUARD_SINGLETON = StorageGuard(brain=brain)
    return _GUARD_SINGLETON


def set_port_locker(enabled: bool) -> bool:
    """Toggle USB mass-storage port locking (guarded, requires admin).

    Sets the USBSTOR service Start value (4=disabled, 3=demand-start) and
    disables/enables matching PnP devices. Missing admin / any failure -> log
    + return False.
    """
    start_val = 4 if enabled else 3
    try:
        r = subprocess.run(
            ["reg", "add",
             r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
             "/v", "Start", "/t", "REG_DWORD", "/d", str(start_val), "/f"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            print(f"[USBMonitor] ERROR: set_port_locker reg failed: {r.stderr.strip()}")
            return False
        ps_cmd = "Disable-PnpDevice" if enabled else "Enable-PnpDevice"
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"Get-PnpDevice -Class USB -PresentOnly | Where-Object {{ $_.InstanceId -like 'USBSTOR*' }} "
             f"| {ps_cmd} -Confirm:$false -ErrorAction SilentlyContinue"],
            capture_output=True, text=True, timeout=30,
        )
        return True
    except Exception as e:
        print(f"[USBMonitor] ERROR: set_port_locker failed (admin required?): {e}")
        return False


def port_locker_status() -> bool:
    """True if USB mass storage is currently locked (USBSTOR Start == 4)."""
    try:
        r = subprocess.run(
            ["reg", "query",
             r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
             "/v", "Start"],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return False
        for tok in r.stdout.split():
            if tok.lower().startswith("0x"):
                return int(tok, 16) == 4
    except Exception as e:
        print(f"[USBMonitor] ERROR: port_locker_status failed: {e}")
    return False


def trust_device(serial: str) -> None:
    """Add a device serial to the running guard's allowlist."""
    guard = _GUARD_SINGLETON
    if guard is None:
        return
    try:
        allow = guard.config.setdefault("allowlist", set())
        if isinstance(allow, set):
            allow.add(serial)
        else:
            guard.config["allowlist"] = set(allow) | {serial}
    except Exception as e:
        print(f"[USBMonitor] ERROR: trust_device failed: {e}")


# Back-compat alias — Flask does `from ... import USBGuard`.
USBGuard = StorageGuard
