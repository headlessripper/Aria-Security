# Main_Unit/Service/Sentinelhwid_lock.py

import os
import sys
import hashlib
import uuid
import subprocess
from pathlib import Path


def get_bios_serial():
    """Best effort BIOS serial (Windows)."""
    try:
        output = subprocess.check_output(
            ["wmic", "bios", "get", "serialnumber"],
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            text=True
        )
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        if len(lines) >= 2:
            return lines[1]
    except Exception:
        pass
    return "UNKNOWN_BIOS"


def get_machine_guid():
    """Windows MachineGuid from registry."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\\Microsoft\\Cryptography"
        )
        guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        winreg.CloseKey(key)
        return guid
    except Exception:
        return "UNKNOWN_GUID"


def get_mac():
    """MAC address as string."""
    mac = uuid.getnode()
    return f"{mac:012x}"


def compute_hwid() -> str:
    """Combine several identifiers and hash them."""
    parts = [
        get_bios_serial(),
        get_machine_guid(),
        get_mac(),
        sys.platform,
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


HWID_FILE = Path.home() / ".AriaSecurity" / "hwid.lock" 


def ensure_hwid_bound() -> bool:
    """
    Returns True only if hwid.lock exists AND matches current machine HWID.
    If hwid.lock is missing or mismatched, returns False.
    """
    if not HWID_FILE.exists():
        # No lock file → treat as invalid / copied
        return False

    hwid = compute_hwid()

    try:
        stored = HWID_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        return False

    return stored == hwid
