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
