"""System resource inspection: memory snapshot, working-set trim, disk list.
No Flask; returns JSON-ready structures. ctypes imported lazily (Windows-only)."""
from __future__ import annotations
import psutil


def memory_snapshot() -> dict:
    vm = psutil.virtual_memory()
    proc = psutil.Process()
    top_procs = []
    for p in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            mi = p.info.get("memory_info")
            if mi:
                top_procs.append({"pid": p.info["pid"], "name": p.info.get("name", "?"),
                                  "mb": round(mi.rss / 1048576, 1)})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    top_procs.sort(key=lambda x: x["mb"], reverse=True)
    return {
        "total": vm.total, "used": vm.used, "free": vm.free, "percent": vm.percent,
        "sentinel_mb": round(proc.memory_info().rss / 1048576, 1),
        "top_procs": top_procs[:20],
    }


def recycle_bin_info() -> dict:
    """Size and item count of the Recycle Bin (all drives). Windows-only."""
    import ctypes
    from ctypes import wintypes

    class _SHQUERYRBINFO(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD),
                    ("i64Size", ctypes.c_int64),
                    ("i64NumItems", ctypes.c_int64)]

    info = _SHQUERYRBINFO()
    info.cbSize = ctypes.sizeof(_SHQUERYRBINFO)
    try:
        # None = all drives
        hr = ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
        if hr != 0:
            return {"bytes": 0, "items": 0, "available": False}
        return {"bytes": int(info.i64Size), "items": int(info.i64NumItems),
                "available": True}
    except Exception:
        return {"bytes": 0, "items": 0, "available": False}


def empty_recycle_bin(confirm: bool = False, progress: bool = False,
                      sound: bool = False) -> dict:
    """Permanently empty the Recycle Bin (all drives).

    Flags default to fully silent (no Windows confirm dialog, no progress UI,
    no sound) because the app asks for confirmation itself.
    """
    import ctypes

    SHERB_NOCONFIRMATION = 0x00000001
    SHERB_NOPROGRESSUI = 0x00000002
    SHERB_NOSOUND = 0x00000004

    flags = 0
    if not confirm:
        flags |= SHERB_NOCONFIRMATION
    if not progress:
        flags |= SHERB_NOPROGRESSUI
    if not sound:
        flags |= SHERB_NOSOUND

    before = recycle_bin_info()
    try:
        hr = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, flags)
    except Exception as e:
        return {"status": "error", "error": str(e), "freed_bytes": 0, "items": 0}

    # S_OK, or "already empty" which the shell reports as an error code.
    if hr not in (0, -2147418113):
        return {"status": "error", "error": f"SHEmptyRecycleBin failed (0x{hr & 0xFFFFFFFF:08X})",
                "freed_bytes": 0, "items": 0}
    return {"status": "emptied",
            "freed_bytes": before.get("bytes", 0),
            "items": before.get("items", 0)}


def list_disks() -> list:
    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({
                "device": part.device, "mountpoint": part.mountpoint, "fstype": part.fstype,
                "total": usage.total, "used": usage.used, "free": usage.free, "percent": usage.percent,
            })
        except (PermissionError, OSError):
            pass
    return disks


def trim_working_sets() -> dict:
    """Trim working sets of all accessible processes via SetProcessWorkingSetSize.
    Windows-only; ctypes imported lazily so this module imports on any OS."""
    import ctypes
    import ctypes.wintypes
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
    kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE
    kernel32.SetProcessWorkingSetSize.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_size_t, ctypes.c_size_t]
    kernel32.SetProcessWorkingSetSize.restype = ctypes.wintypes.BOOL
    kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    kernel32.CloseHandle.restype = ctypes.wintypes.BOOL

    PROCESS_SET_QUOTA = 0x0100
    PROCESS_QUERY_INFORMATION = 0x0400
    ACCESS = PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION
    SIZE_MAX = ctypes.c_size_t(-1).value

    cleaned = 0
    failed = 0
    kernel32.SetProcessWorkingSetSize(kernel32.GetCurrentProcess(), SIZE_MAX, SIZE_MAX)
    for proc in psutil.process_iter(["pid"]):
        try:
            pid = proc.info["pid"]
            if pid == 0:
                continue
            h = kernel32.OpenProcess(ACCESS, False, pid)
            if h:
                kernel32.SetProcessWorkingSetSize(h, SIZE_MAX, SIZE_MAX)
                kernel32.CloseHandle(h)
                cleaned += 1
            else:
                failed += 1
        except Exception:  # noqa: BLE001
            failed += 1
    return {"cleaned": cleaned, "skipped": failed}
