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
