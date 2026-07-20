"""Memory scan core: scan running processes' executables with the shared
scanner. Decoupled from Flask/socketio/brain — progress and threat events are
delivered via optional callbacks the caller supplies."""
from __future__ import annotations
import os
import psutil


def scan_processes(scanner, on_progress=None, on_threat=None) -> list:
    results = []
    checked = 0
    procs = list(psutil.process_iter(["pid", "name", "exe"]))
    total = len(procs)
    if on_progress:
        on_progress(0, total)
    for proc in procs:
        try:
            exe = proc.info.get("exe") or ""
            if not exe or not os.path.exists(exe):
                checked += 1
                continue
            result = scanner.scan_file(exe)
            verdict = (result or {}).get("verdict", "CLEAN")
            if verdict in ("MALWARE", "SUSPICIOUS"):
                row = {
                    "pid": proc.info["pid"], "name": proc.info.get("name", "?"),
                    "exe": exe, "verdict": verdict,
                    "reasons": (result or {}).get("reasons", [])[:3],
                }
                results.append(row)
                if on_threat:
                    on_threat(row)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception:  # noqa: BLE001
            pass
        checked += 1
        if on_progress and checked % 25 == 0:
            on_progress(checked, total)
    return results
