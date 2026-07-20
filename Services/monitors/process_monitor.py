"""Process inspection: pure heuristic risk scoring + task list + kill.
No Flask; returns JSON-ready dict/list. psutil errors fail safe per-item."""
from __future__ import annotations
import os
import psutil

_MINER_KEYWORDS = ("cryptominer", "miner", "payload", "injector", "keylog")


def risk_score(name: str, exe: str, ppid: int) -> int:
    """Pure heuristic risk score, 0..100. No side effects."""
    score = 0
    n = (name or "").lower()
    e = exe or ""
    if any(x in n for x in _MINER_KEYWORDS):
        score += 50
    if ppid in (0, 4) and "system" not in n:
        score += 15
    if e and not os.path.exists(e):
        score += 25
    el = e.lower()
    if "temp" in el or "appdata\\local\\temp" in el:
        score += 20
    if n.endswith(".exe") and len(n) <= 5:
        score += 10
    return min(score, 100)


def process_threats() -> list:
    rows = []
    for proc in psutil.process_iter(["pid", "name", "exe", "ppid"]):
        try:
            info = proc.info
            rows.append({
                "pid": info["pid"],
                "name": info.get("name", "?"),
                "path": info.get("exe") or "",
                "score": risk_score(info.get("name", ""), info.get("exe") or "", info.get("ppid")),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    rows.sort(key=lambda x: x["score"], reverse=True)
    return rows[:200]


def task_list() -> list:
    rows = []
    for proc in psutil.process_iter(["pid", "name", "exe", "status", "cpu_percent", "memory_info"]):
        try:
            mi = proc.info.get("memory_info")
            rows.append({
                "pid": proc.info["pid"],
                "name": proc.info.get("name", "?"),
                "status": proc.info.get("status", "?"),
                "cpu": round(proc.info.get("cpu_percent") or 0, 1),
                "mb": round(mi.rss / 1048576, 1) if mi else 0,
                "path": proc.info.get("exe") or "",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    rows.sort(key=lambda x: x["mb"], reverse=True)
    return rows[:300]


def kill(pid: int) -> dict:
    try:
        psutil.Process(pid).terminate()
        return {"status": "terminated", "pid": pid}
    except psutil.NoSuchProcess:
        return {"error": "process not found"}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
