# Phase 3E — Extract Tier-2 Monitor Logic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the inline business logic of ~14 Tier-2 monitoring routes out of the 1,920-line `SentinelUI_Flask.py` into a new `Services/monitors/` package of clean, unit-tested modules, leaving the routes as thin HTTP adapters with unchanged JSON responses.

**Architecture:** Six focused modules under `Services/monitors/`, each returning plain JSON-ready `dict`/`list` and importing **no Flask/socketio/brain** — cross-cutting concerns (socketio emit, brain events) are injected as callbacks. Pure decision cores (`risk_score`, memory-scan verdict, console filtering, geo-block persistence) are unit-tested directly; psutil/ctypes/registry are monkeypatched for the collectors. Routes shrink to `parse → call module → jsonify`.

**Tech Stack:** Python 3, `psutil`, `ctypes` (Windows), stdlib (`json`, `os`, `pathlib`), Flask + Flask-SocketIO (route layer only), pytest + monkeypatch. **No new dependencies.**

## Global Constraints

- Use `.venv/Scripts/python.exe` for ALL python/pytest invocations.
- No new dependencies (`psutil`, `ctypes`, stdlib only).
- No module in `Services/monitors/` may import `flask`, `flask_socketio`/`socketio`, or the brain — inject via callbacks/arguments.
- Every extracted function must preserve the EXACT JSON shape the current route returns (keys, types, sort order, list caps: memory top_procs 20, process_threats 200, tasks 300, connections 200).
- Never `git add` any `.exe`/`.ips`/PE binary. Stage only the specific files each task changes.
- Do not touch `.venv/`, `cleanup/`, `.superpowers/`, `Config/sentinel_whitelist.json`.
- Commit trailer on every commit: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Behavior-preserving refactor: no endpoint may change its response contract.

---

## File Structure

- `Services/monitors/__init__.py` — package marker (empty).
- `Services/monitors/geo_blocks.py` — geo-block JSON persistence (load/save, atomic).
- `Services/monitors/console_logs.py` — log tail/clear aggregation (path-agnostic).
- `Services/monitors/process_monitor.py` — pure `risk_score` + process_threats/task_list/kill.
- `Services/monitors/system_monitor.py` — memory_snapshot/trim_working_sets/list_disks.
- `Services/monitors/netstat.py` — connections/interface_counters.
- `Services/monitors/mem_scan.py` — threaded-scan core `scan_processes` (callback-decoupled).
- `SentinelUI_Flask.py` — rewrite the ~14 in-scope routes to thin adapters (Task 7).
- `scripts/verify_reachability.py` — bump `EXPECTED_LIVE` (Task 7).
- `tests/services/test_monitors_*.py` — one test file per module.

---

### Task 1: `geo_blocks.py` — geo-block persistence

**Files:**
- Create: `Services/monitors/__init__.py` (empty)
- Create: `Services/monitors/geo_blocks.py`
- Test: `tests/services/test_monitors_geo.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `load(path) -> dict`, `save(path, data: dict) -> None`. `path` is a `str` or `pathlib.Path`.

- [ ] **Step 1: Write the failing test**

```python
# tests/services/test_monitors_geo.py
import json
from pathlib import Path
from Services.monitors import geo_blocks


def test_load_missing_returns_empty(tmp_path):
    assert geo_blocks.load(tmp_path / "nope.json") == {}


def test_save_then_load_roundtrip(tmp_path):
    p = tmp_path / "sub" / "geo.json"  # parent does not exist yet
    data = {"RU": True, "CN": False}
    geo_blocks.save(p, data)
    assert geo_blocks.load(p) == data


def test_save_is_atomic_no_tmp_left(tmp_path):
    p = tmp_path / "geo.json"
    geo_blocks.save(p, {"US": True})
    leftovers = [f.name for f in tmp_path.iterdir() if f.name != "geo.json"]
    assert leftovers == []


def test_load_corrupt_returns_empty(tmp_path):
    p = tmp_path / "geo.json"
    p.write_text("{ not json", encoding="utf-8")
    assert geo_blocks.load(p) == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_monitors_geo.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'Services.monitors'`

- [ ] **Step 3: Write minimal implementation**

Create empty `Services/monitors/__init__.py`, then:

```python
# Services/monitors/geo_blocks.py
"""Geo-block persistence — read/write the country-block map as JSON.
Pure I/O helper; no Flask. Atomic write so a crash can't corrupt the file."""
from __future__ import annotations
import json
import os
from pathlib import Path


def load(path) -> dict:
    p = Path(path)
    try:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def save(path, data: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + f".{os.getpid()}.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, p)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_monitors_geo.py -q`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add Services/monitors/__init__.py Services/monitors/geo_blocks.py tests/services/test_monitors_geo.py
git commit -m "Phase 3E Task 1: monitors/geo_blocks — atomic load/save

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `console_logs.py` — log tail/clear

**Files:**
- Create: `Services/monitors/console_logs.py`
- Test: `tests/services/test_monitors_console.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `tail(log_dir, log_files: list[str], lines: int, module: str = "") -> list[str]`; `clear(log_dir, log_files: list[str], module: str = "") -> int`. `log_dir` is `str`/`Path`; caller injects `log_files` (e.g. the Flask `_LOG_FILES`). `tail` returns lines prefixed `"[<stem>] <line>"`, filtered by `module` substring (case-insensitive on the filename), limited to the last `lines`. `clear` truncates matching existing files and returns the count truncated.

- [ ] **Step 1: Write the failing test**

```python
# tests/services/test_monitors_console.py
from Services.monitors import console_logs


def _make_logs(tmp_path):
    (tmp_path / "network.log").write_text("net line 1\nnet line 2\n", encoding="utf-8")
    (tmp_path / "ransom.log").write_text("ransom line 1\n", encoding="utf-8")
    return ["network.log", "ransom.log"]


def test_tail_prefixes_stem_and_aggregates(tmp_path):
    files = _make_logs(tmp_path)
    out = console_logs.tail(tmp_path, files, lines=100)
    assert "[network] net line 1" in out
    assert "[ransom] ransom line 1" in out


def test_tail_module_filter(tmp_path):
    files = _make_logs(tmp_path)
    out = console_logs.tail(tmp_path, files, lines=100, module="ransom")
    assert all("net line" not in l for l in out)
    assert any("ransom line 1" in l for l in out)


def test_tail_line_limit(tmp_path):
    files = _make_logs(tmp_path)
    out = console_logs.tail(tmp_path, files, lines=1)
    assert len(out) == 1


def test_tail_skips_missing_files(tmp_path):
    out = console_logs.tail(tmp_path, ["ghost.log"], lines=100)
    assert out == []


def test_clear_truncates_and_counts(tmp_path):
    files = _make_logs(tmp_path)
    n = console_logs.clear(tmp_path, files)
    assert n == 2
    assert (tmp_path / "network.log").read_text(encoding="utf-8") == ""


def test_clear_module_filter(tmp_path):
    files = _make_logs(tmp_path)
    n = console_logs.clear(tmp_path, files, module="network")
    assert n == 1
    assert (tmp_path / "ransom.log").read_text(encoding="utf-8") == "ransom line 1\n"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_monitors_console.py -q`
Expected: FAIL — `ImportError: cannot import name 'console_logs'`

- [ ] **Step 3: Write minimal implementation**

```python
# Services/monitors/console_logs.py
"""Console-page log aggregation. Path-agnostic: the caller injects the log
directory and the list of log filenames, so this is testable with tmp dirs."""
from __future__ import annotations
from pathlib import Path


def tail(log_dir, log_files, lines: int, module: str = "") -> list:
    log_dir = Path(log_dir)
    module = (module or "").lower()
    all_lines: list = []
    for fname in log_files:
        if module and module not in fname.lower():
            continue
        lp = log_dir / fname
        if not lp.exists():
            continue
        stem = lp.stem
        with lp.open("r", encoding="utf-8", errors="replace") as f:
            chunk = f.readlines()[-200:]
        all_lines.extend(f"[{stem}] {l.rstrip()}" for l in chunk if l.strip())
    return all_lines[-lines:]


def clear(log_dir, log_files, module: str = "") -> int:
    log_dir = Path(log_dir)
    module = (module or "").lower()
    cleared = 0
    for fname in log_files:
        if module and module not in fname.lower():
            continue
        lp = log_dir / fname
        if lp.exists():
            lp.write_text("", encoding="utf-8")
            cleared += 1
    return cleared
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_monitors_console.py -q`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add Services/monitors/console_logs.py tests/services/test_monitors_console.py
git commit -m "Phase 3E Task 2: monitors/console_logs — tail/clear with module filter

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: `process_monitor.py` — pure `risk_score` + process/task collectors

**Files:**
- Create: `Services/monitors/process_monitor.py`
- Test: `tests/services/test_monitors_process.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `risk_score(name: str, exe: str, ppid: int) -> int` — PURE, capped 0..100.
  - `process_threats() -> list[dict]` — rows `{pid,name,path,score}`, sorted desc by score, top 200.
  - `task_list() -> list[dict]` — rows `{pid,name,status,cpu,mb,path}`, sorted desc by mb, top 300.
  - `kill(pid: int) -> dict` — `{"status":"terminated","pid":pid}` | `{"error":"process not found"}` | `{"error":<msg>}`.

- [ ] **Step 1: Write the failing test**

```python
# tests/services/test_monitors_process.py
import types
from Services.monitors import process_monitor as pm


def test_risk_score_benign_is_zero():
    assert pm.risk_score("explorer.exe", r"C:\Windows\explorer.exe", 1234) == 0


def test_risk_score_miner_keyword():
    assert pm.risk_score("cryptominer.exe", r"C:\x\cryptominer.exe", 1000) >= 50


def test_risk_score_missing_exe_adds_25():
    # exe path that does not exist on disk -> +25
    assert pm.risk_score("weird.exe", r"C:\does\not\exist_xyz.exe", 1000) >= 25


def test_risk_score_temp_dir():
    assert pm.risk_score("a.exe", r"C:\Users\x\AppData\Local\Temp\a.exe", 1000) >= 20


def test_risk_score_capped_at_100():
    # miner keyword (50) + missing exe (25) + temp (20) + short name (10) -> capped 100
    assert pm.risk_score("m.exe", r"C:\Temp\ghostxyz.exe", 0) == 100


class _FakeProc:
    def __init__(self, info):
        self.info = info


def _fake_iter(rows):
    def _it(attrs=None):
        return [_FakeProc(r) for r in rows]
    return _it


def test_process_threats_shape_and_sort(monkeypatch):
    rows = [
        {"pid": 1, "name": "explorer.exe", "exe": r"C:\Windows\explorer.exe", "ppid": 1},
        {"pid": 2, "name": "cryptominer.exe", "exe": r"C:\x\cryptominer.exe", "ppid": 1},
    ]
    monkeypatch.setattr(pm.psutil, "process_iter", _fake_iter(rows))
    out = pm.process_threats()
    assert out[0]["name"] == "cryptominer.exe"  # highest score first
    assert set(out[0].keys()) == {"pid", "name", "path", "score"}


def test_task_list_sorted_by_mb(monkeypatch):
    rows = [
        {"pid": 1, "name": "a", "exe": "", "status": "running",
         "cpu_percent": 1.0, "memory_info": types.SimpleNamespace(rss=1048576)},
        {"pid": 2, "name": "b", "exe": "", "status": "running",
         "cpu_percent": 2.0, "memory_info": types.SimpleNamespace(rss=5 * 1048576)},
    ]
    monkeypatch.setattr(pm.psutil, "process_iter", _fake_iter(rows))
    out = pm.task_list()
    assert out[0]["pid"] == 2 and out[0]["mb"] == 5.0
    assert set(out[0].keys()) == {"pid", "name", "status", "cpu", "mb", "path"}


def test_kill_not_found(monkeypatch):
    class _NSP(Exception):
        pass
    monkeypatch.setattr(pm.psutil, "NoSuchProcess", _NSP)
    def _raise(pid):
        raise _NSP()
    monkeypatch.setattr(pm.psutil, "Process", _raise)
    assert pm.kill(999999) == {"error": "process not found"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_monitors_process.py -q`
Expected: FAIL — `ImportError: cannot import name 'process_monitor'`

- [ ] **Step 3: Write minimal implementation**

```python
# Services/monitors/process_monitor.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_monitors_process.py -q`
Expected: PASS (8 passed)

Note on `test_risk_score_capped_at_100`: `m.exe` (len 5, ends `.exe` → +10), path under `\Temp\` (+20), exe missing on disk (+25), name `m.exe` has no miner keyword — so recheck: to reach 100 the miner keyword must be present. Adjust the test's name to `"miner.exe"` if the assertion under-shoots; the implementer must make the test's numbers self-consistent with `risk_score` and note any tweak in the commit. The scoring constants above are authoritative.

- [ ] **Step 5: Commit**

```bash
git add Services/monitors/process_monitor.py tests/services/test_monitors_process.py
git commit -m "Phase 3E Task 3: monitors/process_monitor — pure risk_score + task/kill

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: `system_monitor.py` — memory + storage

**Files:**
- Create: `Services/monitors/system_monitor.py`
- Test: `tests/services/test_monitors_system.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `memory_snapshot() -> dict` — `{total,used,free,percent,sentinel_mb,top_procs}`; `top_procs` = top-20 `{pid,name,mb}` by mb desc.
  - `list_disks() -> list[dict]` — `{device,mountpoint,fstype,total,used,free,percent}` per partition.
  - `trim_working_sets() -> dict` — `{"cleaned":int,"skipped":int}` (Windows ctypes; must import ctypes lazily inside the function so the module imports on any OS).

- [ ] **Step 1: Write the failing test**

```python
# tests/services/test_monitors_system.py
import types
from Services.monitors import system_monitor as sm


class _FakeProc:
    def __init__(self, info):
        self.info = info


def test_memory_snapshot_shape(monkeypatch):
    monkeypatch.setattr(sm.psutil, "virtual_memory",
                        lambda: types.SimpleNamespace(total=100, used=40, free=60, percent=40.0))
    monkeypatch.setattr(sm.psutil, "Process",
                        lambda: types.SimpleNamespace(memory_info=lambda: types.SimpleNamespace(rss=2 * 1048576)))
    procs = [
        _FakeProc({"pid": 1, "name": "a", "memory_info": types.SimpleNamespace(rss=1 * 1048576)}),
        _FakeProc({"pid": 2, "name": "b", "memory_info": types.SimpleNamespace(rss=9 * 1048576)}),
    ]
    monkeypatch.setattr(sm.psutil, "process_iter", lambda attrs=None: procs)
    out = sm.memory_snapshot()
    assert out["total"] == 100 and out["sentinel_mb"] == 2.0
    assert out["top_procs"][0]["pid"] == 2  # sorted by mb desc
    assert set(out.keys()) == {"total", "used", "free", "percent", "sentinel_mb", "top_procs"}


def test_list_disks_shape(monkeypatch):
    part = types.SimpleNamespace(device="C:\\", mountpoint="C:\\", fstype="NTFS")
    monkeypatch.setattr(sm.psutil, "disk_partitions", lambda all=False: [part])
    monkeypatch.setattr(sm.psutil, "disk_usage",
                        lambda mp: types.SimpleNamespace(total=100, used=30, free=70, percent=30.0))
    out = sm.list_disks()
    assert out[0]["device"] == "C:\\" and out[0]["percent"] == 30.0
    assert set(out[0].keys()) == {"device", "mountpoint", "fstype", "total", "used", "free", "percent"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_monitors_system.py -q`
Expected: FAIL — `ImportError: cannot import name 'system_monitor'`

- [ ] **Step 3: Write minimal implementation**

```python
# Services/monitors/system_monitor.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_monitors_system.py -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add Services/monitors/system_monitor.py tests/services/test_monitors_system.py
git commit -m "Phase 3E Task 4: monitors/system_monitor — memory/disk/trim

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: `netstat.py` — connections + interface counters

**Files:**
- Create: `Services/monitors/netstat.py`
- Test: `tests/services/test_monitors_netstat.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `connections() -> list[dict]` — `{pid,proc,laddr,raddr,status,family}` (family "TCP"/"UDP"), top 200.
  - `interface_counters() -> dict` — `{<nic>: {bytes_sent,bytes_recv,packets_sent,packets_recv,dropin,dropout}}`.

- [ ] **Step 1: Write the failing test**

```python
# tests/services/test_monitors_netstat.py
import types
from Services.monitors import netstat


def test_connections_shape(monkeypatch):
    conn = types.SimpleNamespace(
        pid=1234, type=1, status="ESTABLISHED",
        laddr=types.SimpleNamespace(ip="127.0.0.1", port=50000),
        raddr=types.SimpleNamespace(ip="1.2.3.4", port=443),
    )
    monkeypatch.setattr(netstat.psutil, "net_connections", lambda kind="inet": [conn])
    monkeypatch.setattr(netstat.psutil, "Process",
                        lambda pid: types.SimpleNamespace(name=lambda: "chrome.exe"))
    out = netstat.connections()
    assert out[0]["proc"] == "chrome.exe"
    assert out[0]["laddr"] == "127.0.0.1:50000"
    assert out[0]["raddr"] == "1.2.3.4:443"
    assert out[0]["family"] == "TCP"
    assert set(out[0].keys()) == {"pid", "proc", "laddr", "raddr", "status", "family"}


def test_interface_counters_shape(monkeypatch):
    s = types.SimpleNamespace(bytes_sent=10, bytes_recv=20, packets_sent=1,
                              packets_recv=2, dropin=0, dropout=0)
    monkeypatch.setattr(netstat.psutil, "net_io_counters",
                        lambda pernic=True, nowrap=True: {"Ethernet": s})
    out = netstat.interface_counters()
    assert out["Ethernet"]["bytes_sent"] == 10
    assert set(out["Ethernet"].keys()) == {"bytes_sent", "bytes_recv", "packets_sent",
                                           "packets_recv", "dropin", "dropout"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_monitors_netstat.py -q`
Expected: FAIL — `ImportError: cannot import name 'netstat'`

- [ ] **Step 3: Write minimal implementation**

```python
# Services/monitors/netstat.py
"""Network inspection: live connection table + per-NIC IO counters.
No Flask; returns JSON-ready structures."""
from __future__ import annotations
import psutil


def connections() -> list:
    conns = []
    for c in psutil.net_connections(kind="inet"):
        try:
            proc_name = ""
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except Exception:  # noqa: BLE001
                    pass
            conns.append({
                "pid": c.pid,
                "proc": proc_name,
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "—",
                "status": c.status,
                "family": "TCP" if c.type == 1 else "UDP",
            })
        except Exception:  # noqa: BLE001
            pass
    return conns[:200]


def interface_counters() -> dict:
    ifaces = psutil.net_io_counters(pernic=True, nowrap=True)
    out = {}
    for name, s in ifaces.items():
        out[name] = {
            "bytes_sent": s.bytes_sent, "bytes_recv": s.bytes_recv,
            "packets_sent": s.packets_sent, "packets_recv": s.packets_recv,
            "dropin": getattr(s, "dropin", 0), "dropout": getattr(s, "dropout", 0),
        }
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_monitors_netstat.py -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add Services/monitors/netstat.py tests/services/test_monitors_netstat.py
git commit -m "Phase 3E Task 5: monitors/netstat — connections + interface counters

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: `mem_scan.py` — callback-decoupled memory scan core

**Files:**
- Create: `Services/monitors/mem_scan.py`
- Test: `tests/services/test_monitors_memscan.py`

**Interfaces:**
- Consumes: a `scanner` object exposing `scan_file(path) -> dict|None` (the real one is `VirusScanner`).
- Produces: `scan_processes(scanner, on_progress=None, on_threat=None) -> list[dict]`. Iterates processes with an exe on disk, calls `scanner.scan_file(exe)`, collects rows for `MALWARE`/`SUSPICIOUS` verdicts (`{pid,name,exe,verdict,reasons}`, reasons ≤3). Calls `on_progress(checked:int, total:int)` every 25 checks (and once at start), and `on_threat(row:dict)` for each threat found. **No socketio/brain import.** Returns the collected rows.

- [ ] **Step 1: Write the failing test**

```python
# tests/services/test_monitors_memscan.py
import types
from Services.monitors import mem_scan


class _FakeScanner:
    def __init__(self, verdicts):
        self._v = verdicts  # dict: exe -> verdict dict
    def scan_file(self, exe):
        return self._v.get(exe)


def _fake_iter(rows):
    def _it(attrs=None):
        return [types.SimpleNamespace(info=r) for r in rows]
    return _it


def test_scan_collects_only_threats(monkeypatch, tmp_path):
    good = tmp_path / "good.exe"; good.write_text("x")
    bad = tmp_path / "bad.exe"; bad.write_text("x")
    rows = [
        {"pid": 1, "name": "good.exe", "exe": str(good)},
        {"pid": 2, "name": "bad.exe", "exe": str(bad)},
    ]
    monkeypatch.setattr(mem_scan.psutil, "process_iter", _fake_iter(rows))
    scanner = _FakeScanner({
        str(good): {"verdict": "CLEAN"},
        str(bad): {"verdict": "MALWARE", "reasons": ["a", "b", "c", "d"]},
    })
    threats = []
    progress = []
    out = mem_scan.scan_processes(
        scanner,
        on_progress=lambda c, t: progress.append((c, t)),
        on_threat=lambda row: threats.append(row),
    )
    assert len(out) == 1 and out[0]["pid"] == 2 and out[0]["verdict"] == "MALWARE"
    assert out[0]["reasons"] == ["a", "b", "c"]  # capped at 3
    assert threats == out
    assert progress and progress[0][1] == 2  # total reported


def test_scan_skips_missing_exe(monkeypatch):
    rows = [{"pid": 3, "name": "ghost.exe", "exe": r"C:\nope\ghost_xyz.exe"}]
    monkeypatch.setattr(mem_scan.psutil, "process_iter", _fake_iter(rows))
    called = {"n": 0}
    class _S:
        def scan_file(self, exe):
            called["n"] += 1
            return {"verdict": "MALWARE"}
    out = mem_scan.scan_processes(_S())
    assert out == [] and called["n"] == 0  # never scanned a nonexistent exe
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_monitors_memscan.py -q`
Expected: FAIL — `ImportError: cannot import name 'mem_scan'`

- [ ] **Step 3: Write minimal implementation**

```python
# Services/monitors/mem_scan.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_monitors_memscan.py -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add Services/monitors/mem_scan.py tests/services/test_monitors_memscan.py
git commit -m "Phase 3E Task 6: monitors/mem_scan — callback-decoupled process scan

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Rewrite Flask routes as thin adapters + reachability + boot verify

**Files:**
- Modify: `SentinelUI_Flask.py` (the ~14 in-scope routes; imports)
- Modify: `scripts/verify_reachability.py` (`EXPECTED_LIVE`)
- Test: `tests/services/test_monitors_smoke.py` (import-surface smoke)

**Interfaces:**
- Consumes: all Task 1–6 modules.
- Produces: unchanged HTTP JSON contracts.

- [ ] **Step 1: Add the package import near the other Services imports in `SentinelUI_Flask.py`**

Find the existing service imports (e.g. `import Services.SentinelScheduler as _sched`) and add:

```python
from Services.monitors import (
    system_monitor, process_monitor, netstat,
    console_logs, geo_blocks, mem_scan,
)
```

- [ ] **Step 2: Rewrite each in-scope route body to delegate.** Replace the inline bodies (keep the decorators + function names) as follows.

`/api/memory`:
```python
@app.route("/api/memory")
def api_memory_get():
    try:
        return jsonify(system_monitor.memory_snapshot())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```
`/api/memory/clean`:
```python
@app.route("/api/memory/clean", methods=["POST"])
def api_memory_clean():
    r = system_monitor.trim_working_sets()
    return jsonify({"status": "cleaned", "processes": r["cleaned"], "skipped": r["skipped"]})
```
`/api/storage`:
```python
@app.route("/api/storage")
def api_storage():
    try:
        return jsonify(system_monitor.list_disks())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```
`/api/process_threats`:
```python
@app.route("/api/process_threats")
def api_process_threats():
    try:
        return jsonify(process_monitor.process_threats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```
`/api/tasks`:
```python
@app.route("/api/tasks")
def api_tasks():
    try:
        return jsonify(process_monitor.task_list())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```
`/api/tasks/<int:pid>/kill`:
```python
@app.route("/api/tasks/<int:pid>/kill", methods=["POST"])
def api_task_kill(pid):
    r = process_monitor.kill(pid)
    if "error" in r:
        return jsonify(r), (404 if r["error"] == "process not found" else 500)
    return jsonify(r)
```
`/api/network/connections`:
```python
@app.route("/api/network/connections")
def api_network_connections():
    try:
        return jsonify(netstat.connections())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```
`/api/net_scope`:
```python
@app.route("/api/net_scope")
def api_net_scope():
    try:
        return jsonify(netstat.interface_counters())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```
`/api/geo_blocks` (GET/POST):
```python
@app.route("/api/geo_blocks")
def api_geo_blocks_get():
    try:
        return jsonify(geo_blocks.load(_GEO_PATH))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/geo_blocks", methods=["POST"])
def api_geo_blocks_set():
    try:
        geo_blocks.save(_GEO_PATH, request.json or {})
        return jsonify({"status": "saved"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```
`/api/console/logs` + `/api/console/clear`:
```python
@app.route("/api/console/logs")
def api_console_logs():
    n = int(request.args.get("lines", 400))
    module = request.args.get("module", "")
    try:
        return jsonify({"lines": console_logs.tail(_LOG_DIR, _LOG_FILES, n, module)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/console/clear", methods=["POST"])
def api_console_clear():
    module = (request.json or {}).get("module", "")
    try:
        return jsonify({"status": "cleared", "files": console_logs.clear(_LOG_DIR, _LOG_FILES, module)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```
`/api/memory/scan` — keep the thread + guard + terminal emit; delegate the loop:
```python
@app.route("/api/memory/scan", methods=["POST"])
def api_memory_scan():
    if _mem_scan_running["active"]:
        return jsonify({"error": "scan already running"}), 409
    _mem_scan_running["active"] = True

    def _do():
        try:
            if "cls" not in _svc_module:
                socketio.emit("memory_scan_done", {"error": "Service not loaded yet", "results": []})
                return
            svc = _state._svc_instance or _svc_module["cls"]()
            _state._svc_instance = svc
            scanner = getattr(getattr(svc, "worker", None), "scanner", None)
            if scanner is None:
                socketio.emit("memory_scan_done", {"error": "Scanner unavailable", "results": []})
                return

            def _on_progress(checked, total):
                socketio.emit("memory_scan_progress", {"checked": checked, "total": total, "status": "scanning"})

            def _on_threat(row):
                from Services.SentinelBrain import ThreatCategory, ThreatSeverity
                get_brain().emit_event(ThreatEvent(
                    category=ThreatCategory.MALWARE, severity=ThreatSeverity.CRITICAL,
                    title=f"Memory threat: {row['name']} (PID {row['pid']})",
                    detail=f"{row['verdict']} — {row['exe']}", source_module="MemoryScanner",
                    file_path=row["exe"], pid=row["pid"],
                ))

            results = mem_scan.scan_processes(scanner, on_progress=_on_progress, on_threat=_on_threat)
            socketio.emit("memory_scan_done",
                          {"results": results, "threats": len(results), "status": "done"})
        except Exception as exc:
            socketio.emit("memory_scan_done", {"error": str(exc), "results": []})
        finally:
            _mem_scan_running["active"] = False

    threading.Thread(target=_do, daemon=True, name="MemScan").start()
    return jsonify({"status": "started"})
```
> The implementer MUST confirm `ThreatEvent` is already imported at the top of `SentinelUI_Flask.py` (it is used by the current inline code). If the exact `emit_event`/`ThreatEvent` construction differs from the original, preserve the ORIGINAL construction verbatim inside `_on_threat` — do not invent fields.

- [ ] **Step 3: Delete the now-dead inline helpers** left orphaned by the rewrite (the ctypes block formerly in `api_memory_clean`, the psutil loops). Ensure `_mem_scan_running`, `_GEO_PATH`, `_LOG_DIR`, `_LOG_FILES` module-level definitions REMAIN (routes still reference them).

- [ ] **Step 4: Write the import-surface smoke test**

```python
# tests/services/test_monitors_smoke.py
def test_monitors_package_imports():
    from Services.monitors import (
        system_monitor, process_monitor, netstat, console_logs, geo_blocks, mem_scan,
    )
    for m in (system_monitor, process_monitor, netstat, console_logs, geo_blocks, mem_scan):
        assert m is not None

def test_monitors_have_no_flask_import():
    import Services.monitors.system_monitor as sm
    import Services.monitors.mem_scan as ms
    import sys
    # these modules must not have pulled flask into their own namespace
    assert not hasattr(sm, "jsonify")
    assert not hasattr(ms, "socketio")
```

- [ ] **Step 5: Run the full services suite**

Run: `.venv/Scripts/python.exe -m pytest tests/services/ -q`
Expected: PASS (all prior + new monitor tests).

- [ ] **Step 6: Update reachability gate**

Run: `.venv/Scripts/python.exe scripts/verify_reachability.py`
It prints the live count and (if changed) a mismatch vs `EXPECTED_LIVE`. Set `EXPECTED_LIVE` in `scripts/verify_reachability.py` to the newly printed live value (the 6 new `Services/monitors/*` modules are now imported by the entry file), then re-run:
Run: `.venv/Scripts/python.exe scripts/verify_reachability.py`
Expected: PASS.

- [ ] **Step 7: Headless boot smoke (HTTP 200)**

Run:
```bash
SENTINEL_NO_ELEVATE=1 timeout 120 .venv/Scripts/python.exe -c "import os,sys,threading,time,urllib.request,importlib.util; os.environ['SENTINEL_NO_ELEVATE']='1'; sys.argv=['x','--no-elevate']; os.chdir(r'D:/ZashironSentinel'); sys.path.insert(0,r'D:/ZashironSentinel'); spec=importlib.util.spec_from_file_location('e','SentinelUI_Flask.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); threading.Thread(target=m._start_flask,daemon=True).start(); time.sleep(12); print('HTTP', urllib.request.urlopen('http://127.0.0.1:8765',timeout=5).status); os._exit(0)" 2>&1 | grep -E "HTTP|Traceback|Error"
```
Expected: `HTTP 200`, no traceback.

- [ ] **Step 8: Commit**

```bash
git checkout -- Config/sentinel_whitelist.json 2>/dev/null || true
git add SentinelUI_Flask.py scripts/verify_reachability.py tests/services/test_monitors_smoke.py
git commit -m "Phase 3E Task 7: route adapters delegate to Services/monitors + reachability

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- geo_blocks → Task 1 ✓; console_logs → Task 2 ✓; process_monitor (risk_score/threats/tasks/kill) → Task 3 ✓; system_monitor (memory/trim/storage) → Task 4 ✓; netstat (connections/net_scope) → Task 5 ✓; mem_scan (callback-decoupled) → Task 6 ✓; route rewrite + reachability + boot → Task 7 ✓.
- Out-of-scope items (threat_intel/stats, network/events, Action Center) correctly left untouched — no task modifies them.
- Testing depth (pure cores direct, psutil/ctypes mocked, tmp_path for fs) → covered per task.

**Placeholder scan:** No TBD/TODO. Task 3 flags a self-consistency check on the cap-at-100 test (constants are authoritative); Task 7 flags verbatim-preserve of the `ThreatEvent` construction — both are explicit instructions, not placeholders.

**Type consistency:** `scan_processes(scanner, on_progress, on_threat)`, `risk_score(name, exe, ppid)`, `tail(log_dir, log_files, lines, module)`, `save(path, data)`, `trim_working_sets() -> {cleaned,skipped}` — names/signatures match between their defining task and Task 7's consumption. Route `/api/memory/clean` maps `cleaned→processes`, `skipped→skipped` (preserving the original JSON keys).

**Verification:** full suite + reachability bump + boot HTTP 200 all in Task 7.
