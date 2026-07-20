# Phase 3D — Support Services — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the six support services — Scheduler onto `BaseService`, and SecureVault/ScanHistory/Whitelist/CloudAnalysis/Sandbox as clean modules with concrete bug fixes + real tests.

**Architecture:** Each module keeps its existing public API (the Flask UI + VirusScanner call them) while its internals are hardened. New pure cores (`due_schedules`, `RateLimiter`, `diff_snapshots`, whitelist normalization) are extracted for direct testing. Only Scheduler is a `BaseService`; the other five stay module-level utilities.

**Tech Stack:** Python 3.10+, cryptography (Fernet/PBKDF2), sqlite3, requests, psutil, pytest. Reuses `Services.framework.base_service.BaseService`, `Engine.Compiler.SentinelCompiler_v5.VirusScanner`.

## Global Constraints

- **Preserve each module's existing public API** — Flask/VirusScanner import these; renaming/removing breaks the app. SecureVault: `add`/`extract`/`delete`/`list_files`/`vault_size_bytes`. ScanHistory: `record`/`query`/`stats`/`clear`. Whitelist: `get_whitelist()` + `add_file`/`add_dir`/`add_ip`/`add_hash` + `is_whitelisted_file`/`is_whitelisted_hash`. CloudAnalysis: `get_vt_client()` + `VirusTotalClient` + `CloudVerdict`. Sandbox: `run_in_windows_sandbox`/`run_restricted` + `SandboxReport`. Scheduler: `load_schedules`/`save_schedules`/`add_schedule`/`update_last_run`.
- Only **Scheduler** subclasses `BaseService` (`name="Scheduler"`). The 5 utilities are NOT services.
- Every module fails safe: wrong vault password → clean error; missing VT key / WSB → "unavailable" (no crash); DB → WAL + thread-safe.
- No new dependencies. App boots HTTP 200; `scripts/verify_reachability.py` green (update `EXPECTED_LIVE` in Task 7). Never `git add` any `.exe`/`.ips`/PE binary. Commit after every task.
- **Each task: READ the existing target file first**, then apply the changes below and add the new pure core + tests — do NOT rewrite the whole module from scratch; preserve working logic + the public API.

---

## File Structure

- `Services/SentinelScheduler.py` — modify → `Scheduler(BaseService)` + `due_schedules`.
- `Services/SentinelSecureVault.py` — modify (atomic write + InvalidToken).
- `Services/SentinelScanHistory.py` — modify (WAL + thread-safe).
- `Services/SentinelWhitelist.py` — modify (normalization + lock).
- `Services/SentinelCloudAnalysis.py` — modify (RateLimiter + timeouts + no-key).
- `Services/SentinelSandbox.py` — modify (WSB degradation + diff_snapshots).
- `Services/SentinelService_v2.py` — modify (register Scheduler).
- `tests/services/test_scheduler.py`, `test_secure_vault.py`, `test_scan_history.py`, `test_whitelist.py`, `test_cloud_analysis.py`, `test_sandbox.py` — new.

---

### Task 1: Scheduler → BaseService

**Files:** Modify `Services/SentinelScheduler.py`; Test `tests/services/test_scheduler.py`

**Interfaces:**
- Produces: `due_schedules(schedules: list[dict], now: float) -> list[dict]`; `class Scheduler(BaseService)` (`name="Scheduler"`, `__init__(config=None, brain=None, on_scan_due=None)`). Keeps `load_schedules`/`save_schedules`/`add_schedule`/`update_last_run`.

- [ ] **Step 1: Write the tests**
```python
# tests/services/test_scheduler.py
from Services.SentinelScheduler import due_schedules, Scheduler

def test_due_schedules_fires_when_next_run_passed():
    now = 1000.0
    scheds = [
        {"id": "a", "enabled": True,  "next_run": 900.0},   # due
        {"id": "b", "enabled": True,  "next_run": 1100.0},  # future
        {"id": "c", "enabled": False, "next_run": 800.0},   # disabled
    ]
    due = due_schedules(scheds, now)
    assert [s["id"] for s in due] == ["a"]

def test_due_schedules_missing_fields_safe():
    assert due_schedules([{"id": "x"}], 1000.0) == []   # no next_run -> not due, no crash

def test_scheduler_lifecycle(fake_brain):
    s = Scheduler(brain=fake_brain, on_scan_due=lambda sid, path: None)
    s.start(); assert s.is_running() is True
    s.stop();  assert s.is_running() is False
```

- [ ] **Step 2: Run to fail.**

- [ ] **Step 3: Implement.** Add the pure fn + convert the thread to `BaseService`:
```python
def due_schedules(schedules, now):
    out = []
    for s in schedules or []:
        try:
            if s.get("enabled", True) and float(s.get("next_run", float("inf"))) <= now:
                out.append(s)
        except (TypeError, ValueError):
            continue
    return out
```
Replace the `SchedulerThread(threading.Thread)` class (and the stale QThread doc reference) with:
```python
from Services.framework.base_service import BaseService

class Scheduler(BaseService):
    name = "Scheduler"
    def __init__(self, config=None, brain=None, on_scan_due=None):
        cfg = {"check_interval": 60.0}; cfg.update(config or {})
        super().__init__(cfg, brain)
        self._on_scan_due = on_scan_due

    def _fire(self, sched):
        sid = sched.get("id"); path = sched.get("scan_path") or sched.get("path")
        if self._on_scan_due:
            self._on_scan_due(sid, path)
        update_last_run(sid, float(sched.get("interval_hours", 24)))

    def _run(self):
        self._heartbeat()
        while not self._stopping():
            try:
                for sched in due_schedules(load_schedules(), time.time()):
                    try: self._fire(sched)
                    except Exception as e: self._log(f"schedule fire error: {e}", "ERROR")
            except Exception as e:
                self._log(f"scheduler tick error: {e}", "ERROR")
            self._heartbeat()
            if not self._sleep(self.config.get("check_interval", 60.0)):
                break
```
Keep `load_schedules`/`save_schedules`/`add_schedule`/`update_last_run` unchanged.

- [ ] **Step 4: Run to green** — `.venv/Scripts/python.exe -m pytest tests/services/test_scheduler.py -q` → 3 passed. Then `tests/services/ -q` passes.

- [ ] **Step 5: Commit** — `git add Services/SentinelScheduler.py tests/services/test_scheduler.py && git commit -m "Phase 3D Task 1: Scheduler on BaseService + pure due_schedules"`

---

### Task 2: SecureVault hardening

**Files:** Modify `Services/SentinelSecureVault.py`; Test `tests/services/test_secure_vault.py`

**Interfaces:** Preserves `add(src_path, password, delete_original=True) -> str` (vault_id), `extract(vault_id, dst_dir, password) -> str`, `delete(vault_id)`, `list_files()`, `vault_size_bytes()`. Adds `class VaultError(Exception)`.

- [ ] **Step 1: Write the tests**
```python
# tests/services/test_secure_vault.py
import os
import Services.SentinelSecureVault as vault

def test_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "_VAULT_DIR", tmp_path / "vault")
    (tmp_path / "vault").mkdir()
    src = tmp_path / "secret.txt"; src.write_bytes(b"top secret data")
    vid = vault.add(str(src), "pw123", delete_original=False)
    out = vault.extract(vid, str(tmp_path / "out"), "pw123")
    assert open(out, "rb").read() == b"top secret data"

def test_wrong_password_clean_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "_VAULT_DIR", tmp_path / "vault")
    (tmp_path / "vault").mkdir()
    src = tmp_path / "s.txt"; src.write_bytes(b"x")
    vid = vault.add(str(src), "right", delete_original=False)
    import pytest
    with pytest.raises(vault.VaultError):
        vault.extract(vid, str(tmp_path / "out"), "wrong")
```
(If the vault dir constant has a different name than `_VAULT_DIR`, the implementer adapts the monkeypatch target to the real name and notes it.)

- [ ] **Step 2: Run to fail.**

- [ ] **Step 3: Implement.** In `extract`, wrap the Fernet decrypt: `except InvalidToken: raise VaultError("wrong password or corrupt vault entry")`. Add `class VaultError(Exception): pass`. In `add`, write ciphertext to `path + ".tmp"` then `os.replace(path + ".tmp", path)` (atomic); only call the original-file delete AFTER `os.replace` succeeds. Keep the Fernet/PBKDF2 crypto as-is.

- [ ] **Step 4: Run to green** — `.venv/Scripts/python.exe -m pytest tests/services/test_secure_vault.py -q` → 2 passed.

- [ ] **Step 5: Commit** — `git add Services/SentinelSecureVault.py tests/services/test_secure_vault.py && git commit -m "Phase 3D Task 2: SecureVault - InvalidToken handling + atomic writes"`

---

### Task 3: ScanHistory hardening

**Files:** Modify `Services/SentinelScanHistory.py`; Test `tests/services/test_scan_history.py`

**Interfaces:** Preserves `record(file_path, result: dict)`, `query(verdict=None, search=None, limit=100) -> list`, `stats() -> dict`, `clear()`.

- [ ] **Step 1: Write the tests**
```python
# tests/services/test_scan_history.py
import Services.SentinelScanHistory as hist

def test_record_query_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(hist, "_DB_PATH", str(tmp_path / "hist.db"))
    hist.clear()
    hist.record("C:/x.exe", {"verdict": "MALWARE", "reasons": ["y"], "details": {"sha256": "ab"}})
    rows = hist.query(verdict="MALWARE")
    assert len(rows) == 1 and rows[0]["file_path"] == "C:/x.exe"
    assert hist.query(verdict="CLEAN") == []

def test_stats_and_search(tmp_path, monkeypatch):
    monkeypatch.setattr(hist, "_DB_PATH", str(tmp_path / "h2.db"))
    hist.clear()
    hist.record("C:/evil.exe", {"verdict": "MALWARE"})
    hist.record("C:/ok.dll", {"verdict": "CLEAN"})
    assert hist.stats().get("MALWARE") == 1
    assert len(hist.query(search="evil")) == 1
```
(Adapt the `_DB_PATH` monkeypatch target to the real constant name; if `_connect()` caches a path at import, ensure the monkeypatch takes effect — the implementer makes `_connect()` read the current module-level path each call.)

- [ ] **Step 2: Run to fail.**

- [ ] **Step 3: Implement.** In `_connect()`: `conn = sqlite3.connect(_DB_PATH, check_same_thread=False, timeout=10); conn.row_factory = sqlite3.Row; conn.execute("PRAGMA journal_mode=WAL")`. Ensure `record`/`query`/`stats`/`clear` open (and close) a connection per call so they're thread-safe from the scanner + UI. Keep parameterized queries. `record` defaults missing `result` keys safely (`result.get("verdict","UNKNOWN")`, etc.).

- [ ] **Step 4: Run to green** — `.venv/Scripts/python.exe -m pytest tests/services/test_scan_history.py -q` → 2 passed.

- [ ] **Step 5: Commit** — `git add Services/SentinelScanHistory.py tests/services/test_scan_history.py && git commit -m "Phase 3D Task 3: ScanHistory - WAL + thread-safe connections"`

---

### Task 4: Whitelist hardening

**Files:** Modify `Services/SentinelWhitelist.py`; Test `tests/services/test_whitelist.py`

**Interfaces:** Preserves `get_whitelist()`, `add_file(path)->bool`, `add_dir(path)->bool`, `add_ip(ip)->bool`, `add_hash(sha256)->bool`, `is_whitelisted_file(path)->bool`, `is_whitelisted_hash(sha256)->bool`. Adds pure `norm_path(p)->str`.

- [ ] **Step 1: Write the tests**
```python
# tests/services/test_whitelist.py
from Services.SentinelWhitelist import SentinelWhitelist, norm_path

def test_norm_path_case_and_slashes():
    assert norm_path(r"C:\Users\X\file.EXE") == norm_path("c:/users/x/file.exe")

def test_file_whitelist_normalized(tmp_path, monkeypatch):
    wl = SentinelWhitelist(path=str(tmp_path / "wl.json"))
    wl.add_file(r"C:\Temp\App.exe")
    assert wl.is_whitelisted_file(r"c:\temp\app.exe") is True     # case-insensitive match
    assert wl.is_whitelisted_file(r"C:\Temp\Other.exe") is False

def test_hash_whitelist_lowercased(tmp_path):
    wl = SentinelWhitelist(path=str(tmp_path / "wl.json"))
    wl.add_hash("ABCDEF")
    assert wl.is_whitelisted_hash("abcdef") is True
```
(If `SentinelWhitelist.__init__` doesn't accept a `path` kwarg, the implementer adds one — defaulting to the current constant — so tests use a temp file.)

- [ ] **Step 2: Run to fail.**

- [ ] **Step 3: Implement.**
```python
import os
def norm_path(p):
    return os.path.normcase(os.path.abspath(p)) if p else ""
```
Store file entries as `norm_path(path)`; `is_whitelisted_file` compares `norm_path(query)`. Store hashes lowercased; `is_whitelisted_hash` lowercases the query. `is_whitelisted_file` also returns True if the file is under any whitelisted dir (prefix match on `norm_path`). Add a `threading.Lock` around the in-memory set mutations + JSON persist (atomic write via temp+replace). Accept `path=` in `__init__` (default the existing constant).

- [ ] **Step 4: Run to green** — `.venv/Scripts/python.exe -m pytest tests/services/test_whitelist.py -q` → 3 passed.

- [ ] **Step 5: Commit** — `git add Services/SentinelWhitelist.py tests/services/test_whitelist.py && git commit -m "Phase 3D Task 4: Whitelist - path/hash normalization + lock"`

---

### Task 5: CloudAnalysis hardening

**Files:** Modify `Services/SentinelCloudAnalysis.py`; Test `tests/services/test_cloud_analysis.py`

**Interfaces:** Preserves `get_vt_client()`, `VirusTotalClient`, `CloudVerdict`. Adds pure `class RateLimiter(max_calls, per_seconds)` with `allow(now: float) -> bool`.

- [ ] **Step 1: Write the tests**
```python
# tests/services/test_cloud_analysis.py
from Services.SentinelCloudAnalysis import RateLimiter, VirusTotalClient

def test_rate_limiter():
    rl = RateLimiter(max_calls=4, per_seconds=60)
    assert all(rl.allow(now=0) for _ in range(4))
    assert rl.allow(now=0) is False           # 5th within the window blocked
    assert rl.allow(now=61) is True           # window elapsed

def test_no_api_key_returns_unavailable(monkeypatch):
    c = VirusTotalClient(api_key="")          # no key
    v = c.lookup_hash("a" * 64)
    assert v is not None and getattr(v, "status", None) in ("unavailable", "no_key", "error")
```
(Adapt `lookup_hash`/`status` to the real method/field names discovered when reading the file; the binding requirement is: no key → a defined non-crashing verdict.)

- [ ] **Step 2: Run to fail.**

- [ ] **Step 3: Implement.**
```python
from collections import deque
class RateLimiter:
    def __init__(self, max_calls, per_seconds):
        self.max_calls = max_calls; self.per = per_seconds; self._calls = deque()
    def allow(self, now):
        while self._calls and self._calls[0] <= now - self.per:
            self._calls.popleft()
        if len(self._calls) >= self.max_calls:
            return False
        self._calls.append(now); return True
```
Wire the client to use `RateLimiter` (free tier 4/60s). Add `timeout=` to every `requests` call. If `api_key` is empty → `lookup` returns a `CloudVerdict(status="unavailable")` immediately (no HTTP). Wrap HTTP/JSON parsing so any error → an `"unavailable"`/`"error"` verdict, never a raised exception. Preserve the existing `CloudVerdict` fields (add a `status` field if absent).

- [ ] **Step 4: Run to green** — `.venv/Scripts/python.exe -m pytest tests/services/test_cloud_analysis.py -q` → 2 passed.

- [ ] **Step 5: Commit** — `git add Services/SentinelCloudAnalysis.py tests/services/test_cloud_analysis.py && git commit -m "Phase 3D Task 5: CloudAnalysis - pure RateLimiter, timeouts, no-key unavailable"`

---

### Task 6: Sandbox hardening

**Files:** Modify `Services/SentinelSandbox.py`; Test `tests/services/test_sandbox.py`

**Interfaces:** Preserves `run_in_windows_sandbox(file_path, timeout=60)`, `run_restricted(file_path, timeout=…)`, `SandboxReport`. Adds pure `diff_snapshots(before: dict, after: dict) -> dict` and `detonate(file_path)` (picks WSB if available, else restricted, else unavailable).

- [ ] **Step 1: Write the tests**
```python
# tests/services/test_sandbox.py
import Services.SentinelSandbox as sb

def test_diff_snapshots():
    before = {"procs": {1: "a.exe"}, "conns": {("1.2.3.4", 80)}}
    after  = {"procs": {1: "a.exe", 2: "evil.exe"}, "conns": {("1.2.3.4", 80), ("9.9.9.9", 443)}}
    d = sb.diff_snapshots(before, after)
    assert d["new_processes"] == {2: "evil.exe"}
    assert ("9.9.9.9", 443) in d["new_connections"]

def test_detonate_unavailable_is_graceful(tmp_path, monkeypatch):
    monkeypatch.setattr(sb, "_is_wsb_available", lambda: False)
    monkeypatch.setattr(sb, "run_restricted", lambda p, **k: sb.SandboxReport(status="restricted_ok"))
    rep = sb.detonate(str(tmp_path / "x.exe"))
    assert rep is not None and getattr(rep, "status", None) in ("restricted_ok", "unavailable")
```
(Adapt `SandboxReport` construction / `status` to the real dataclass fields discovered when reading the file.)

- [ ] **Step 2: Run to fail.**

- [ ] **Step 3: Implement.**
```python
def diff_snapshots(before, after):
    bp, ap = before.get("procs", {}), after.get("procs", {})
    bc, ac = before.get("conns", set()), after.get("conns", set())
    return {"new_processes": {k: v for k, v in ap.items() if k not in bp},
            "new_connections": ac - bc}

def detonate(file_path):
    try:
        if _is_wsb_available():
            return run_in_windows_sandbox(file_path)
        return run_restricted(file_path)
    except Exception as e:
        return SandboxReport(status="unavailable")
```
Ensure `SandboxReport` has a `status` field. Refactor the existing WSB/restricted process+connection diffing to call `diff_snapshots`. `run_in_windows_sandbox` already guards on `_is_wsb_available`; make any WSB failure return a `status="unavailable"` report rather than raising.

- [ ] **Step 4: Run to green** — `.venv/Scripts/python.exe -m pytest tests/services/test_sandbox.py -q` → 2 passed.

- [ ] **Step 5: Commit** — `git add Services/SentinelSandbox.py tests/services/test_sandbox.py && git commit -m "Phase 3D Task 6: Sandbox - graceful WSB degradation + pure diff_snapshots"`

---

### Task 7: Orchestration + verify

**Files:** Modify `Services/SentinelService_v2.py`, `scripts/verify_reachability.py`; Test extend `tests/services/test_orchestration.py`

- [ ] **Step 1: Read `Services/SentinelService_v2.py`** — find any existing Scheduler wrapper/import (`SchedulerThread`, `SentinelScheduler`).

- [ ] **Step 2: Wire Scheduler** — register `Scheduler(on_scan_due=<callback that runs the shared VirusScanner over the path>)` via `_ServiceHolder`. If there is no existing Scheduler wrapper, add the holder to the registry list alongside the others. Fix any stale `SchedulerThread` import. The 5 utilities are NOT registered (module-level, called on demand).

- [ ] **Step 3: Extend the orchestration test**
```python
def test_scheduler_starts_stops(fake_brain):
    from Services.SentinelScheduler import Scheduler
    s = Scheduler(brain=fake_brain, on_scan_due=lambda sid, p: None)
    s.start(); assert s.is_running() is True
    s.stop();  assert s.is_running() is False
```

- [ ] **Step 4: Verify suite + reachability + boot**

Run: `.venv/Scripts/python.exe -m pytest tests/services/ -q` → all pass.
Run: `.venv/Scripts/python.exe scripts/verify_reachability.py` — set `EXPECTED_LIVE` to the printed value, re-run → PASS.
Boot: `SENTINEL_NO_ELEVATE=1 timeout 120 .venv/Scripts/python.exe -c "import os,sys,threading,time,urllib.request,importlib.util; os.environ['SENTINEL_NO_ELEVATE']='1'; sys.argv=['x','--no-elevate']; os.chdir(r'D:/ZashironSentinel'); sys.path.insert(0,r'D:/ZashironSentinel'); spec=importlib.util.spec_from_file_location('e','SentinelUI_Flask.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); threading.Thread(target=m._start_flask,daemon=True).start(); time.sleep(12); sys.stdout.flush(); print('HTTP', urllib.request.urlopen('http://127.0.0.1:8765',timeout=5).status); sys.stdout.flush(); os._exit(0)" 2>&1 | grep -E "HTTP|Traceback|Error"` → `HTTP 200`.

- [ ] **Step 5: Commit** — `git add Services/SentinelService_v2.py scripts/verify_reachability.py tests/services/test_orchestration.py && git commit -m "Phase 3D Task 7: wire Scheduler into the service registry"`

---

## Self-Review

- **Spec coverage:** §2 Scheduler→BaseService+due_schedules → T1. §3.1 SecureVault (InvalidToken/atomic) → T2. §3.2 ScanHistory (WAL/thread) → T3. §3.3 Whitelist (normalization/lock) → T4. §3.4 CloudAnalysis (RateLimiter/timeout/no-key) → T5. §3.5 Sandbox (WSB degrade/diff_snapshots) → T6. §4 orchestration → T7. §6 testing → each task. All covered.
- **Placeholder scan:** all new pure cores (`due_schedules`/`RateLimiter`/`diff_snapshots`/`norm_path`) and ALL tests are complete code; the hardening edits are specified as exact code changes to named methods (`extract`/`add`/`_connect`/`is_whitelisted_file`/`lookup`/`detonate`). Each task instructs reading the existing file first (these are modify-existing tasks) and notes where a real name may differ from the plan's assumption, with instructions to adapt + report.
- **Type consistency:** `due_schedules(schedules,now)->list` T1↔T7; `RateLimiter(max_calls,per_seconds).allow(now)->bool` T5; `diff_snapshots(before,after)->dict{new_processes,new_connections}` T6; `norm_path(p)->str` T4. Public APIs listed in Global Constraints preserved across tasks.
- **Note:** T7 `EXPECTED_LIVE` computed at execution; several tasks adapt monkeypatch targets to real constant/field names (intentional — modify-existing tasks).
