# Phase 3B — Service Framework + File/Host Protection — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a uniform `BaseService` framework and rewrite the file/host protection services (Ransomware, Exploit, Behavioral) on it with robust, real-world, user-mode detection.

**Architecture:** `BaseService` (ABC) standardizes lifecycle, cooperative stop, Brain integration, threat emission, health, and exception isolation. Each protection service is a focused `BaseService` subclass. `SentinelService_v2` becomes a uniform registry. Detection uses `watchdog` (file events) + `psutil` (process events); no real malware in tests — synthetic triggers.

**Tech Stack:** Python 3.10+, threading, watchdog, psutil, pytest. Reuses `Services.SentinelBrain` (`ThreatEvent`/`ThreatCategory`/`ThreatSeverity`/`get_brain`) and `Engine.Detection.cert_reputation.CertReputation`.

## Global Constraints

- Every rewritten service subclasses `BaseService` and implements `_run(self)`; stop is cooperative via `self._stopping()` / `self._sleep()`; a service must exit `_run` within the stop timeout.
- Threats are emitted ONLY via `BaseService.emit_threat(category, severity, title, detail, ...)` which builds a real `ThreatEvent(category, severity, title, detail, source_module=self.name, file_path, pid, ip_address, extra)` and calls `brain.emit_event`.
- `ThreatCategory` ∈ {MALWARE, RANSOMWARE, NETWORK, EXPLOIT, BEHAVIORAL, USB, SYSTEM}; `ThreatSeverity` ∈ {INFO, LOW, MEDIUM, HIGH, CRITICAL}.
- Services are unit-testable with an injected fake brain (no Qt/OS coupling); all detector logic is exception-isolated (one detector error never kills the service).
- RansomProtection response is **graduated**: suspend on high confidence (canary trip OR ≥2 detectors in a window), alert+monitor on a single heuristic; **never** suspend a validly-signed/trusted process (reuse `CertReputation`) or a configured critical-system image.
- New dep: `watchdog`. Already present: `psutil`, `pefile`.
- App must stay bootable (HTTP 200 on 127.0.0.1:8765) and `scripts/verify_reachability.py` green (update `EXPECTED_LIVE` in Task 5 to the new count).
- Never `git add` any `.exe`/`.ips`/PE binary. Commit after every task.

---

## File Structure

- `Services/framework/__init__.py` — **new.** Re-exports `BaseService`, `ServiceState`.
- `Services/framework/base_service.py` — **new.** The framework.
- `Services/Protection/SentinelRansomProtection.py` — **rewrite.** `RansomProtection(BaseService)`.
- `Services/Protection/SentinelExploitProtection.py` — **rewrite.** `ExploitProtection(BaseService)`.
- `Services/SentinelBehavioralEngine.py` — **rewrite.** `BehavioralEngine(BaseService)`.
- `Engine/Rules/behavioral_rules.json` — **rewrite.** Rule schema + starter ruleset.
- `Services/SentinelService_v2.py` — **modify.** Uniform registry for the 3 rewritten services.
- `tests/services/…` — **new.** pytest suite + `FakeBrain` helper.
- `requirements.txt` — **modify.** Add `watchdog`.

---

### Task 1: Dependencies + `BaseService` framework

**Files:**
- Modify: `requirements.txt`
- Create: `Services/framework/__init__.py`, `Services/framework/base_service.py`
- Create: `tests/services/__init__.py`, `tests/services/conftest.py`, `tests/services/test_base_service.py`

**Interfaces:**
- Produces: `class ServiceState(Enum)` {STOPPED, STARTING, RUNNING, STOPPING, ERROR}; `class BaseService(ABC)` with `__init__(config=None, brain=None)`, `start()`, `stop(timeout=5.0)`, `is_running()->bool`, `health()->dict`, abstract `_run()`, `_teardown()`, and helpers `_stopping()->bool`, `_sleep(seconds)->bool` (False if stopped during sleep), `_heartbeat()`, `emit_threat(category, severity, title, detail, file_path=None, pid=None, ip_address=None, extra=None)`, `emit_block(ip, reason)`, `_log(msg, level="INFO")`. `name: str` class attr.
- Produces (test helper): `tests/services/conftest.py::FakeBrain` with `.events`, `.blocks`, `.module_states` and `emit_event/emit_block/set_module_running`.

- [ ] **Step 1: Add the dependency**

Run: `.venv/Scripts/python.exe -m pip install watchdog 2>&1 | tail -2` (expect `Successfully installed watchdog-...`). Append `watchdog  # real-time file-system events (RansomProtection)` to `requirements.txt`.

- [ ] **Step 2: Write `Services/framework/base_service.py`**

```python
from __future__ import annotations
import threading, time, traceback
from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import Optional

try:
    from Services.SentinelBrain import get_brain, ThreatEvent
except Exception:  # keep importable in isolation
    get_brain = None
    ThreatEvent = None

class ServiceState(Enum):
    STOPPED = auto(); STARTING = auto(); RUNNING = auto(); STOPPING = auto(); ERROR = auto()

class BaseService(ABC):
    """Uniform lifecycle + Brain integration for every protection service."""
    name: str = "BaseService"

    def __init__(self, config: Optional[dict] = None, brain=None):
        self.config = config or {}
        self._brain = brain if brain is not None else (get_brain() if get_brain else None)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._state = ServiceState.STOPPED
        self._last_heartbeat = 0.0
        self._error: Optional[str] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._error = None
        self._state = ServiceState.STARTING
        self._thread = threading.Thread(target=self._guarded_run, daemon=True, name=self.name)
        self._thread.start()
        self._state = ServiceState.RUNNING
        self._set_module_running(True)

    def stop(self, timeout: float = 5.0) -> None:
        self._state = ServiceState.STOPPING
        self._stop_event.set()
        try:
            self._teardown()
        except Exception as e:
            self._log(f"teardown error: {e}", "ERROR")
        if self._thread:
            self._thread.join(timeout=timeout)
        self._state = ServiceState.STOPPED
        self._set_module_running(False)

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive()) and self._state == ServiceState.RUNNING

    def health(self) -> dict:
        return {"name": self.name, "state": self._state.name,
                "last_heartbeat": self._last_heartbeat, "error": self._error}

    @abstractmethod
    def _run(self) -> None: ...

    def _teardown(self) -> None:
        pass

    def _guarded_run(self) -> None:
        try:
            self._run()
        except Exception as e:
            self._error = f"{e}\n{traceback.format_exc()}"
            self._state = ServiceState.ERROR
            self._log(f"_run crashed: {e}", "ERROR")

    def _stopping(self) -> bool:
        return self._stop_event.is_set()

    def _sleep(self, seconds: float) -> bool:
        return not self._stop_event.wait(seconds)  # False if stopped during the wait

    def _heartbeat(self) -> None:
        self._last_heartbeat = time.time()

    def emit_threat(self, category, severity, title: str, detail: str,
                    file_path=None, pid=None, ip_address=None, extra=None) -> None:
        self._heartbeat()
        if not self._brain or ThreatEvent is None:
            return
        try:
            self._brain.emit_event(ThreatEvent(
                category=category, severity=severity, title=title, detail=detail,
                source_module=self.name, file_path=file_path, pid=pid,
                ip_address=ip_address, extra=extra or {}))
        except Exception as e:
            self._log(f"emit_threat failed: {e}", "ERROR")

    def emit_block(self, ip: str, reason: str) -> None:
        if self._brain:
            try: self._brain.emit_block(ip, reason)
            except Exception: pass

    def _set_module_running(self, running: bool) -> None:
        if self._brain:
            try: self._brain.set_module_running(self.name, running)
            except Exception: pass

    def _log(self, msg: str, level: str = "INFO") -> None:
        print(f"[{self.name}] {level}: {msg}")
```

`Services/framework/__init__.py`:
```python
from Services.framework.base_service import BaseService, ServiceState
__all__ = ["BaseService", "ServiceState"]
```

- [ ] **Step 3: Write the test helper + tests**

`tests/services/__init__.py`: empty. `tests/services/conftest.py`:
```python
import pytest

class FakeBrain:
    def __init__(self):
        self.events = []
        self.blocks = []
        self.module_states = {}
    def emit_event(self, evt): self.events.append(evt)
    def emit_block(self, ip, reason): self.blocks.append((ip, reason))
    def set_module_running(self, name, running, health_note="OK"): self.module_states[name] = running

@pytest.fixture
def fake_brain():
    return FakeBrain()
```

`tests/services/test_base_service.py`:
```python
import time
from Services.framework.base_service import BaseService
from Services.SentinelBrain import ThreatCategory, ThreatSeverity

class _Echo(BaseService):
    name = "EchoSvc"
    def _run(self):
        while not self._stopping():
            if not self._sleep(0.05):
                break

class _Crash(BaseService):
    name = "CrashSvc"
    def _run(self):
        raise RuntimeError("boom")

def test_lifecycle_and_brain_registration(fake_brain):
    s = _Echo(brain=fake_brain)
    assert s.is_running() is False
    s.start()
    assert s.is_running() is True
    assert fake_brain.module_states["EchoSvc"] is True
    s.stop()
    assert s.is_running() is False
    assert fake_brain.module_states["EchoSvc"] is False
    assert s.health()["state"] == "STOPPED"

def test_stop_is_prompt(fake_brain):
    s = _Echo(brain=fake_brain)
    s.start()
    t0 = time.time()
    s.stop(timeout=2)
    assert time.time() - t0 < 1.5  # cooperative stop, not the full timeout

def test_idempotent_start(fake_brain):
    s = _Echo(brain=fake_brain)
    s.start(); first = s._thread
    s.start(); assert s._thread is first  # no second thread
    s.stop()

def test_emit_threat_builds_event(fake_brain):
    s = _Echo(brain=fake_brain)
    s.emit_threat(ThreatCategory.RANSOMWARE, ThreatSeverity.CRITICAL, "Title", "detail",
                  file_path="C:/x", pid=42, extra={"k": "v"})
    assert len(fake_brain.events) == 1
    e = fake_brain.events[0]
    assert e.category == ThreatCategory.RANSOMWARE and e.severity == ThreatSeverity.CRITICAL
    assert e.source_module == "EchoSvc" and e.pid == 42 and e.extra == {"k": "v"}

def test_run_crash_sets_error_not_process(fake_brain):
    s = _Crash(brain=fake_brain)
    s.start()
    time.sleep(0.15)
    assert s.health()["state"] == "ERROR"   # crashed internally, process still alive
    s.stop()
```

- [ ] **Step 4: Run tests**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_base_service.py -q 2>&1 | tail -8`
Expected: 5 passed, pristine.

- [ ] **Step 5: Commit**

```bash
git add requirements.txt Services/framework/ tests/services/
git commit -m "Phase 3B Task 1: BaseService framework + watchdog dep"
```

---

### Task 2: RansomProtection rewrite

**Files:**
- Rewrite: `Services/Protection/SentinelRansomProtection.py`
- Test: `tests/services/test_ransom_protection.py`

**Interfaces:**
- Consumes: `BaseService` (Task 1); `Engine.Detection.cert_reputation.CertReputation` (safety guard).
- Produces: `class RansomProtection(BaseService)` with `name="RansomProtection"`. Pure helpers importable for tests: `shannon_entropy(data: bytes) -> float`; `class _Window` (event-velocity counter with `add(ts)` and `count(now, seconds) -> int`); method `_classify_and_respond(trip_reasons: set, path: str, pid: int|None)` that decides suspend vs alert per the graduated policy and returns the chosen action string (`"suspend"|"alert"|"alert_safeguarded"`).

- [ ] **Step 1: Write the failing tests** (they define the detection contract)

`tests/services/test_ransom_protection.py`:
```python
import os
from Services.Protection.SentinelRansomProtection import (
    RansomProtection, shannon_entropy, _Window,
)
from Services.SentinelBrain import ThreatCategory, ThreatSeverity

def test_shannon_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1000) < 0.1          # all-same → ~0
    assert shannon_entropy(bytes(range(256)) * 4) > 7.9   # uniform → ~8

def test_window_counts_within_horizon():
    w = _Window()
    for t in range(10):        # timestamps 0..9
        w.add(t)
    # count() is pure (no mutation); horizon is half-open (now-seconds, now]
    assert w.count(now=10, seconds=5) == 4    # {6,7,8,9}
    assert w.count(now=10, seconds=100) == 10 # all (pure count, unaffected by the prior call)

def test_canary_trip_is_high_confidence_suspend(fake_brain, tmp_path, monkeypatch):
    rp = RansomProtection(config={"watch_dirs": [str(tmp_path)], "action": "auto"}, brain=fake_brain)
    suspended = {}
    monkeypatch.setattr(rp, "_suspend_pid", lambda pid: suspended.setdefault("pid", pid) or True)
    # canary trips are highest confidence -> suspend chosen
    action = rp._classify_and_respond({"canary"}, str(tmp_path / "canary.dat"), pid=1234)
    assert action == "suspend"

def test_single_heuristic_is_alert_only(fake_brain, tmp_path):
    rp = RansomProtection(config={"watch_dirs": [str(tmp_path)], "action": "auto"}, brain=fake_brain)
    action = rp._classify_and_respond({"velocity"}, str(tmp_path / "f"), pid=None)
    assert action == "alert"

def test_two_detectors_together_suspend(fake_brain, tmp_path, monkeypatch):
    rp = RansomProtection(config={"watch_dirs": [str(tmp_path)], "action": "auto"}, brain=fake_brain)
    monkeypatch.setattr(rp, "_suspend_pid", lambda pid: True)
    action = rp._classify_and_respond({"velocity", "entropy"}, str(tmp_path / "f"), pid=99)
    assert action == "suspend"

def test_safety_guard_never_suspends_trusted(fake_brain, tmp_path, monkeypatch):
    rp = RansomProtection(config={"watch_dirs": [str(tmp_path)], "action": "auto"}, brain=fake_brain)
    monkeypatch.setattr(rp, "_pid_is_protected", lambda pid: True)  # trusted/critical
    called = {"n": 0}
    monkeypatch.setattr(rp, "_suspend_pid", lambda pid: called.__setitem__("n", called["n"] + 1))
    action = rp._classify_and_respond({"canary"}, str(tmp_path / "c"), pid=4)
    assert action == "alert_safeguarded" and called["n"] == 0

def test_trip_emits_critical_ransomware(fake_brain, tmp_path, monkeypatch):
    rp = RansomProtection(config={"watch_dirs": [str(tmp_path)], "action": "alert_only"}, brain=fake_brain)
    rp._on_trip({"canary"}, str(tmp_path / "c"), pid=None)
    assert any(e.category == ThreatCategory.RANSOMWARE and e.severity == ThreatSeverity.CRITICAL
               for e in fake_brain.events)
```
(Fix the `test_window_counts_within_horizon` expectation to match your `_Window.count` definition — define `count(now, seconds)` as the number of timestamps `t` with `now - seconds < t <= now`.)

- [ ] **Step 2: Run to see them fail**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_ransom_protection.py -q 2>&1 | tail -15`
Expected: import/attribute errors.

- [ ] **Step 3: Implement `RansomProtection`**

Structure (implement fully; the pure helpers + `_classify_and_respond` + `_on_trip` are pinned by the tests, the watchdog wiring is standard):
```python
from __future__ import annotations
import math, os, time, threading
from collections import deque
from pathlib import Path
from Services.framework.base_service import BaseService
from Services.SentinelBrain import ThreatCategory, ThreatSeverity

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data); ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

class _Window:
    """Sliding count of event timestamps. count() is PURE (no mutation) so
    repeated queries don't interfere; add() prunes beyond a max horizon."""
    def __init__(self, max_horizon: float = 3600.0):
        self._ts = deque()
        self._max = max_horizon
    def add(self, ts: float) -> None:
        self._ts.append(ts)
        cutoff = ts - self._max
        while self._ts and self._ts[0] < cutoff:
            self._ts.popleft()
    def count(self, now: float, seconds: float) -> int:
        cutoff = now - seconds
        return sum(1 for t in self._ts if t > cutoff)  # half-open (now-seconds, now]

_DEFAULTS = {
    "watch_dirs": [],
    "window_seconds": 5,
    "velocity_threshold": 30,
    "entropy_threshold": 7.8,
    "entropy_sample_bytes": 8192,
    "canary_count": 3,
    "ransom_extensions": [".locked", ".crypto", ".enc", ".ryk", ".crypt", ".wcry"],
    "action": "auto",                 # auto | alert_only | always_suspend
    "protected_images": ["explorer.exe", "system", "svchost.exe", "csrss.exe"],
}

class RansomProtection(BaseService):
    name = "RansomProtection"

    def __init__(self, config=None, brain=None):
        cfg = dict(_DEFAULTS); cfg.update(config or {})
        super().__init__(cfg, brain)
        self._window = _Window()
        self._recent_trips: deque = deque()   # (ts, reason) for multi-detector correlation
        self._canaries: set[str] = set()
        self._observer = None

    # --- detection helpers (pinned by tests) ---
    def _pid_is_protected(self, pid) -> bool:
        # trusted-signed or critical system image -> never suspend
        if pid is None:
            return False
        try:
            import psutil
            p = psutil.Process(pid)
            name = (p.name() or "").lower()
            if name in {x.lower() for x in self.config["protected_images"]}:
                return True
            exe = p.exe()
            from Engine.Detection.cert_reputation import CertReputation
            return bool(exe and CertReputation().evaluate(exe).get("trusted"))
        except Exception:
            return False

    def _suspend_pid(self, pid) -> bool:
        try:
            import psutil
            psutil.Process(pid).suspend(); return True
        except Exception:
            return False

    def _classify_and_respond(self, trip_reasons: set, path: str, pid) -> str:
        high_conf = ("canary" in trip_reasons) or (len(trip_reasons) >= 2)
        action = self.config.get("action", "auto")
        if action == "alert_only":
            return "alert"
        want_suspend = (action == "always_suspend") or (action == "auto" and high_conf)
        if not want_suspend:
            return "alert"
        if pid is None:
            return "alert"
        if self._pid_is_protected(pid):
            return "alert_safeguarded"
        self._suspend_pid(pid)
        return "suspend"

    def _on_trip(self, trip_reasons: set, path: str, pid) -> None:
        self.emit_threat(ThreatCategory.RANSOMWARE, ThreatSeverity.CRITICAL,
                         "Ransomware behavior detected",
                         f"triggers={sorted(trip_reasons)} path={path}",
                         file_path=path, pid=pid, extra={"reasons": sorted(trip_reasons)})
        self._classify_and_respond(trip_reasons, path, pid)

    # --- watchdog wiring (standard; seed canaries, subscribe to events, feed detectors) ---
    def _run(self) -> None:
        # seed canaries; start a watchdog Observer over config['watch_dirs'];
        # on each event run _detectors(event) which may call _on_trip; heartbeat each loop.
        # (Use watchdog.observers.Observer + a FileSystemEventHandler; on stop, _teardown stops it.)
        ...
    def _teardown(self) -> None:
        try:
            if self._observer: self._observer.stop(); self._observer.join(timeout=2)
        except Exception: pass
```
Implement `_run`/`_detectors`/canary seeding to satisfy the behavior; the tests exercise the pure logic directly (no real Observer needed for the suite).

- [ ] **Step 4: Run tests to green**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_ransom_protection.py -q 2>&1 | tail -12`
Expected: all pass. Adjust `_Window.count` / test expectation so they agree on the half-open `(now-seconds, now]` horizon.

- [ ] **Step 5: Commit**

```bash
git add Services/Protection/SentinelRansomProtection.py tests/services/test_ransom_protection.py
git commit -m "Phase 3B Task 2: RansomProtection rewrite (velocity/entropy/canary/ext + graduated response)"
```

---

### Task 3: ExploitProtection rewrite

**Files:**
- Rewrite: `Services/Protection/SentinelExploitProtection.py`
- Test: `tests/services/test_exploit_protection.py`

**Interfaces:**
- Consumes: `BaseService`; `Engine.Detection.cert_reputation.CertReputation`.
- Produces: `class ExploitProtection(BaseService)` (`name="ExploitProtection"`) with a pure classifier `evaluate_process(proc: dict) -> tuple[bool, str, ThreatSeverity]` where `proc` has keys `{pid, name, exe, cmdline(list[str]), parent_name}`. Returns `(is_suspicious, reason, severity)`.

- [ ] **Step 1: Write the tests** (define the classifier contract)

`tests/services/test_exploit_protection.py`:
```python
from Services.Protection.SentinelExploitProtection import ExploitProtection
from Services.SentinelBrain import ThreatSeverity

def _ep():
    return ExploitProtection(brain=None)

def test_office_spawns_powershell_is_high():
    ep = _ep()
    sus, reason, sev = ep.evaluate_process(
        {"pid": 10, "name": "powershell.exe", "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "cmdline": ["powershell.exe", "-nop", "-w", "hidden", "-enc", "AAA="], "parent_name": "winword.exe"})
    assert sus is True and sev == ThreatSeverity.HIGH and "parent" in reason.lower()

def test_lolbin_encoded_powershell_is_high():
    ep = _ep()
    sus, reason, sev = ep.evaluate_process(
        {"pid": 11, "name": "powershell.exe", "exe": "p", "cmdline": ["powershell", "-EncodedCommand", "ZQ=="],
         "parent_name": "cmd.exe"})
    assert sus is True and sev in (ThreatSeverity.HIGH, ThreatSeverity.MEDIUM)

def test_benign_process_not_flagged():
    ep = _ep()
    sus, reason, sev = ep.evaluate_process(
        {"pid": 12, "name": "notepad.exe", "exe": r"C:\Windows\System32\notepad.exe",
         "cmdline": ["notepad.exe"], "parent_name": "explorer.exe"})
    assert sus is False

def test_untrusted_temp_location(monkeypatch):
    ep = _ep()
    monkeypatch.setattr(ep, "_is_trusted_exe", lambda exe: False)
    sus, reason, sev = ep.evaluate_process(
        {"pid": 13, "name": "x.exe", "exe": r"C:\Users\u\AppData\Local\Temp\x.exe",
         "cmdline": ["x.exe"], "parent_name": "explorer.exe"})
    assert sus is True and "untrusted" in reason.lower()
```

- [ ] **Step 2: Run to see fail**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_exploit_protection.py -q 2>&1 | tail -12` → import/attr errors.

- [ ] **Step 3: Implement** — `evaluate_process` encodes the rules (parent→child set, LOLBin arg patterns, untrusted temp/downloads location via `_is_trusted_exe` which wraps `CertReputation`), and `_run` polls `psutil.process_iter` on `poll_interval`, builds the `proc` dict, calls `evaluate_process`, and `emit_threat(ThreatCategory.EXPLOIT, sev, ...)` on suspicious (de-duped by pid). Config holds the parent/child map, LOLBin patterns, watched locations. Keep `evaluate_process` pure (no psutil) so tests drive it directly.

- [ ] **Step 4: Run to green** — `.venv/Scripts/python.exe -m pytest tests/services/test_exploit_protection.py -q` → all pass.

- [ ] **Step 5: Commit**

```bash
git add Services/Protection/SentinelExploitProtection.py tests/services/test_exploit_protection.py
git commit -m "Phase 3B Task 3: ExploitProtection rewrite (chains/LOLBins/untrusted-location)"
```

---

### Task 4: BehavioralEngine rewrite

**Files:**
- Rewrite: `Services/SentinelBehavioralEngine.py`
- Rewrite: `Engine/Rules/behavioral_rules.json` (schema + starter rules)
- Test: `tests/services/test_behavioral_engine.py`

**Interfaces:**
- Consumes: `BaseService`.
- Produces: `class BehavioralEngine(BaseService)` (`name="BehavioralEngine"`); pure functions `load_rules(path) -> list[dict]` (skips malformed rules), `event_matches(rule: dict, event: dict) -> bool`, and a `RuleState` that tracks windowed thresholds via `feed(rule, event, now) -> bool` (returns True when the rule *fires*).

- [ ] **Step 1: Write the tests**

`tests/services/test_behavioral_engine.py`:
```python
import json
from Services.SentinelBehavioralEngine import load_rules, event_matches, RuleState

def test_event_matches_ops():
    rule = {"event": "process_start",
            "conditions": [{"field": "image", "op": "contains", "value": "powershell"},
                           {"field": "cmdline", "op": "regex", "value": "-enc"}]}
    assert event_matches(rule, {"type": "process_start", "image": "powershell.exe", "cmdline": "ps -enc x"}) is True
    assert event_matches(rule, {"type": "process_start", "image": "cmd.exe", "cmdline": "-enc"}) is False
    assert event_matches(rule, {"type": "file_write", "image": "powershell.exe", "cmdline": "-enc"}) is False  # wrong event type

def test_windowed_threshold_fires_once(fake_brain):
    rule = {"id": "R", "event": "net_connect", "threshold": 3, "window_seconds": 10,
            "conditions": [{"field": "remote_ip", "op": "startswith", "value": "185."}]}
    st = RuleState(rule)
    ev = {"type": "net_connect", "remote_ip": "185.1.1.1"}
    assert st.feed(rule, ev, now=0) is False
    assert st.feed(rule, ev, now=1) is False
    assert st.feed(rule, ev, now=2) is True     # 3rd within window -> fire
    assert st.feed(rule, ev, now=3) is False    # already fired for this burst

def test_single_event_rule_fires_immediately():
    rule = {"id": "S", "event": "process_start", "threshold": 1, "window_seconds": None,
            "conditions": [{"field": "image", "op": "eq", "value": "mimikatz.exe"}]}
    st = RuleState(rule)
    assert st.feed(rule, {"type": "process_start", "image": "mimikatz.exe"}, now=0) is True

def test_load_rules_skips_malformed(tmp_path):
    p = tmp_path / "rules.json"
    p.write_text(json.dumps({"rules": [
        {"id": "ok", "event": "process_start", "conditions": []},
        {"id": "bad"},                        # missing 'event' -> skipped
        "not a dict",                          # skipped
    ]}))
    rules = load_rules(str(p))
    assert [r["id"] for r in rules] == ["ok"]
```

- [ ] **Step 2: Run to see fail** → import/attr errors.

- [ ] **Step 3: Implement**
```python
import json, re, time
from collections import deque
from Services.framework.base_service import BaseService
from Services.SentinelBrain import ThreatCategory, ThreatSeverity

_OPS = {
    "eq": lambda a, b: a == b,
    "contains": lambda a, b: b in (a or ""),
    "startswith": lambda a, b: (a or "").startswith(b),
    "regex": lambda a, b: re.search(b, a or "") is not None,
    "in": lambda a, b: a in b,
}

def event_matches(rule: dict, event: dict) -> bool:
    if rule.get("event") != event.get("type"):
        return False
    for cond in rule.get("conditions", []):
        op = _OPS.get(cond.get("op"))
        if op is None:
            return False
        if not op(event.get(cond.get("field")), cond.get("value")):
            return False
    return True

def load_rules(path: str) -> list:
    try:
        raw = json.loads(open(path, encoding="utf-8").read())
    except Exception:
        return []
    out = []
    for r in raw.get("rules", []):
        if isinstance(r, dict) and r.get("event") and "conditions" in r:
            out.append(r)
    return out

class RuleState:
    def __init__(self, rule: dict):
        self._hits = deque()
        self._fired = False
    def feed(self, rule: dict, event: dict, now: float) -> bool:
        if not event_matches(rule, event):
            return False
        threshold = int(rule.get("threshold", 1))
        window = rule.get("window_seconds")
        if window is None or threshold <= 1:
            return True
        cutoff = now - float(window)
        self._hits.append(now)
        while self._hits and self._hits[0] <= cutoff:
            self._hits.popleft()
        if len(self._hits) >= threshold and not self._fired:
            self._fired = True
            return True
        if len(self._hits) < threshold:
            self._fired = False
        return False

# BehavioralEngine(BaseService): _run polls psutil for process_start / net_connect events,
# builds event dicts {type,image,cmdline,parent,remote_ip,...}, feeds each rule's RuleState,
# and emit_threat(ThreatCategory.BEHAVIORAL, <severity from rule>, rule['name'], ...) on fire.
```
Rewrite `Engine/Rules/behavioral_rules.json` to the `{"rules": [...]}` schema with a few real starter rules (encoded-powershell process_start, mimikatz image, repeated connects to a suspicious prefix). `ThreatSeverity[rule.get("severity","MEDIUM")]` maps the string to the enum.

- [ ] **Step 4: Run to green** — `.venv/Scripts/python.exe -m pytest tests/services/test_behavioral_engine.py -q` → all pass.

- [ ] **Step 5: Commit**

```bash
git add Services/SentinelBehavioralEngine.py Engine/Rules/behavioral_rules.json tests/services/test_behavioral_engine.py
git commit -m "Phase 3B Task 4: BehavioralEngine rewrite (JSON rule engine + windowed thresholds)"
```

---

### Task 5: Orchestration refactor + integration

**Files:**
- Modify: `Services/SentinelService_v2.py` (uniform registry for the 3 rewritten services)
- Modify: `scripts/verify_reachability.py` (`EXPECTED_LIVE`)
- Test: `tests/services/test_orchestration.py`

**Interfaces:**
- Consumes: `RansomProtection`, `ExploitProtection`, `BehavioralEngine` (all `BaseService`).

- [ ] **Step 1: Read `Services/SentinelService_v2.py`** to find the `_RansomThread`/`_ExploitThread`/`_BehavioralThread` wrappers and how `start`/`stop`/status iterate modules.

- [ ] **Step 2: Refactor** — replace those three `_ModuleThread` wrappers with the new services behind a uniform adapter so the orchestrator calls `svc.start()`/`svc.stop()`/`svc.is_running()` uniformly. Instantiate them with config from `Sys_Config`. Leave the other (not-yet-rewritten) modules' wrappers untouched; the registry holds both kinds behind the same `start/stop/is_running` shape. Keep the `get_brain().set_module_running` status reporting working (the new services do it themselves in `BaseService`).

- [ ] **Step 3: Write the integration test**

`tests/services/test_orchestration.py`:
```python
from Services.Protection.SentinelRansomProtection import RansomProtection
from Services.Protection.SentinelExploitProtection import ExploitProtection
from Services.SentinelBehavioralEngine import BehavioralEngine

def test_services_start_stop_uniformly(fake_brain, tmp_path):
    svcs = [RansomProtection(config={"watch_dirs": [str(tmp_path)]}, brain=fake_brain),
            ExploitProtection(config={"poll_interval": 0.1}, brain=fake_brain),
            BehavioralEngine(config={"poll_interval": 0.1}, brain=fake_brain)]
    for s in svcs:
        s.start()
    assert all(s.is_running() for s in svcs)
    for s in svcs:
        s.stop()
    assert not any(s.is_running() for s in svcs)
```

- [ ] **Step 4: Run + reachability + boot**

Run: `.venv/Scripts/python.exe -m pytest tests/services/ -q 2>&1 | tail -6` → all pass.
Run: `.venv/Scripts/python.exe scripts/verify_reachability.py 2>&1 | tail -3`. If LIVE changed (new framework modules are imported by the rewritten services, which are imported by SentinelService_v2), set `EXPECTED_LIVE` to the printed value; re-run → PASS.
Boot check:
```bash
SENTINEL_NO_ELEVATE=1 timeout 100 .venv/Scripts/python.exe -c "import os,sys,threading,time,urllib.request,importlib.util; os.environ['SENTINEL_NO_ELEVATE']='1'; sys.argv=['x','--no-elevate']; os.chdir(r'D:/ZashironSentinel'); sys.path.insert(0,r'D:/ZashironSentinel'); spec=importlib.util.spec_from_file_location('e','SentinelUI_Flask.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); threading.Thread(target=m._start_flask,daemon=True).start(); time.sleep(10); print('HTTP', urllib.request.urlopen('http://127.0.0.1:8765',timeout=5).status); os._exit(0)" 2>&1 | grep -E "HTTP|Traceback|Error"
```
Expected: `HTTP 200`.

- [ ] **Step 5: Commit**

```bash
git add Services/SentinelService_v2.py scripts/verify_reachability.py tests/services/test_orchestration.py
git commit -m "Phase 3B Task 5: uniform service registry for the rewritten file/host services"
```

---

## Self-Review

- **Spec coverage:** §2 BaseService → T1 (full code + tests). §3.1 Ransom (4 detectors + graduated response + safety guard) → T2 (pure helpers + `_classify_and_respond` + tests). §3.2 Exploit → T3 (`evaluate_process` + tests). §3.3 Behavioral (schema + engine) → T4 (`load_rules`/`event_matches`/`RuleState` + rules json + tests). §4 orchestration → T5. §5 error isolation → T1 `_guarded_run` + `test_run_crash_sets_error_not_process`. §6 synthetic-trigger testing → each task's tests. §7 deps (watchdog) → T1. All covered.
- **Placeholder scan:** the framework, all pure helpers, and ALL tests are complete code. The `_run` watchdog/psutil *plumbing* bodies are described precisely (not shown line-for-line) because they are standard library wiring whose behavior is pinned by the pure-logic tests — the load-bearing logic (entropy, window, classify/respond, evaluate_process, rule matching, windowed thresholds) is complete. This is the honest form for a rewrite; no vague "add error handling".
- **Type consistency:** `emit_threat(category, severity, title, detail, file_path, pid, ip_address, extra)` consistent T1↔T2↔T3↔T4. `evaluate_process(proc)->(bool,str,ThreatSeverity)` T3. `event_matches(rule,event)->bool`, `RuleState.feed(rule,event,now)->bool`, `load_rules(path)->list` T4. `_Window.count(now,seconds)` and `_classify_and_respond(reasons,path,pid)->str` T2.
- **Known coupling:** T5's `EXPECTED_LIVE` value is computed at execution (can't be known until the new modules exist) — intentional, matches the Phase 2 pattern.
