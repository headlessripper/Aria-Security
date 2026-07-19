# Phase 3C — Device & Discovery — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite StorageGuard (all external/removable storage, scan-then-warn, absorbing AccessControl) and SentinelSense (system-change monitor with suspicious-install flagging) on `BaseService`.

**Architecture:** Each service has a PURE, test-pinned core (StorageGuard: `is_external_storage`/`diff_drives`/`is_allowlisted`; Sense: `diff_installs`/`classify_install`) and a `BaseService` I/O loop (polling + scan/registry + emit). Windows I/O (IOCTL bus-type probe, icacls, USBSTOR, VirusScanner, registry) is isolated behind the pure core so it's mocked in tests.

**Tech Stack:** Python 3.10+, ctypes (Win32 IOCTL), winreg, psutil, pytest. Reuses `Services.framework.base_service.BaseService`, `Engine.Compiler.SentinelCompiler_v5.VirusScanner`, `Engine.Detection.cert_reputation.CertReputation`, `Services.SentinelBrain`.

## Global Constraints

- Both services subclass `BaseService`; threats only via `emit_threat(...)`; cooperative stop; exception-isolated `_run`.
- StorageGuard covers ANY external/removable storage: `is_external_storage` returns True for `DRIVE_REMOVABLE`, OR `bus_type ∈ {6,7,12,13}` (1394/USB/SD/MMC), OR `removable_media` — so an external HDD/SSD reported as `DRIVE_FIXED` is caught. `DRIVE_REMOTE` (network) → False.
- **Default response = scan-then-warn** (allow access, background scan, `emit_threat` + quarantine the offending FILE on a hit — NOT a drive-wide access lock). `block_until_scanned` config default **False**.
- StorageGuard preserves the module-level API the Flask UI calls: `get_state()`, `get_guard()`, `set_port_locker(bool)`, `port_locker_status()`, `trust_device(serial)`.
- SentinelSense: Qt window removed; keep `get_state()`; brain name `"SentinelSense"`. StorageGuard brain name `"USBMonitor"`.
- No new dependencies. App boots HTTP 200; `scripts/verify_reachability.py` green (update `EXPECTED_LIVE` in Task 5). Never `git add` any `.exe`/`.ips`/PE binary. Commit after every task.

---

## File Structure

- `Services/SentinelUSBGuard.py` — **rewrite.** `StorageGuard(BaseService)` + pure detection core + module API. (Filename kept for Flask imports.)
- `Services/Sense/SentinelSense.py` — **rewrite.** `SentinelSense(BaseService)` + pure core; Qt removed.
- `Services/SentinelService_v2.py` — **modify.** `_ServiceHolder` for both.
- `tests/services/test_storage_guard_core.py`, `test_storage_guard.py`, `test_sense_core.py`, `test_sense.py` — **new.**

---

### Task 1: StorageGuard pure detection core

**Files:**
- Create (partial): `Services/SentinelUSBGuard.py` (pure fns + constants only this task)
- Test: `tests/services/test_storage_guard_core.py`

**Interfaces:**
- Produces: `is_external_storage(drive_info: dict) -> bool`, `diff_drives(before: set, after: set) -> tuple[set, set]` (new, removed), `is_allowlisted(drive_info: dict, allowlist: set) -> bool`. Constants `DRIVE_REMOVABLE=2`, `DRIVE_FIXED=3`, `DRIVE_REMOTE=4`, `DRIVE_CDROM=5`, `EXTERNAL_BUS_TYPES={6,7,12,13}`.

- [ ] **Step 1: Write the tests**

`tests/services/test_storage_guard_core.py`:
```python
from Services.SentinelUSBGuard import is_external_storage, diff_drives, is_allowlisted

def test_usb_flash_is_external():
    assert is_external_storage({"letter": "E:", "drive_type": 2, "bus_type": 7}) is True

def test_external_ssd_reported_fixed_is_external():
    # external SSD on USB: Windows says DRIVE_FIXED(3) but bus is USB(7)
    assert is_external_storage({"letter": "F:", "drive_type": 3, "bus_type": 7}) is True

def test_internal_disk_not_external():
    # internal SATA SSD: FIXED + SATA bus (11), removable_media False
    assert is_external_storage({"letter": "C:", "drive_type": 3, "bus_type": 11, "removable_media": False}) is False

def test_network_drive_not_external():
    assert is_external_storage({"letter": "Z:", "drive_type": 4, "bus_type": 0}) is False

def test_removable_media_flag_is_external():
    assert is_external_storage({"letter": "G:", "drive_type": 3, "bus_type": 0, "removable_media": True}) is True

def test_diff_drives():
    new, removed = diff_drives({"C:", "D:"}, {"C:", "D:", "E:"})
    assert new == {"E:"} and removed == set()
    new, removed = diff_drives({"C:", "E:"}, {"C:"})
    assert new == set() and removed == {"E:"}

def test_allowlist():
    al = {"VOL-1234", "MyUSB"}
    assert is_allowlisted({"serial": "VOL-1234"}, al) is True
    assert is_allowlisted({"label": "MyUSB"}, al) is True
    assert is_allowlisted({"serial": "OTHER", "label": "x"}, al) is False
```

- [ ] **Step 2: Run to fail** → import error.

- [ ] **Step 3: Implement** (top of `Services/SentinelUSBGuard.py`)

```python
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
# STORAGE_BUS_TYPE: 6=1394, 7=USB, 12=SD, 13=MMC (all external/removable transports)
EXTERNAL_BUS_TYPES = {6, 7, 12, 13}

def is_external_storage(drive_info):
    """True if drive_info describes external/removable storage.
    drive_info: {letter, drive_type, bus_type, removable_media?}. An external
    HDD/SSD on USB reports drive_type=FIXED but bus_type=USB -> still external."""
    dt = drive_info.get("drive_type")
    if dt == DRIVE_REMOTE:
        return False
    if dt == DRIVE_REMOVABLE:
        return True
    if drive_info.get("removable_media"):
        return True
    return drive_info.get("bus_type") in EXTERNAL_BUS_TYPES

def diff_drives(before, after):
    return (after - before, before - after)

def is_allowlisted(drive_info, allowlist):
    return (drive_info.get("serial") in allowlist) or (drive_info.get("label") in allowlist)
```

- [ ] **Step 4: Run to green** — `.venv/Scripts/python.exe -m pytest tests/services/test_storage_guard_core.py -q` → 7 passed.

- [ ] **Step 5: Commit**

```bash
git add Services/SentinelUSBGuard.py tests/services/test_storage_guard_core.py
git commit -m "Phase 3C Task 1: StorageGuard pure detection core (external-storage classifier)"
```

---

### Task 2: StorageGuard service

**Files:**
- Modify: `Services/SentinelUSBGuard.py` (add the `BaseService` + I/O + module API)
- Test: `tests/services/test_storage_guard.py`

**Interfaces:**
- Consumes: Task 1 pure fns; `BaseService`; `Engine.Compiler.SentinelCompiler_v5.VirusScanner`; `Services.SentinelBrain.ThreatCategory/ThreatSeverity`.
- Produces: `class StorageGuard(BaseService)` (`name="USBMonitor"`); module fns `get_state()->dict`, `get_guard()->StorageGuard|None`, `set_port_locker(enabled: bool)->bool`, `port_locker_status()->bool`, `trust_device(serial: str)->None`. Method `_scan_drive(letter, drive_info)` (background scan → emit + quarantine on hit).

- [ ] **Step 1: Write the tests**

`tests/services/test_storage_guard.py`:
```python
from Services.SentinelUSBGuard import StorageGuard

def test_lifecycle(fake_brain):
    g = StorageGuard(brain=fake_brain)
    g.start()
    assert g.is_running() is True
    g.stop()
    assert g.is_running() is False

def test_scan_emits_and_quarantines_on_malware(fake_brain, tmp_path, monkeypatch):
    g = StorageGuard(brain=fake_brain)
    bad = tmp_path / "evil.exe"; bad.write_bytes(b"MZ" + b"\x00" * 100)
    # fake VirusScanner: reports the file malicious
    class FakeVS:
        def scan_file(self, p): return {"verdict": "MALWARE", "reasons": ["test"], "details": {}}
    g._scanner = FakeVS()
    quarantined = []
    monkeypatch.setattr(g, "_quarantine", lambda p: quarantined.append(p))
    g._scan_files([str(bad)], "E:")
    assert any(t["category"] for t in fake_brain.threats)   # a threat was emitted
    assert quarantined == [str(bad)]

def test_scan_clean_no_emit(fake_brain, tmp_path):
    g = StorageGuard(brain=fake_brain)
    good = tmp_path / "ok.exe"; good.write_bytes(b"MZ" + b"\x00" * 100)
    class FakeVS:
        def scan_file(self, p): return {"verdict": "CLEAN", "reasons": [], "details": {}}
    g._scanner = FakeVS()
    g._scan_files([str(good)], "E:")
    assert fake_brain.threats == []

def test_allowlisted_drive_skipped(fake_brain):
    g = StorageGuard(brain=fake_brain, config={"allowlist": {"VOL-1"}})
    # a helper that decides whether to scan a newly-seen drive
    assert g._should_scan({"letter": "E:", "drive_type": 2, "bus_type": 7, "serial": "VOL-1"}) is False
    assert g._should_scan({"letter": "F:", "drive_type": 2, "bus_type": 7, "serial": "OTHER"}) is True
```
(Extend `tests/services/conftest.py`'s `FakeBrain` to record `emit_event` into a `self.threats` list if not already present — a threat dict with a `category` key.)

- [ ] **Step 2: Run to fail.**

- [ ] **Step 3: Implement** the service. Add to `Services/SentinelUSBGuard.py`:
```python
import ctypes, json, threading, time
from pathlib import Path
from Services.framework.base_service import BaseService
from Services.SentinelBrain import ThreatCategory, ThreatSeverity

_STATE_PATH = Path.home() / ".AriaSecurity" / "usb_guard_state.json"
_SCAN_EXTS = {".exe",".dll",".scr",".com",".sys",".bat",".cmd",".ps1",".vbs",".js",".jar",".msi",".lnk",".hta"}
_GUARD_SINGLETON = None

class StorageGuard(BaseService):
    name = "USBMonitor"
    def __init__(self, config=None, brain=None):
        cfg = {"allowlist": set(), "block_until_scanned": False, "poll_interval": 3.0, "max_files": 5000}
        cfg.update(config or {})
        super().__init__(cfg, brain)
        self._scanner = None
        self._known = set()
        global _GUARD_SINGLETON; _GUARD_SINGLETON = self

    def _should_scan(self, drive_info):
        from Services.SentinelUSBGuard import is_external_storage, is_allowlisted
        if not is_external_storage(drive_info):
            return False
        return not is_allowlisted(drive_info, self.config.get("allowlist", set()))

    def _ensure_scanner(self):
        if self._scanner is None:
            from Engine.Compiler.SentinelCompiler_v5 import VirusScanner
            self._scanner = VirusScanner(max_workers=2)
        return self._scanner

    def _scan_files(self, files, letter):
        scanner = self._scanner or self._ensure_scanner()
        for f in files:
            try:
                r = scanner.scan_file(f)
                if r.get("verdict") == "MALWARE":
                    self.emit_threat(ThreatCategory.USB, ThreatSeverity.HIGH,
                                     "Malware on external drive", "; ".join(r.get("reasons", [])), file_path=f)
                    self._quarantine(f)
            except Exception as e:
                self._log(f"scan error {f}: {e}", "ERROR")

    def _scan_drive(self, letter, drive_info):
        self._set_drive_state(letter, "scanning")
        files = self._enumerate(letter)
        self._scan_files(files, letter)
        self._set_drive_state(letter, "scanned")

    def _quarantine(self, path):
        # move to vault/quarantine dir (best-effort); real impl uses SecureVault
        ...
    def _enumerate(self, letter): ...        # walk drive root, filter _SCAN_EXTS, cap max_files
    def _set_drive_state(self, letter, state): ...   # persist to _STATE_PATH
    def _run(self): ...                      # poll GetLogicalDrives diff -> for new letters, probe drive_info, if _should_scan -> threading.Thread(_scan_drive)

# module API (kept for Flask)
def get_state(): ...
def get_guard(): return _GUARD_SINGLETON
def set_port_locker(enabled): ...            # USBSTOR Start=4/3 + Disable/Enable-PnpDevice, guarded
def port_locker_status(): ...
def trust_device(serial): ...
```
Fully implement each `...`: `_run` polls `[chr(65+i)+':' for i,b in enumerate(bin(ctypes.windll.kernel32.GetLogicalDrives())) ...]` (or `os.listdrives`-style), diffs via `diff_drives`, for each NEW letter gathers `drive_info` (drive_type via `GetDriveTypeW`; bus_type/removable via `IOCTL_STORAGE_QUERY_PROPERTY` on `\\.\X:` — guarded, default `bus_type=0` on failure so drive-type still classifies), and if `_should_scan` spawns a daemon `_scan_drive` thread; `_heartbeat()`; `_sleep(poll_interval)`. `_quarantine` moves the file into `~/.AriaSecurity/quarantine/` (best-effort, exception-isolated). `set_port_locker`/`port_locker_status` use `reg`/`Disable-PnpDevice` guarded (missing admin → log + return False). `get_state` reads `_STATE_PATH`.

- [ ] **Step 4: Run to green** — `.venv/Scripts/python.exe -m pytest tests/services/test_storage_guard.py -q` → passes. Then `.venv/Scripts/python.exe -m pytest tests/services/ -q` → whole suite passes.

- [ ] **Step 5: Commit**

```bash
git add Services/SentinelUSBGuard.py tests/services/test_storage_guard.py tests/services/conftest.py
git commit -m "Phase 3C Task 2: StorageGuard service (scan-then-warn, port-locker, module API)"
```

---

### Task 3: SentinelSense pure core

**Files:**
- Create (partial): `Services/Sense/SentinelSense.py` (pure fns only)
- Test: `tests/services/test_sense_core.py`

**Interfaces:**
- Produces: `diff_installs(before: dict, after: dict) -> tuple[list, list]` (installed, uninstalled — each a list of app_info dicts), `classify_install(app_info: dict, is_trusted_exe=None) -> tuple[bool, str]`.

- [ ] **Step 1: Write the tests**

`tests/services/test_sense_core.py`:
```python
from Services.Sense.SentinelSense import diff_installs, classify_install

def test_diff_installs_detects_add_and_remove():
    before = {"AppA": {"name": "AppA"}}
    after = {"AppA": {"name": "AppA"}, "AppB": {"name": "AppB"}}
    installed, uninstalled = diff_installs(before, after)
    assert [a["name"] for a in installed] == ["AppB"] and uninstalled == []
    installed, uninstalled = diff_installs(after, before)
    assert installed == [] and [a["name"] for a in uninstalled] == ["AppB"]

def test_classify_unsigned_exe_suspicious():
    info = {"name": "x", "publisher": "Acme", "install_location": r"C:\Program Files\X", "main_exe": r"C:\Program Files\X\x.exe"}
    sus, reason = classify_install(info, is_trusted_exe=lambda e: False)   # untrusted
    assert sus is True and "unsigned" in reason.lower()

def test_classify_signed_programfiles_clean():
    info = {"name": "x", "publisher": "Acme", "install_location": r"C:\Program Files\X", "main_exe": r"C:\Program Files\X\x.exe"}
    sus, _ = classify_install(info, is_trusted_exe=lambda e: True)
    assert sus is False

def test_classify_temp_location_no_publisher_suspicious():
    info = {"name": "x", "publisher": "", "install_location": r"C:\Users\u\AppData\Local\Temp\x", "main_exe": None}
    sus, reason = classify_install(info, is_trusted_exe=None)
    assert sus is True

def test_classify_clean_no_signals():
    info = {"name": "x", "publisher": "Acme", "install_location": r"C:\Program Files\X", "main_exe": None}
    sus, _ = classify_install(info, is_trusted_exe=None)
    assert sus is False
```

- [ ] **Step 2: Run to fail.**

- [ ] **Step 3: Implement** (top of `Services/Sense/SentinelSense.py`)
```python
_SUSPICIOUS_LOC = ("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp", "\\appdata\\roaming")

def diff_installs(before, after):
    installed = [after[k] for k in after.keys() - before.keys()]
    uninstalled = [before[k] for k in before.keys() - after.keys()]
    return installed, uninstalled

def classify_install(app_info, is_trusted_exe=None):
    loc = (app_info.get("install_location") or "").lower()
    susp_loc = any(s in loc for s in _SUSPICIOUS_LOC)
    no_pub = not (app_info.get("publisher") or "").strip()
    exe = app_info.get("main_exe")
    untrusted = bool(is_trusted_exe and exe and not is_trusted_exe(exe))
    reasons = []
    if untrusted: reasons.append("unsigned/untrusted executable")
    if susp_loc: reasons.append("suspicious install location")
    if no_pub: reasons.append("no publisher")
    suspicious = untrusted or (susp_loc and no_pub)
    return suspicious, "; ".join(reasons)
```

- [ ] **Step 4: Run to green** — `.venv/Scripts/python.exe -m pytest tests/services/test_sense_core.py -q` → 5 passed.

- [ ] **Step 5: Commit**

```bash
git add Services/Sense/SentinelSense.py tests/services/test_sense_core.py
git commit -m "Phase 3C Task 3: SentinelSense pure core (install diff + suspicious classifier)"
```

---

### Task 4: SentinelSense service

**Files:**
- Modify: `Services/Sense/SentinelSense.py` (add `BaseService` + registry I/O; REMOVE all Qt code)
- Test: `tests/services/test_sense.py`

**Interfaces:**
- Consumes: Task 3 pure fns; `BaseService`; `Engine.Detection.cert_reputation.CertReputation`; `Services.SentinelBrain`.
- Produces: `class SentinelSense(BaseService)` (`name="SentinelSense"`); module `get_state()->dict`. Method `_snapshot_installed()->dict` (reads the 3 Uninstall keys).

- [ ] **Step 1: Write the tests**

`tests/services/test_sense.py`:
```python
from Services.Sense.SentinelSense import SentinelSense

def test_lifecycle(fake_brain):
    s = SentinelSense(brain=fake_brain)
    s.start()
    assert s.is_running() is True
    s.stop()
    assert s.is_running() is False

def test_new_suspicious_install_emits(fake_brain, monkeypatch):
    s = SentinelSense(brain=fake_brain)
    # drive two snapshots through the internal handler with an injected classifier
    before = {"AppA": {"name": "AppA", "publisher": "Acme", "install_location": r"C:\Program Files\A", "main_exe": None}}
    after = dict(before); after["Evil"] = {"name": "Evil", "publisher": "", "install_location": r"C:\Users\u\AppData\Local\Temp\evil", "main_exe": None}
    s._process_snapshot(before, after)   # helper: diffs + classifies + emits
    assert any("Suspicious" in (t.get("title","")) or t.get("category") for t in fake_brain.threats)

def test_benign_install_no_emit(fake_brain):
    s = SentinelSense(brain=fake_brain)
    before = {"AppA": {"name": "AppA", "publisher": "Acme", "install_location": r"C:\Program Files\A", "main_exe": None}}
    after = dict(before); after["Good"] = {"name": "Good", "publisher": "BigCo", "install_location": r"C:\Program Files\Good", "main_exe": None}
    s._process_snapshot(before, after)
    assert fake_brain.threats == []
```

- [ ] **Step 2: Run to fail.**

- [ ] **Step 3: Implement** `class SentinelSense(BaseService)` (`name="SentinelSense"`). REMOVE every Qt import/stub/window class from the file. `_run`: `snap = self._snapshot_installed()`; loop: `self._sleep(scan_interval)`; `new = self._snapshot_installed()`; `self._process_snapshot(snap, new)`; `snap = new`; `_heartbeat()`. `_snapshot_installed()`: walk the 3 Uninstall registry keys via `winreg`, returning `{key: {name, publisher, install_location, main_exe, uninstall_string}}` (guarded per subkey). `_process_snapshot(before, after)`: `installed, uninstalled = diff_installs(before, after)`; for each installed → `sus, reason = classify_install(info, is_trusted_exe=self._trusted)`; if `sus` → `emit_threat(BEHAVIORAL, MEDIUM, "Suspicious software install", f"{name}: {reason}")`; for each uninstalled → best-effort leftover mapping → `emit_threat(SYSTEM, INFO, "Uninstall leftovers", detail)`. `self._trusted(exe)` wraps `CertReputation().evaluate(exe).get("trusted", False)` (guarded → False). `get_state()` returns persisted state.

- [ ] **Step 4: Run to green** — `.venv/Scripts/python.exe -m pytest tests/services/test_sense.py -q` → passes. Confirm no Qt: `grep -nE "PySide6|QApplication|QWidget|_QtStub" Services/Sense/SentinelSense.py` → EMPTY. Then whole `tests/services/` suite passes.

- [ ] **Step 5: Commit**

```bash
git add Services/Sense/SentinelSense.py tests/services/test_sense.py
git commit -m "Phase 3C Task 4: SentinelSense service (system-change monitor; Qt removed)"
```

---

### Task 5: Orchestration + wiring

**Files:**
- Modify: `Services/SentinelService_v2.py`, `scripts/verify_reachability.py`
- Test: extend `tests/services/test_orchestration.py`

- [ ] **Step 1: Read `Services/SentinelService_v2.py`** — find the `_UsbThread`/`_SenseThread` `_ModuleThread` wrappers + their imports of the old `SentinelSenseController`/USBGuard functions.

- [ ] **Step 2: Rewire** — replace `_UsbThread`/`_SenseThread` with `_ServiceHolder` wrapping `StorageGuard()` (from `Services.SentinelUSBGuard`) and `SentinelSense()` (from `Services.Sense.SentinelSense`). Fix all stale imports of the old names. Leave the other clusters untouched.

- [ ] **Step 3: Extend the orchestration test** — append to `tests/services/test_orchestration.py`:
```python
def test_device_services_start_stop(fake_brain):
    from Services.SentinelUSBGuard import StorageGuard
    from Services.Sense.SentinelSense import SentinelSense
    svcs = [StorageGuard(brain=fake_brain), SentinelSense(brain=fake_brain)]
    for s in svcs: s.start()
    assert all(s.is_running() for s in svcs)
    for s in svcs: s.stop()
    assert not any(s.is_running() for s in svcs)
```

- [ ] **Step 4: Verify suite + reachability + boot**

Run: `.venv/Scripts/python.exe -m pytest tests/services/ -q` → all pass.
Run: `.venv/Scripts/python.exe scripts/verify_reachability.py` — set `EXPECTED_LIVE` to the printed value, re-run → PASS.
Boot: `SENTINEL_NO_ELEVATE=1 timeout 120 .venv/Scripts/python.exe -c "import os,sys,threading,time,urllib.request,importlib.util; os.environ['SENTINEL_NO_ELEVATE']='1'; sys.argv=['x','--no-elevate']; os.chdir(r'D:/ZashironSentinel'); sys.path.insert(0,r'D:/ZashironSentinel'); spec=importlib.util.spec_from_file_location('e','SentinelUI_Flask.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); threading.Thread(target=m._start_flask,daemon=True).start(); time.sleep(12); sys.stdout.flush(); print('HTTP', urllib.request.urlopen('http://127.0.0.1:8765',timeout=5).status); sys.stdout.flush(); os._exit(0)" 2>&1 | grep -E "HTTP|Traceback|Error"` → `HTTP 200`.

- [ ] **Step 5: Commit**

```bash
git add Services/SentinelService_v2.py scripts/verify_reachability.py tests/services/test_orchestration.py
git commit -m "Phase 3C Task 5: wire StorageGuard + SentinelSense into the service registry"
```

---

## Self-Review

- **Spec coverage:** §2.1 detection → T1 (`is_external_storage` incl. external-SSD-as-FIXED). §2.2 scan-then-warn → T2. §2.3 port-locker → T2 (`set_port_locker`). §2.4 block_until_scanned config → T2 (default False). §2.5 allowlist + API → T1/T2. §3 Sense (diff_installs/classify_install/leftovers/no-Qt) → T3/T4. §4 orchestration → T5. §6 synthetic tests → each task. All covered.
- **Placeholder scan:** all pure fns (`is_external_storage`/`diff_drives`/`is_allowlisted`/`diff_installs`/`classify_install`) and ALL tests are complete code. The service `_run`/IOCTL/registry/port-locker bodies are specified precisely (Windows I/O behind the pure core, mocked in tests) — the `...` placeholders in the Task 2 skeleton are each accompanied by an explicit prose spec of exactly what to implement.
- **Type consistency:** `is_external_storage(drive_info)->bool`, `diff_drives(before,after)->(set,set)`, `is_allowlisted(drive_info,allowlist)->bool` T1↔T2; `diff_installs(before,after)->(list,list)`, `classify_install(app_info,is_trusted_exe)->(bool,str)` T3↔T4. `StorageGuard.name="USBMonitor"`, `SentinelSense.name="SentinelSense"`. `get_state`/`get_guard`/`set_port_locker`/`port_locker_status`/`trust_device` module API T2.
- **Note:** T5 `EXPECTED_LIVE` computed at execution (intentional).
