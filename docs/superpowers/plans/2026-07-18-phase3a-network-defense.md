# Phase 3A — Network Defense — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the network defense cluster (ThreatIntelligence, NetworkProtection, PSDS) on `BaseService` as reputation + IOC-feed + heuristic + packet-level defense, retiring the stale `.pkl` zoo.

**Architecture:** A shared thread-safe `ThreatIntelStore` decouples the IOC producer (ThreatIntelligence, feeding it) from the consumer (NetworkProtection, querying it). NetworkProtection collapses to a pure `classify_connection`; PSDS keeps WinDivert with graceful degradation. All three are `BaseService` subclasses wired via the `_ServiceHolder` registry.

**Tech Stack:** Python 3.10+, psutil, requests/urllib, pydivert (WinDivert), pytest. Reuses `Services.framework.base_service.BaseService`, `Services.SentinelBrain`.

## Global Constraints

- Every service subclasses `BaseService`; threats only via `emit_threat(category, severity, title, detail, ...)`; cooperative stop; exception-isolated `_run`.
- `NetworkProtection` contains NO `.pkl`/pandas/sklearn/CSV logic. Firewall blocking uses `netsh advfirewall` (both directions), kept from the current implementation.
- `ThreatIntelStore` is the ONLY IOC/reputation channel between the two services (via `get_intel_store()` singleton, or injected for tests).
- **Graceful degradation:** PSDS with missing `pydivert`/WinDivert/admin logs once + idles (stays "running", inert) — never crashes; a dead feed is skipped; `net_connections` AccessDenied under non-admin logs once + degrades.
- Reputation thresholds: block ≥ 80, alert ≥ 50 (config-overridable). PSDS default `syn_rate_threshold=50`, `window=1.0s`.
- New dep: `pydivert`. Retire the 9 `models/*.pkl` + `models/Data_Files/*.csv` to `cleanup/phase3a-network-pkl/` (loaded only by the old NetProtectionNG2).
- App boots HTTP 200; `scripts/verify_reachability.py` green (update `EXPECTED_LIVE` in Task 5). Never `git add` any `.exe`/`.ips`/PE binary. Commit after every task.

---

## File Structure

- `Services/Protection/threat_intel_store.py` — **new.** `ThreatIntelStore` + `get_intel_store()`.
- `Services/SentinelThreatIntelligence.py` — **rewrite.** `ThreatIntelligence(BaseService)` + pure feed parsers.
- `Services/Protection/SentinelNetProtectionNG2.py` — **rewrite.** `NetworkProtection(BaseService)` + `classify_connection`.
- `Services/Protection/Sentinelpsds.py` — **rewrite.** `PSDS(BaseService)` + `SynRateTracker`.
- `Services/SentinelService_v2.py` — **modify.** `_ServiceHolder` for the 3 network services.
- `requirements.txt` — **modify.** Add `pydivert`.
- `tests/services/test_threat_intel_store.py`, `test_threat_intelligence.py`, `test_network_protection.py`, `test_psds.py` — **new.**
- `cleanup/phase3a-network-pkl/…` — **new.** Retired `.pkl` + CSVs.

---

### Task 1: ThreatIntelStore

**Files:**
- Create: `Services/Protection/threat_intel_store.py`
- Test: `tests/services/test_threat_intel_store.py`

**Interfaces:**
- Produces: `class ThreatIntelStore` with `add_bad_ips(ips:set, source="unknown")`, `add_bad_hashes(hashes:set, source="unknown")`, `is_bad_ip(ip)->bool`, `is_bad_hash(sha256)->bool`, `set_reputation(ip, score:int, ttl_s=3600)`, `ip_reputation(ip)->int|None` (None when unknown or expired), `stats()->dict`. Module fn `get_intel_store()->ThreatIntelStore` (singleton).

- [ ] **Step 1: Write the implementation**

```python
import threading, time

class ThreatIntelStore:
    """Thread-safe shared IOC + reputation store (producer: ThreatIntelligence, consumer: NetworkProtection)."""
    def __init__(self):
        self._lock = threading.RLock()
        self._bad_ips = set()
        self._bad_hashes = set()
        self._reputation = {}   # ip -> (score, expires_ts)
        self._sources = {}

    def add_bad_ips(self, ips, source="unknown"):
        with self._lock:
            new = {str(i).strip() for i in ips if i and str(i).strip()}
            self._bad_ips |= new
            self._sources[source] = len(new)

    def add_bad_hashes(self, hashes, source="unknown"):
        with self._lock:
            self._bad_hashes |= {str(h).strip().lower() for h in hashes if h and str(h).strip()}

    def is_bad_ip(self, ip):
        with self._lock:
            return ip in self._bad_ips

    def is_bad_hash(self, sha256):
        with self._lock:
            return (sha256 or "").lower() in self._bad_hashes

    def set_reputation(self, ip, score, ttl_s=3600):
        with self._lock:
            self._reputation[ip] = (int(score), time.time() + ttl_s)

    def ip_reputation(self, ip):
        with self._lock:
            entry = self._reputation.get(ip)
            if not entry:
                return None
            score, exp = entry
            if time.time() > exp:
                del self._reputation[ip]
                return None
            return score

    def stats(self):
        with self._lock:
            return {"bad_ips": len(self._bad_ips), "bad_hashes": len(self._bad_hashes),
                    "reputation_cached": len(self._reputation), "sources": dict(self._sources)}

_STORE = None
def get_intel_store():
    global _STORE
    if _STORE is None:
        _STORE = ThreatIntelStore()
    return _STORE
```

- [ ] **Step 2: Write the tests**

`tests/services/test_threat_intel_store.py`:
```python
import time
from Services.Protection.threat_intel_store import ThreatIntelStore, get_intel_store

def test_bad_ip_add_and_query():
    s = ThreatIntelStore()
    s.add_bad_ips({"1.2.3.4", " 5.6.7.8 ", "", None}, source="feed")
    assert s.is_bad_ip("1.2.3.4") and s.is_bad_ip("5.6.7.8")
    assert s.is_bad_ip("9.9.9.9") is False

def test_bad_hash_case_insensitive():
    s = ThreatIntelStore()
    s.add_bad_hashes({"ABCDEF"}, source="x")
    assert s.is_bad_hash("abcdef") and s.is_bad_hash("ABCDEF")
    assert s.is_bad_hash("000000") is False

def test_reputation_ttl():
    s = ThreatIntelStore()
    s.set_reputation("1.1.1.1", 90, ttl_s=100)
    assert s.ip_reputation("1.1.1.1") == 90
    s.set_reputation("2.2.2.2", 40, ttl_s=-1)   # already expired
    assert s.ip_reputation("2.2.2.2") is None
    assert s.ip_reputation("3.3.3.3") is None

def test_singleton():
    assert get_intel_store() is get_intel_store()

def test_stats():
    s = ThreatIntelStore()
    s.add_bad_ips({"1.2.3.4"}, source="feodo")
    st = s.stats()
    assert st["bad_ips"] == 1 and "feodo" in st["sources"]
```

- [ ] **Step 3: Run** — `.venv/Scripts/python.exe -m pytest tests/services/test_threat_intel_store.py -q` → 5 passed, pristine.

- [ ] **Step 4: Commit**

```bash
git add Services/Protection/threat_intel_store.py tests/services/test_threat_intel_store.py
git commit -m "Phase 3A Task 1: ThreatIntelStore (shared IOC + reputation)"
```

---

### Task 2: ThreatIntelligence rewrite

**Files:**
- Rewrite: `Services/SentinelThreatIntelligence.py`
- Test: `tests/services/test_threat_intelligence.py`

**Interfaces:**
- Consumes: `BaseService`, `ThreatIntelStore`/`get_intel_store`.
- Produces: `class ThreatIntelligence(BaseService)` (`name="ThreatIntelligence"`); pure fns `parse_ip_list(text: str) -> set[str]` (skips `#`/`;`/blank; validates each first-token as an IP), `parse_hashes(content: bytes|str) -> tuple[set[str], set[str]]` (returns `(sha256_set, md5_set)`; JSON-tolerant with a hex-regex fallback). Retains `lookup_ip_abuseipdb(ip, api_key) -> dict|None`.

- [ ] **Step 1: Write the tests** (pin the parsers)

`tests/services/test_threat_intelligence.py`:
```python
from Services.SentinelThreatIntelligence import parse_ip_list, parse_hashes

def test_parse_ip_list():
    text = "# comment\n; also comment\n1.2.3.4\n5.6.7.8 , foo\nnot-an-ip\n\n10.0.0.1\n"
    ips = parse_ip_list(text)
    assert ips == {"1.2.3.4", "5.6.7.8", "10.0.0.1"}

def test_parse_hashes_regex_fallback():
    text = ("sha256: " + "a" * 64 + "\nmd5: " + "b" * 32 + "\ngarbage\n")
    sha, md5 = parse_hashes(text)
    assert ("a" * 64) in sha and ("b" * 32) in md5

def test_parse_hashes_bytes_ok():
    sha, md5 = parse_hashes(("c" * 64).encode())
    assert ("c" * 64) in sha
```

- [ ] **Step 2: Run to fail** → import errors.

- [ ] **Step 3: Implement** the parsers exactly as their tests require:
```python
import ipaddress, json, re

def parse_ip_list(text):
    ips = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        tok = line.replace(",", " ").split()[0]
        try:
            ipaddress.ip_address(tok); ips.add(tok)
        except ValueError:
            pass
    return ips

def parse_hashes(content):
    text = content.decode("utf-8", "ignore") if isinstance(content, (bytes, bytearray)) else (content or "")
    sha = {m.lower() for m in re.findall(r"\b[a-fA-F0-9]{64}\b", text)}
    md5 = {m.lower() for m in re.findall(r"\b[a-fA-F0-9]{32}\b", text)}
    return sha, md5
```
Then `class ThreatIntelligence(BaseService)`: `name="ThreatIntelligence"`, `__init__` grabs `self.store = get_intel_store()` (or from config). `_run`: load persisted blocklist file (`IPS_FILE_PATH`) into the store; loop `while not self._stopping()`: for each feed due per `UPDATE_INTERVAL_HOURS`, fetch (guarded HTTP via `requests`/`urllib`), `parse_ip_list`/`parse_hashes`, `store.add_bad_ips/add_bad_hashes(..., source=name)`, persist, `emit_threat(SYSTEM, INFO, "Threat feed updated", detail)`; `self._heartbeat()`; `self._sleep(check_interval)`. Feeds and their URLs come from the existing `FEEDS` config (Feodo/CINS/URLhaus/MalwareBazaar). Every fetch is `try/except` (dead feed → log + skip). Keep `lookup_ip_abuseipdb`.

- [ ] **Step 4: Run to green** — `.venv/Scripts/python.exe -m pytest tests/services/test_threat_intelligence.py -q` → 3 passed. (Tests do NOT hit the network — only the pure parsers.)

- [ ] **Step 5: Commit**

```bash
git add Services/SentinelThreatIntelligence.py tests/services/test_threat_intelligence.py
git commit -m "Phase 3A Task 2: ThreatIntelligence rewrite (BaseService, feeds -> ThreatIntelStore)"
```

---

### Task 3: NetworkProtection rewrite

**Files:**
- Rewrite: `Services/Protection/SentinelNetProtectionNG2.py`
- Test: `tests/services/test_network_protection.py`

**Interfaces:**
- Consumes: `BaseService`, `ThreatIntelStore`, `Services.SentinelBrain.ThreatSeverity`.
- Produces: `class NetworkProtection(BaseService)` (`name="NetProtection"`); pure `classify_connection(conn: dict, intel, cfg: dict) -> (action: str, reason: str, severity)` where `conn={raddr_ip, raddr_port, laddr_port, pid, status}`, `action ∈ {"clean","alert","block"}`; helper `is_private_or_local(ip) -> bool`.

- [ ] **Step 1: Write the tests** (pin the classifier)

`tests/services/test_network_protection.py`:
```python
from Services.Protection.SentinelNetProtectionNG2 import classify_connection, is_private_or_local
from Services.Protection.threat_intel_store import ThreatIntelStore
from Services.SentinelBrain import ThreatSeverity

CFG = {"whitelist": set(), "rep_block_threshold": 80, "rep_alert_threshold": 50,
       "suspicious_ports": {4444, 1337}}

def test_private_and_loopback_skipped():
    assert is_private_or_local("192.168.1.5") and is_private_or_local("127.0.0.1")
    assert is_private_or_local("8.8.8.8") is False
    intel = ThreatIntelStore()
    action, _, _ = classify_connection({"raddr_ip": "10.0.0.9", "raddr_port": 443}, intel, CFG)
    assert action == "clean"

def test_ioc_match_blocks():
    intel = ThreatIntelStore(); intel.add_bad_ips({"185.220.1.1"}, "feodo")
    action, reason, sev = classify_connection({"raddr_ip": "185.220.1.1", "raddr_port": 443}, intel, CFG)
    assert action == "block" and sev == ThreatSeverity.HIGH

def test_high_reputation_blocks():
    intel = ThreatIntelStore(); intel.set_reputation("9.9.9.9", 90)
    action, _, sev = classify_connection({"raddr_ip": "9.9.9.9", "raddr_port": 443}, intel, CFG)
    assert action == "block"

def test_mid_reputation_alerts():
    intel = ThreatIntelStore(); intel.set_reputation("9.9.9.8", 60)
    action, _, sev = classify_connection({"raddr_ip": "9.9.9.8", "raddr_port": 443}, intel, CFG)
    assert action == "alert" and sev == ThreatSeverity.MEDIUM

def test_suspicious_port_alerts():
    intel = ThreatIntelStore()
    action, reason, _ = classify_connection({"raddr_ip": "9.9.9.7", "raddr_port": 4444}, intel, CFG)
    assert action == "alert" and "port" in reason.lower()

def test_whitelisted_ip_clean():
    intel = ThreatIntelStore(); intel.add_bad_ips({"9.9.9.6"}, "x")
    cfg = dict(CFG); cfg["whitelist"] = {"9.9.9.6"}
    action, _, _ = classify_connection({"raddr_ip": "9.9.9.6", "raddr_port": 4444}, intel, cfg)
    assert action == "clean"

def test_benign_public_clean():
    intel = ThreatIntelStore()
    action, _, _ = classify_connection({"raddr_ip": "8.8.8.8", "raddr_port": 443}, intel, CFG)
    assert action == "clean"
```

- [ ] **Step 2: Run to fail** → import errors.

- [ ] **Step 3: Implement**
```python
import ipaddress
from Services.framework.base_service import BaseService
from Services.SentinelBrain import ThreatCategory, ThreatSeverity

def is_private_or_local(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified
    except ValueError:
        return True   # unparseable -> non-actionable

def classify_connection(conn, intel, cfg):
    ip = conn.get("raddr_ip")
    if not ip or is_private_or_local(ip) or ip in cfg.get("whitelist", set()):
        return ("clean", "", ThreatSeverity.INFO)
    if intel.is_bad_ip(ip):
        return ("block", f"IOC feed match: {ip}", ThreatSeverity.HIGH)
    rep = intel.ip_reputation(ip)
    if rep is not None:
        if rep >= cfg.get("rep_block_threshold", 80):
            return ("block", f"AbuseIPDB reputation {rep}%", ThreatSeverity.HIGH)
        if rep >= cfg.get("rep_alert_threshold", 50):
            return ("alert", f"AbuseIPDB reputation {rep}%", ThreatSeverity.MEDIUM)
    port = conn.get("raddr_port")
    if port in cfg.get("suspicious_ports", set()):
        return ("alert", f"suspicious destination port {port}", ThreatSeverity.MEDIUM)
    return ("clean", "", ThreatSeverity.INFO)
```
Then `class NetworkProtection(BaseService)` (`name="NetProtection"`): `__init__` config defaults (`whitelist`, thresholds, `suspicious_ports={4444,1337,3389,5900,23,...}`, `poll_interval=5.0`, `action="auto"`), `self.store = get_intel_store()`. `_run`: poll `psutil.net_connections(kind="inet")` (guarded; AccessDenied → log once + degrade), build `conn` dicts, dedupe by remote IP per cycle, call `classify_connection`; on `block` → `self._firewall_block(ip)` + `emit_threat(NETWORK, sev, "Malicious connection blocked", reason, ip_address=ip, pid=...)`; on `alert` → emit only (no block). Kick an async AbuseIPDB lookup (via `ThreatIntelligence.lookup_ip_abuseipdb`) for unknown public IPs, storing results in `self.store.set_reputation`. Also a simple per-IP connection **velocity** check in `_run` (new outbound IPs over a threshold in a window) → alert. `_firewall_block(ip)`: `netsh advfirewall firewall add rule ... dir=out/in remoteip=<ip> action=block` (port both directions), guarded, `CREATE_NO_WINDOW`. Delete ALL old ML/CSV/pandas/joblib code.

- [ ] **Step 4: Run to green** — `.venv/Scripts/python.exe -m pytest tests/services/test_network_protection.py -q` → 7 passed. Confirm no `joblib`/`sklearn`/`pandas`/`.pkl` import remains: `grep -nE "joblib|sklearn|pandas|\.pkl|Data_Files" Services/Protection/SentinelNetProtectionNG2.py` → empty.

- [ ] **Step 5: Commit**

```bash
git add Services/Protection/SentinelNetProtectionNG2.py tests/services/test_network_protection.py
git commit -m "Phase 3A Task 3: NetworkProtection rewrite (IOC/reputation/heuristic, no ML)"
```

---

### Task 4: PSDS rewrite

**Files:**
- Rewrite: `Services/Protection/Sentinelpsds.py`
- Test: `tests/services/test_psds.py`

**Interfaces:**
- Consumes: `BaseService`.
- Produces: `class PSDS(BaseService)` (`name="PSDS"`); pure `class SynRateTracker` with `__init__(threshold=50, window=1.0)`, `record(ip, ts)`, `exceeded(ip, now) -> bool`.

- [ ] **Step 1: Write the tests**

`tests/services/test_psds.py`:
```python
from Services.Protection.Sentinelpsds import SynRateTracker, PSDS

def test_syn_rate_tracker_threshold():
    t = SynRateTracker(threshold=5, window=10)
    for i in range(4):
        t.record("1.2.3.4", i)
    assert t.exceeded("1.2.3.4", now=4) is False
    t.record("1.2.3.4", 5)
    assert t.exceeded("1.2.3.4", now=5) is True

def test_syn_rate_window_expiry():
    t = SynRateTracker(threshold=3, window=5)
    for i in range(3):
        t.record("1.2.3.4", i)          # ts 0,1,2
    assert t.exceeded("1.2.3.4", now=100) is False   # all outside a 5s window

def test_unknown_ip_not_exceeded():
    t = SynRateTracker(threshold=1, window=1)
    assert t.exceeded("9.9.9.9", now=0) is False

def test_psds_degrades_without_pydivert(fake_brain, monkeypatch):
    # simulate pydivert unavailable -> service must not raise, stays alive
    import Services.Protection.Sentinelpsds as psds_mod
    monkeypatch.setattr(psds_mod, "pydivert", None, raising=False)
    p = PSDS(brain=fake_brain)
    p.start()
    import time; time.sleep(0.1)
    assert p.is_running() is True          # inert but alive, not ERROR
    p.stop()
```

- [ ] **Step 2: Run to fail** → import errors.

- [ ] **Step 3: Implement**
```python
from collections import defaultdict, deque
from Services.framework.base_service import BaseService
from Services.SentinelBrain import ThreatCategory, ThreatSeverity

try:
    import pydivert
except Exception:
    pydivert = None

class SynRateTracker:
    def __init__(self, threshold=50, window=1.0):
        self.threshold = threshold
        self.window = window
        self._syns = defaultdict(deque)
    def record(self, ip, ts):
        self._syns[ip].append(ts)
    def exceeded(self, ip, now):
        q = self._syns.get(ip)
        if not q:
            return False
        cutoff = now - self.window
        while q and q[0] <= cutoff:
            q.popleft()
        return len(q) >= self.threshold
```
Then `class PSDS(BaseService)` (`name="PSDS"`): config `syn_rate_threshold`, `window`. `_run`: if `pydivert is None` OR not admin → `self._log("WinDivert/admin unavailable; PSDS idle", "WARN")`, set a health note, then idle (`while not self._stopping(): self._sleep(1)`), staying RUNNING but inert. Else open `pydivert.WinDivert("tcp.Syn and inbound")`, read packets until `_stopping()`, `tracker.record(src_ip, time)`, and when `tracker.exceeded(src_ip, now)` → drop the packet, `_firewall_block(src_ip)`, `emit_threat(NETWORK, HIGH, "SYN flood / port scan", detail, ip_address=src_ip)`. `_teardown` closes the WinDivert handle. All packet-loop work exception-isolated.

- [ ] **Step 4: Run to green** — `.venv/Scripts/python.exe -m pytest tests/services/test_psds.py -q` → 4 passed, pristine.

- [ ] **Step 5: Commit**

```bash
git add Services/Protection/Sentinelpsds.py tests/services/test_psds.py
git commit -m "Phase 3A Task 4: PSDS rewrite (WinDivert SYN/scan + graceful degradation)"
```

---

### Task 5: Orchestration + retire the .pkl zoo

**Files:**
- Modify: `Services/SentinelService_v2.py`, `requirements.txt`, `scripts/verify_reachability.py`
- Move: `models/*.pkl` + `models/Data_Files/*.csv` → `cleanup/phase3a-network-pkl/`
- Test: extend `tests/services/test_orchestration.py`

- [ ] **Step 1: Add dep** — `.venv/Scripts/python.exe -m pip install pydivert 2>&1 | tail -2` (if it fails to build/needs the driver, that's fine — PSDS degrades; still add `pydivert  # WinDivert SYN/scan defense (PSDS); optional, degrades gracefully` to `requirements.txt`).

- [ ] **Step 2: Rewire orchestration** — in `Services/SentinelService_v2.py`, replace the `_NetThread`/`_PsdsThread`/`_IntelThread` `_ModuleThread` wrappers with `_ServiceHolder` wrapping `ThreatIntelligence()`, `NetworkProtection()`, `PSDS()` (the new `BaseService` classes). Construct `ThreatIntelligence` BEFORE `NetworkProtection` so the shared store is live. Leave the other clusters' wrappers untouched.

- [ ] **Step 3: Retire the pickle zoo**

```bash
cd "D:/ZashironSentinel"
mkdir -p cleanup/phase3a-network-pkl/models/Data_Files
git mv models/nids_model.pkl models/nids_scaler.pkl models/nids_label_encoder.pkl \
       models/network_autoencoder.pkl models/network_isoforest.pkl models/network_scaler.pkl \
       models/malware_detector.pkl models/phishing_detector.pkl models/phishing_vectorizer.pkl \
       cleanup/phase3a-network-pkl/models/
git mv models/Data_Files/network_traffic.csv models/Data_Files/Train_data.csv \
       cleanup/phase3a-network-pkl/models/Data_Files/
```
Confirm none are still imported: `grep -rInE "nids_model|network_isoforest|malware_detector\.pkl|phishing_detector|Data_Files" --include=*.py Services/ | grep -v cleanup` → empty.

- [ ] **Step 4: Extend the orchestration test**

Append to `tests/services/test_orchestration.py`:
```python
def test_network_services_start_stop(fake_brain):
    from Services.SentinelThreatIntelligence import ThreatIntelligence
    from Services.Protection.SentinelNetProtectionNG2 import NetworkProtection
    from Services.Protection.Sentinelpsds import PSDS
    svcs = [ThreatIntelligence(brain=fake_brain), NetworkProtection(brain=fake_brain), PSDS(brain=fake_brain)]
    for s in svcs: s.start()
    assert all(s.is_running() for s in svcs)
    for s in svcs: s.stop()
    assert not any(s.is_running() for s in svcs)
```

- [ ] **Step 5: Verify suite + reachability + boot**

Run: `.venv/Scripts/python.exe -m pytest tests/services/ -q` → all pass.
Run: `.venv/Scripts/python.exe scripts/verify_reachability.py` — set `EXPECTED_LIVE` to the printed value (the store + rewritten services shift the graph), re-run → PASS.
Boot: `SENTINEL_NO_ELEVATE=1 timeout 120 .venv/Scripts/python.exe -c "import os,sys,threading,time,urllib.request,importlib.util; os.environ['SENTINEL_NO_ELEVATE']='1'; sys.argv=['x','--no-elevate']; os.chdir(r'D:/ZashironSentinel'); sys.path.insert(0,r'D:/ZashironSentinel'); spec=importlib.util.spec_from_file_location('e','SentinelUI_Flask.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); threading.Thread(target=m._start_flask,daemon=True).start(); time.sleep(12); print('HTTP', urllib.request.urlopen('http://127.0.0.1:8765',timeout=5).status); os._exit(0)" 2>&1 | grep -E "HTTP|Traceback|Error"` → `HTTP 200`.

- [ ] **Step 6: Commit**

```bash
git add Services/SentinelService_v2.py requirements.txt scripts/verify_reachability.py tests/services/test_orchestration.py cleanup/phase3a-network-pkl/
git commit -m "Phase 3A Task 5: wire network services into registry; retire .pkl zoo + CSVs"
```

---

## Self-Review

- **Spec coverage:** §2.1 store → T1. §3.1 ThreatIntelligence + parsers → T2. §3.2 NetworkProtection + classify_connection → T3. §3.3 PSDS + SynRateTracker + graceful degradation → T4. §4 orchestration + retirement → T5. §6 synthetic testing → each task's tests. §7 pydivert dep → T5/T4. All covered.
- **Placeholder scan:** store, all pure fns (`parse_ip_list`/`parse_hashes`/`classify_connection`/`is_private_or_local`/`SynRateTracker`), and ALL tests are complete code. The `_run` feed/poll/WinDivert loop bodies are precisely specified (standard wiring pinned by the pure-logic tests) — no vague "add error handling".
- **Type consistency:** `classify_connection(conn, intel, cfg) -> (action:str, reason:str, ThreatSeverity)` T3. `SynRateTracker(threshold, window).record/exceeded` T4. store API identical T1↔T2↔T3. `is_private_or_local(ip)->bool` T3.
- **Known coupling:** T5 `EXPECTED_LIVE` computed at execution (intentional). `pydivert` install may fail (no driver) — PSDS degrades, so the plan doesn't gate on it.
