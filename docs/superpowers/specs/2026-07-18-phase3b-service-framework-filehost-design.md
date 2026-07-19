# Phase 3B — Service Framework + File/Host Protection — Design

**Date:** 2026-07-18
**Status:** Design (awaiting user review) → implementation plan.
**Context:** First sub-project of Phase 3 (protection-services revamp). Order: **3B (this) → 3A network → 3C device/discovery → 3D support.** Depth: full clean-slate rewrite of every service (user-approved). Master spec: `2026-07-17-zashiron-rebuild-design.md`.

---

## 1. Scope

Phase 3 rewrites the ~13 protection services. The Python→exe→Python anti-pattern is already gone (services run as in-process daemon threads via `SentinelService_v2`), so Phase 3 is about **reforging service logic to be robust and real-world-effective** on a clean shared framework.

**This sub-project (3B)** delivers:
1. **`BaseService` framework** — the uniform contract every rewritten service (all clusters) is built on.
2. Full rewrites of the **file/host protection** cluster on that framework: **RansomProtection, ExploitProtection, BehavioralEngine**.
3. Refactor of `SentinelService_v2` orchestration to a uniform service registry.

**Out of scope / boundaries:**
- `AVBrain` (ARIA) = Phase 4. `SentinelBrain` (event bus) is kept as-is and consumed, not rewritten.
- **Kernel-grade telemetry** (true injection/ETW/minifilter detection) belongs to the **C++ minifilter driver (`Plugins/Filter/`), a planned FINAL phase** after all Python phases + a trained production model. This rewrite delivers robust **user-mode** detection; each service documents where kernel telemetry would extend it.

---

## 2. `BaseService` Framework (`Services/framework/base_service.py`)

Every protection service subclasses `BaseService`, giving uniform lifecycle, Brain integration, health, and testability.

```
class ServiceState(Enum): STOPPED, STARTING, RUNNING, STOPPING, ERROR

class BaseService(ABC):
    name: str                      # brain module name, e.g. "RansomProtection"
    def __init__(self, config: dict | None = None, brain=None): ...   # brain defaults to get_brain(); injectable for tests
    # lifecycle (all idempotent)
    def start(self) -> None        # STARTING → spawn daemon worker → RUNNING → brain.set_module_running(name, True)
    def stop(self, timeout=5) -> None   # STOPPING → stop_event.set() → _teardown() → join(timeout) → STOPPED → set_module_running(name, False)
    def is_running(self) -> bool
    def health(self) -> dict       # {state, last_heartbeat_ts, error, detail}
    # subclass hooks
    @abstractmethod
    def _run(self) -> None         # worker body; loop while not self._stopping(); MUST return promptly on stop
    def _teardown(self) -> None    # optional cleanup (unhook observers etc.); default no-op
    # helpers provided to subclasses
    def _stopping(self) -> bool                      # self._stop_event.is_set()
    def _sleep(self, seconds: float) -> bool         # interruptible; returns False if stopped during sleep
    def _heartbeat(self) -> None                     # update last_heartbeat_ts (health)
    def emit_threat(self, category, severity, detail: str, source: str | None = None, meta: dict | None = None) -> None
                                                     # builds ThreatEvent(category, severity, ...) → brain.emit_event
    def emit_block(self, ip: str, reason: str) -> None
    def _log(self, msg: str, level: str = "INFO") -> None
```

Guarantees:
- **Exception isolation:** `_run` is invoked inside a guard; an unhandled exception sets `ERROR` state + logs, and (per policy) may auto-restart with backoff — it never crashes the process or other services.
- **Clean stop:** `stop()` signals `_stop_event`, calls `_teardown`, joins with timeout; a service that ignores the stop signal is force-abandoned after timeout (daemon thread) and logged.
- **Brain-optional:** with an injected fake brain, services are unit-testable with zero Qt/OS coupling.

`Services/framework/__init__.py` re-exports `BaseService`, `ServiceState`.

---

## 3. Service Rewrites

### 3.1 RansomProtection (`Services/Protection/SentinelRansomProtection.py`)
Real-time file-system defense. Watches configured dirs (`watch_dirs`) via **`watchdog`** (ReadDirectoryChangesW under the hood). Four independent detectors, any of which trips:
1. **Mass-change velocity** — > `velocity_threshold` file modify/rename/delete events within `window_seconds` (default 30 in 5s).
2. **Entropy spike** — on write, sample first `entropy_sample_bytes` (default 8192); Shannon entropy ≥ `entropy_threshold` (default 7.8) flags likely encryption; many concurrent high-entropy writes → trip.
3. **Canary tripwire** — hidden honeypot files (`canary_count`, default 3) seeded in watched dirs; ANY modify/delete/rename of a canary → immediate CRITICAL (highest confidence).
4. **Known ransom extensions** — new files with extensions in a configurable set (`.locked`, `.crypto`, `.enc`, `.ryk`, …) → trip.

**On trip:** `emit_threat(RANSOMWARE, CRITICAL, detail, source=<path/proc>)`; best-effort identify the offending process (recent writer to the watched tree via psutil, or the process holding the canary handle) and, if `action` config allows, `psutil.Process.suspend()` it; optionally quarantine touched files. All thresholds/actions are config. State persisted to `~/.AriaSecurity/ransom_state.json` for the UI.

### 3.2 ExploitProtection (`Services/Protection/SentinelExploitProtection.py`)
User-mode process-behavior heuristics via `psutil` polling (interval config). Detectors:
1. **Suspicious parent→child chains** — office/browser/PDF apps spawning `cmd`/`powershell`/`wscript`/`mshta`/`regsvr32`/`rundll32` → HIGH.
2. **LOLBin abuse** — known living-off-the-land binaries with hostile arg patterns (`powershell -enc/-nop/-w hidden`, `mshta http`, `regsvr32 /i:http`, `rundll32 …javascript:`) → HIGH.
3. **Untrusted execution location** — new processes running from `%TEMP%`/Downloads/`%APPDATA%` whose image is not validly signed (reuses `Engine.Detection.cert_reputation.CertReputation`) → MEDIUM→HIGH.
4. **(Documented limitation)** true cross-process injection (RWX + remote thread) needs the kernel driver; a best-effort psutil heuristic is included and explicitly labeled limited.

**On trip:** `emit_threat(EXPLOIT, HIGH|CRITICAL, detail, source=<pid/image>, meta={ppid, cmdline})`. Config-driven rules so the chains/LOLBins are tunable.

### 3.3 BehavioralEngine (`Services/SentinelBehavioralEngine.py`)
A real rule engine over a live event stream. Schema (`Engine/Rules/behavioral_rules.json`):
```
{ "rules": [ {
    "id": "R001", "name": "...", "severity": "HIGH", "category": "BEHAVIORAL",
    "event": "process_start" | "file_write" | "registry_set" | "net_connect",
    "conditions": [ {"field": "image"|"cmdline"|"path"|"parent"|"key"|"remote_ip"|..., "op": "eq"|"contains"|"regex"|"in"|"startswith", "value": ...} ],
    "window_seconds": <int|null>, "threshold": <int>   // fire when >= threshold matches in window (null window = per-event)
} ] }
```
The engine builds a live event stream (process starts + net connections via `psutil` polling; extensible to file/registry) and evaluates each rule; on match (single event, or `threshold` matches within `window_seconds`) → `emit_threat(BEHAVIORAL, <rule severity>, rule.name, meta=<matched event>)`. Ships a starter ruleset. Malformed rules are skipped with a log (never crash the engine).

---

## 4. Orchestration refactor (`Services/SentinelService_v2.py`)
Replace the ad-hoc `_ModuleThread` wrappers for the 3B services with a uniform registry: a dict of `name → BaseService instance`; `start_all`/`stop_all`/`status` iterate the uniform interface. The other (not-yet-rewritten) services keep their current wrappers until their cluster's sub-phase — the registry holds both kinds behind an adapter so nothing breaks mid-migration.

---

## 5. Data flow & error handling
**Flow:** OS event (watchdog/psutil) → detector → `BaseService.emit_threat(...)` → `SentinelBrain.emit_event(ThreatEvent)` → protection-level recompute + UI. **Errors:** each detector call is exception-isolated; `_run` guarded (ERROR state + backoff restart); Brain calls best-effort; a failed OS hook (e.g. watchdog can't watch a path) logs + continues on the paths it can watch. Stop is cooperative with a hard timeout.

## 6. Testing (synthetic triggers — no real malware)
- **BaseService:** lifecycle (start→running→stop→stopped, idempotency), stop responsiveness (worker exits within timeout), brain registration calls, `emit_threat` builds the right `ThreatEvent`, exception in `_run` → ERROR not crash. Fake brain records calls.
- **RansomProtection:** temp dir + fake brain → (a) create N files fast → velocity trip; (b) write high-entropy data → entropy trip; (c) touch a canary → immediate CRITICAL; (d) create `.locked` file → trip. Assert `emit_threat(RANSOMWARE, CRITICAL/…)` called.
- **ExploitProtection:** feed synthetic process records (monkeypatch the psutil enumeration) representing an office→powershell chain and a LOLBin cmdline → assert HIGH emitted; benign chain → no emit.
- **BehavioralEngine:** load a test ruleset; feed matching + non-matching synthetic events (single-event and windowed-threshold) → assert correct emits; malformed rule → skipped, engine still runs.

## 7. Dependencies
Add `watchdog` (file-system events). Already present: `psutil`, `pefile`, and `Engine.Detection.cert_reputation` (reused by ExploitProtection).

## 8. Deferred / future
- Remaining Phase 3 clusters: 3A (network + retire `.pkl` zoo), 3C (device/discovery), 3D (support).
- **C++ minifilter driver (`Plugins/Filter/`)** — the FINAL phase, after all Python phases + trained test/production models; provides kernel-grade telemetry that extends ExploitProtection (real injection detection) and RansomProtection (pre-write blocking).
