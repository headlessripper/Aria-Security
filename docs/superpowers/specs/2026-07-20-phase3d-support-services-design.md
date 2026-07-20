# Phase 3D — Support Services — Design

**Date:** 2026-07-20
**Status:** Design (awaiting user review) → implementation plan.
**Context:** Final cluster of Phase 3 (3B, 3A, 3C done → **3D (this)**). Master spec: `2026-07-17-zashiron-rebuild-design.md`. After 3D: **Phase 3E** extracts the Tier-2 UI-backed feature logic (memory/process/connections/geo-block/storage/console/action-center) out of the 1,920-line Flask app into clean modules.

---

## 1. Scope

The six support services. Unlike 3B/3A/3C, **only one (Scheduler) is a background service**; the other five are passive utilities called on-demand by the scan/quarantine flow. So this is a **harden-and-modernize** pass, not from-scratch rewrites — the cores are mostly sound (SecureVault uses real Fernet+PBKDF2; ScanHistory uses parameterized SQL).

- **Scheduler → `BaseService`** (the one real background service).
- **SecureVault, ScanHistory, Whitelist, CloudAnalysis, Sandbox → clean, hardened modules** (NOT `BaseService` — they have no loop). Keep the solid cores, fix concrete gaps, add real tests.

**Out of scope:** Tier-2 UI-backed features (→ Phase 3E); the kernel driver (final phase). No new dependencies.

---

## 2. Scheduler → `BaseService` (`Services/SentinelScheduler.py`)

`BaseService`, `name="Scheduler"`. Replaces the raw `SchedulerThread(threading.Thread)` + the stale QThread reference.
- **Pure core (test-pinned):** `due_schedules(schedules: list[dict], now: float) -> list[dict]` — returns schedules whose `next_run <= now` and are `enabled`.
- `_run`: loop with interruptible `_sleep(check_interval=60)`; each tick `for s in due_schedules(load_schedules(), time.time())`: fire the scan (call the injected `on_scan_due(schedule_id, scan_path)` callback, default = run `Engine.Compiler.SentinelCompiler_v5.VirusScanner` over `scan_path`), then `update_last_run(sid, interval_hours)` (recompute `next_run`). Exception-isolated per schedule.
- Keeps `load_schedules`/`save_schedules`/`add_schedule`/`update_last_run` module fns (the Flask UI calls them). Persisted to `~/.AriaSecurity/schedules.json`.

---

## 3. Utility hardening (clean modules — concrete fixes)

### 3.1 SecureVault (`Services/SentinelSecureVault.py`)
Keep Fernet + PBKDF2 per-file-key design. Fixes:
- **Wrong password** → catch `InvalidToken` in `extract`, return a clear failure (raise `VaultError`/return None) — never a raw traceback.
- **Atomic writes** — encrypt to a temp file then `os.replace` into place, so a crash mid-write can't corrupt the vault; only `delete_original` AFTER a verified successful encrypt.
- Tests: add→extract round-trip (correct password recovers bytes); wrong password → clean failure; `list_files`/`delete`/`vault_size_bytes`. Uses a `tmp_path` vault dir + a test password.

### 3.2 ScanHistory (`Services/SentinelScanHistory.py`)
Keep parameterized SQL. Fixes:
- **Thread safety** — a fresh `sqlite3.connect(..., check_same_thread=False)` per call OR a locked shared connection; enable **WAL** (`PRAGMA journal_mode=WAL`) for concurrent scanner writes + UI reads.
- Robust `record` (missing result keys default safely).
- Tests: `record`→`query` round-trip; verdict filter; `search` LIKE; `stats`; `clear` — against a `tmp_path` DB.

### 3.3 Whitelist (`Services/SentinelWhitelist.py`)
Keep the singleton store. Fixes:
- **Normalization** — paths normalized (`os.path.normcase(os.path.abspath(...))`) so `is_whitelisted_file` matches regardless of case/slash; hashes lowercased; IPs validated.
- **Thread safety** — a lock around read/write; atomic JSON persist.
- Tests: add/query for file, dir (prefix match), ip, hash; normalization (mixed-case path matches); not-whitelisted returns False.

### 3.4 CloudAnalysis (`Services/SentinelCloudAnalysis.py`)
Keep the VirusTotal client. Fixes:
- **API-key absent** → `get_vt_client().lookup(...)` returns a defined "unavailable" `CloudVerdict` (not a crash).
- **Timeouts** on every `requests` call; robust response parsing (missing fields → unknown, not KeyError).
- **Rate limiter** made a pure, testable unit (`RateLimiter.allow(now) -> bool` for the free-tier 4/min).
- Tests: `RateLimiter` pure logic; `lookup` with mocked HTTP → parses malicious/clean/unknown; no-API-key → unavailable verdict; timeout/HTTP-error → unavailable, no raise.

### 3.5 Sandbox (`Services/SentinelSandbox.py`)
Keep Windows Sandbox (WSB) + restricted detonation. Fixes:
- **Graceful degradation** — `detonate(file)` checks `_is_wsb_available()`; if WSB is unavailable (Home edition / no Hyper-V), fall back to `run_restricted` or return a `SandboxReport(status="unavailable")` — never crash.
- **Pure core** — the process/connection snapshot diff (`diff_snapshots(before, after) -> {new_processes, new_connections}`) extracted + tested.
- Tests: `diff_snapshots` (pure); WSB-unavailable path → graceful `unavailable` report; `SandboxReport` shape. No real detonation in tests.

---

## 4. Orchestration
Wire **Scheduler** into `Services/SentinelService_v2.py` via `_ServiceHolder` (its `on_scan_due` triggers the shared `VirusScanner`). The 5 utilities are NOT registered as services — they stay module-level and are called by the scan/quarantine flow (VirusScanner → Whitelist/ScanHistory; quarantine → SecureVault; cloud second-opinion → CloudAnalysis; detonation → Sandbox). Fix any stale imports of the old Scheduler thread.

## 5. Data flow & error handling
**Flow:** Scheduler tick → due schedule → VirusScanner over path. On-demand: scanner queries Whitelist + records to ScanHistory; a flagged file → SecureVault quarantine, optional CloudAnalysis + Sandbox second opinions. **Errors:** every module fails safe (wrong password → clear error; missing API key/WSB → "unavailable"; DB locked → retried/WAL); Scheduler's per-schedule loop is exception-isolated; `BaseService` crash isolation for Scheduler.

## 6. Testing (synthetic — no real detonation/network/crypto secrets)
Pure cores (`due_schedules`, `RateLimiter.allow`, `diff_snapshots`, whitelist normalization) unit-tested directly; SecureVault round-trip with a temp vault; ScanHistory against a temp DB; CloudAnalysis/Sandbox with mocked HTTP/WSB. Scheduler `BaseService` lifecycle with a fake brain + injected `on_scan_due`.

## 7. Dependencies
None new (`cryptography`, `sqlite3`, `requests`, `psutil` all present).

## 8. Deferred / future
- **Phase 3E** — extract Tier-2 UI-backed feature logic (memory/process-threats/tasks/connections/geo-block/storage/console/action-center) out of `SentinelUI_Flask.py` into clean tested modules, slimming the god-file for Phase 5.
- Phase 4 (Argus), Phase 5 (Swiss UI), then the kernel minifilter driver (final phase) + real EMBER training.
