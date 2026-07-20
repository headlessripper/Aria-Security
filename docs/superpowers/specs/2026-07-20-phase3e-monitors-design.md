# Phase 3E — Extract Tier-2 UI Feature Logic — Design

**Date:** 2026-07-20
**Status:** Design (user delegated: "do what you think is right") → implementation plan.
**Context:** Phase 3 (protection/support services) is complete (origin/main tip `2aa57a2`). `SentinelUI_Flask.py` is a 1,920-line god-file: 87 routes, several of which carry real business logic inline. Phase 3E extracts the **Tier-2 UI-backed monitoring features** into clean, tested modules, slimming the entry file ahead of Phase 5 (Swiss UI). Master spec: `2026-07-17-zashiron-rebuild-design.md`.

---

## 1. Scope

Extract the inline business logic from the Tier-2 monitoring/system routes into a new `Services/monitors/` package. **Routes become thin HTTP adapters** (parse request → call module fn → `jsonify`). This is a *refactor with no behavior change* — every endpoint returns the same JSON shape it does today.

**Routes in scope (~14):**
- `/api/memory` (GET), `/api/memory/scan` (POST, threaded+socketio), `/api/memory/clean` (POST, ctypes)
- `/api/process_threats` (GET)
- `/api/tasks` (GET), `/api/tasks/<pid>/kill` (POST)
- `/api/network/connections` (GET), `/api/net_scope` (GET)
- `/api/geo_blocks` (GET/POST)
- `/api/storage` (GET)
- `/api/console/logs` (GET), `/api/console/clear` (POST)

**Explicitly OUT of scope (stay in the Flask file, already clean):**
- `/api/threat_intel/stats` and `/api/network/events` — thin reads over `SentinelBrain` (already a clean module); nothing to extract.
- **Action Center** — a UI view over `SentinelBrain`'s threat log; no backend logic to extract.
- Argus chat / settings / about / network-tools (ping/traceroute) routes — belong to Phase 4/5.
- The kernel driver (final phase). **No new dependencies** (`psutil`, `ctypes`, stdlib only).

---

## 2. Package: `Services/monitors/`

Mirrors the existing `Services/Protection/` and `Services/Sense/` subpackage style. These are **on-demand inspectors called by routes**, NOT `BaseService`s (no background loop). Each module returns plain JSON-ready `dict`/`list`; **no module imports Flask, socketio, or the brain** — cross-cutting concerns are injected via callbacks.

### 2.1 `system_monitor.py` — memory + storage
- `memory_snapshot() -> dict` — `psutil.virtual_memory()` totals + this-process RSS + top-20 processes by RSS. (Was `/api/memory`.)
- `trim_working_sets() -> dict` — the `/api/memory/clean` ctypes logic (`SetProcessWorkingSetSize` over all accessible PIDs); returns `{"cleaned": int, "skipped": int}`.
- `list_disks() -> list[dict]` — `psutil.disk_partitions` + `disk_usage` per mount. (Was `/api/storage`.)

### 2.2 `process_monitor.py` — process/task inspection + risk scoring
- **`risk_score(name: str, exe: str, ppid: int) -> int` (PURE)** — the heuristic scorer (name keywords, orphan-parent, missing-exe, temp-dir, short-name), capped at 100. Unit-tested directly.
- `process_threats() -> list[dict]` — iterates `psutil`, applies `risk_score`, returns top-200 by score. (Was `/api/process_threats`.)
- `task_list() -> list[dict]` — full process list (pid/name/status/cpu/mb/path), top-300 by RSS. (Was `/api/tasks`.)
- `kill(pid: int) -> dict` — `psutil.Process(pid).terminate()`; returns status or a typed not-found/error dict. (Was `/api/tasks/<pid>/kill`.)

### 2.3 `mem_scan.py` — the threaded memory scan (decoupled)
- `scan_processes(scanner, on_progress=None, on_threat=None) -> list[dict]` — iterates processes, calls `scanner.scan_file(exe)`, collects `MALWARE`/`SUSPICIOUS` verdicts. `on_progress(checked, total)` and `on_threat(result_row)` are optional callbacks. **No socketio/brain import** — the route passes callbacks that emit socketio progress and fire the brain `ThreatEvent`. The per-process verdict decision is testable with a fake scanner.
- The route keeps ownership of the `threading.Thread`, the `_mem_scan_running` guard, and the terminal `memory_scan_done` emit.

### 2.4 `netstat.py` — network inspection
- `connections() -> list[dict]` — `psutil.net_connections(kind="inet")` with resolved process names, top-200. (Was `/api/network/connections`.)
- `interface_counters() -> dict` — `psutil.net_io_counters(pernic=True)` per-NIC bytes/packets/drops. (Was `/api/net_scope`.)

### 2.5 `console_logs.py` — log aggregation
- `tail(log_dir, log_files, lines, module="") -> list[str]` — reads the tail of each matching log file, prefixes `[stem]`, filters by `module` substring, returns last `lines`. Testable with a `tmp_path` log dir.
- `clear(log_dir, log_files, module="") -> int` — truncates matching log files; returns count. Testable with `tmp_path`.
- (`log_dir`/`log_files` are injected by the route from the existing module-level `_LOG_DIR`/`_LOG_FILES` so the module stays path-agnostic and testable.)

### 2.6 `geo_blocks.py` — geo-block persistence
- `load(path) -> dict` — read JSON (missing → `{}`).
- `save(path, data) -> None` — atomic write (temp + `os.replace`), parents created. Round-trip testable with `tmp_path`.

---

## 3. Route rewrite pattern

Each in-scope route in `SentinelUI_Flask.py` collapses to:
```python
@app.route("/api/storage")
def api_storage():
    try:
        return jsonify(system_monitor.list_disks())
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```
The memory-scan route retains its threading + socketio wiring but delegates the loop:
```python
def _do():
    try:
        rows = mem_scan.scan_processes(scanner,
            on_progress=lambda c, t: socketio.emit("memory_scan_progress", {...}),
            on_threat=lambda row: (_emit_brain_event(row), ...))
        socketio.emit("memory_scan_done", {"results": rows, ...})
    finally:
        _mem_scan_running["active"] = False
```

---

## 4. Testing (synthetic — no reliance on this machine's live process table)

`tests/services/test_monitors.py` (or per-module files under `tests/services/`):
- **`risk_score`** — boundary/aggregation cases (miner keyword, orphan ppid, missing exe, temp path, short name; cap at 100; benign → 0).
- **`scan_processes`** — a fake `scanner` returning scripted verdicts + a fake process list (monkeypatched `psutil.process_iter`) → asserts only MALWARE/SUSPICIOUS collected and `on_progress`/`on_threat` invoked.
- **`console_logs.tail`/`clear`** — `tmp_path` log dir, module filter, line-limit.
- **`geo_blocks.load`/`save`** — round-trip + missing-file → `{}` against `tmp_path`.
- **Collectors** (`memory_snapshot`, `list_disks`, `connections`, `interface_counters`, `task_list`, `process_threats`) — `psutil` monkeypatched with fakes; assert the JSON shape/keys and sorting/limits. `trim_working_sets`/`kill` — `ctypes`/`psutil` mocked; assert counts and typed error dicts (no real process termination).

---

## 5. Orchestration & error handling

No service registry changes (these aren't services). Routes keep the existing `try/except → jsonify({"error"}, 500)` contract. Every collector fails safe per-item (`NoSuchProcess`/`AccessDenied`/`PermissionError` swallowed per element, matching today's behavior). `geo_blocks.save` is atomic so a crash can't corrupt the file.

---

## 6. Verification

- `python -m pytest tests/services/ -q` → green (existing 99 + new).
- `scripts/verify_reachability.py` → the new `Services/monitors/*` modules become LIVE (imported by the entry file); bump `EXPECTED_LIVE` to the printed value and re-run → PASS.
- Headless boot → HTTP 200.
- Spot-check `/api/storage`, `/api/process_threats`, `/api/net_scope` return the same shape as before the refactor.

---

## 7. Deferred / future

- Phase 4 (Argus assistant), Phase 5 (Swiss #000/#FFF UI).
- Then real EMBER training (mid-size test → full EMBER 2018) + the C++ minifilter driver (final phase).
- Follow-up carried from 3C: retire the now-dead `UsbAllowlistPage.py`.
