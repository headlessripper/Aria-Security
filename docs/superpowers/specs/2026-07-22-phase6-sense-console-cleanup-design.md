# Phase 6 — SentinelSense v2, In-App Console, Page Cleanup — Design

**Date:** 2026-07-22
**Status:** Design (user-approved decisions: passive watchers + registry correlation; permanent delete with hard safety rails) → implementation.
**Context:** All 5 rebuild phases + real EMBER model + the C++ minifilter are complete (main tip `c1ae8f4`). Three user-requested items, executed in this order.

---

## Item 1 — SentinelSense v2: install footprint tracking + residual cleanup

**Problem.** Today `SentinelSense` only polls the three Uninstall registry hives, diffs snapshots, and flags "residue" if an uninstalled app's install directory still exists. It does not track what an installer actually put on the machine.

**Goal (IObit-Uninstaller-like).** Track every file / directory / registry entry / log / temp file an application writes during install; keep a per-app **data tree** in `Sense_Map.json`; when an app is uninstalled and residuals remain, show the user that tree and offer cleanup. **Yes** → permanently delete. **No** → residuals stay on disk but remain tracked in `Sense_Map.json`.

### Capture model (approved): passive watchers + registry correlation

- **`Services/Sense/fs_journal.py`** — always-on `watchdog` observers on the tracked roots: `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramData%`, `%LOCALAPPDATA%`, `%APPDATA%`, `%TEMP%`. Every created file/dir is appended to a bounded in-memory journal as `(path, timestamp, is_dir)` (ring buffer, default 50k entries). Ignores Aria's own paths and `.git`.
- **Registry install/uninstall detection** — keep the existing hive polling (`diff_installs`) as the trigger.
- **`Services/Sense/attribution.py`** — **pure** `attribute(journal, app_info, installed_at, window_s) -> footprint`. A journal entry belongs to an app when it was created within `window_s` of the install AND (path is under the app's `install_location`, OR the path contains a normalized name token of the app or its publisher). Pure → directly unit-testable.
- Registry footprint: the app's own Uninstall key plus any `HKCU/HKLM Software\<Publisher|Name>` keys discovered at install time.

### Store — `Services/Sense/sense_map.py`

`ConversationStore`-style persisted JSON at `~/.AriaSecurity/Sense_Map.json` (atomic write):

```json
{"apps": {"<key>": {
  "name": "...", "publisher": "...", "install_location": "...",
  "installed_at": 0, "uninstalled_at": null,
  "status": "installed" | "uninstalled" | "residual_kept" | "cleaned",
  "files": [], "dirs": [], "registry": [],
  "residuals": [], "residual_bytes": 0
}}}
```

API: `upsert_app`, `set_footprint`, `mark_uninstalled`, `set_residuals`, `mark_kept`, `mark_cleaned`, `get(key)`, `all()`, `remove(key)`.

### Residuals + deletion rails — `Services/Sense/residuals.py`

- `find_residuals(footprint) -> (paths, total_bytes)` — footprint entries that still exist on disk.
- **`is_safe_to_delete(path, footprint) -> bool` (pure, the safety core).** Deletion is refused unless ALL hold: the path is **in that app's recorded footprint**; it resolves under one of the tracked roots; it is not a tracked root itself, a drive root, or a Windows/System32/Program Files *top-level* dir; no `..` traversal. Anything else → refuse.
- `delete_residuals(footprint) -> (deleted, failed, bytes_freed)` — permanent delete (`os.remove` / `shutil.rmtree`), each path re-checked through `is_safe_to_delete` immediately before removal.

### Service — `Services/Sense/SentinelSense.py` (BaseService, keeps its name)

On each tick: snapshot hives → `diff_installs`.
- **Installed** → `upsert_app`, attribute journal → `set_footprint`; keep existing suspicious-install classification (emits BEHAVIORAL threat).
- **Uninstalled** → `mark_uninstalled`, compute residuals → `set_residuals`; if residuals exist emit a SYSTEM event so the UI can prompt.

### Flask API + UI page

- `GET /api/sense/apps` → tracked apps (name, status, counts, residual_bytes).
- `GET /api/sense/app/<key>` → full data tree (files/dirs/registry, sizes).
- `GET /api/sense/residuals` → apps awaiting a cleanup decision.
- `POST /api/sense/cleanup` `{key}` → permanent delete via the rails; returns freed bytes; marks `cleaned`.
- `POST /api/sense/keep` `{key}` → marks `residual_kept` (stays tracked, nothing deleted).
- **New "Sentinel Sense" page** in the SPA: tracked-app list with status badges, a residual banner when cleanup is pending, an expandable per-app data tree (files / dirs / registry with sizes), and **Clean up** / **Keep** actions.

---

## Item 2 — Console page reads the app, not log files

**Problem.** `/api/console/logs` tails `_LOG_FILES` on disk, while `SentinelCompiler_v5.py` and ~43 other `print()` sites still write to the terminal — so the in-app console shows stale file content and real output is invisible in the UI.

**Design.**
- **`Services/log_bus.py`** — a process-wide bounded ring buffer (default 2000 lines) of `{ts, source, text}`, thread-safe, with `emit(source, text)`, `lines(n, source_filter)`, `clear()`, and an optional subscriber callback so the Flask layer can push to socketio.
- **stdout/stderr tee** — `install_stdout_tee()` wraps `sys.stdout`/`sys.stderr` so every existing `print()` anywhere in the app is captured into the bus **and** still reaches the real terminal. This captures all 43 sites without editing them; modules that already tag output (`[MLScanner] …`) keep their prefix, which becomes the `source`.
- `/api/console/logs` now reads the **bus** (not files); `/api/console/clear` clears the bus. Same JSON shape (`{"lines":[...]}`) so the existing page JS keeps working. `Services/monitors/console_logs.py` file-tailing is retired.
- Live updates: the bus subscriber emits a `console_line` socketio event; the console page appends in real time.

---

## Item 3 — Remove redundant / unused pages

Remove these 6 (each has exactly one nav entry + one page div):

| Page | Reason | Migration |
|------|--------|-----------|
| Protection | redundant with Dashboard | none |
| File Scan | not needed | none |
| Threat Intel | redundant with Dashboard | none |
| VirusTotal | unused | none |
| Service Tools | unused | **firewall quick actions → Firewall page** |
| Plugin | unused | none |

Also remove: their nav buttons, page `<div>`s, page-specific JS (render/refresh functions, event handlers, `_PAGES`/router entries), and any Flask routes that become dead **only if** no surviving page uses them (verify each before deleting — e.g. `/api/threat_intel/stats` and `/api/scan` may still back the Dashboard). Net nav count 28 → 23 (28 − 6 + 1 new Sense page).

---

## Testing & verification

- **Pure cores unit-tested:** `attribute()` (in-window + under-install-location + name-token match; excludes unrelated/old entries), `is_safe_to_delete()` (refuses paths outside the footprint, tracked roots themselves, drive roots, Windows/System32, `..` traversal; accepts a genuine footprint file), `find_residuals()` (existing vs missing, byte totals) with `tmp_path`; `sense_map` persistence round-trip; `log_bus` ring-buffer bounds/filter/clear.
- **Mocked:** registry snapshots, watchdog events.
- **Gates:** full suite green; reachability PASS (new Sense modules become live → bump `EXPECTED_LIVE`); boot HTTP 200; the SPA renders the new Sense page and the 6 removed pages leave no dead nav/router references.
- **Not auto-tested:** real installer capture (needs an actual install) — documented as manual.

## Non-goals

- No driver/kernel involvement. No uninstaller execution (SentinelSense doesn't run an app's uninstaller; it cleans residuals *after* the user uninstalls).
- Deletion never touches anything outside a recorded footprint.
