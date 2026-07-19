# Phase 3C — Device & Discovery — Design

**Date:** 2026-07-18
**Status:** Design (awaiting user review) → implementation plan.
**Context:** Third sub-project of Phase 3 (order 3B, 3A done → **3C (this)** → 3D). Full clean-slate rewrite on the `BaseService` framework. Master spec: `2026-07-17-zashiron-rebuild-design.md`.

---

## 1. Scope

The services originally flagged as having the poorest logic. Two decisions collapsed the cluster from three services to two:
- **AccessControl folds into StorageGuard** (its USBSTOR enable/disable IS the port-locker — no separate service).
- **SentinelSense is reframed** with real security value (not just uninstall hygiene).

**Deliverables (both → `BaseService`):**
1. **StorageGuard** (`Services/SentinelUSBGuard.py`, filename kept for the Flask API) — protects against **any external/removable storage medium**, scan-then-warn.
2. **SentinelSense** (`Services/Sense/SentinelSense.py`) — system-change monitor: install/uninstall tracking + suspicious-new-software flagging + leftover detection; Qt stripped.

**Out of scope:** the Phase 5 Flask UI (StorageGuard/Sense keep their `get_state()` module API so the current UI keeps working); the kernel driver (final phase). AccessControl stays retired in `cleanup/`.

---

## 2. StorageGuard (`Services/SentinelUSBGuard.py`)

`BaseService`, `name="USBMonitor"` (brain module name kept). Guards **all external/removable storage** — USB flash, SD/microSD, external HDDs **and** SSDs, portable/Thunderbolt drives, optical — not just "USB drives."

### 2.1 Broad external-storage detection (the key fix)
An external HDD/SSD typically reports as `DRIVE_FIXED`, so drive-type alone is insufficient. Detection is two-stage:
1. **Drive-letter diff** — poll `GetLogicalDrives()` each cycle; a *newly appeared* letter is a mount event (catches every medium).
2. **External classification** — for a new letter, gather `drive_info = {letter, drive_type, bus_type, removable_media}` where `bus_type` comes from the backing physical disk (via `IOCTL_STORAGE_QUERY_PROPERTY` → `STORAGE_ADAPTER_DESCRIPTOR.BusType`, ctypes, no dep; fallback PowerShell `Get-Partition -DriveLetter X | Get-Disk | Select BusType`). Pure classifier `is_external_storage(drive_info) -> bool` returns True when `drive_type == DRIVE_REMOVABLE`, OR `bus_type ∈ {USB(7), 1394(6), SD(12), MMC(13), removable}`, OR `removable_media` is set — so an external SSD on USB is caught even though Windows calls it FIXED. `DRIVE_REMOTE`/network is excluded; `DRIVE_CDROM` handled per config.

### 2.2 Scan-then-warn (default response)
On a new external drive that isn't allowlisted: **allow access, scan in the background** — enumerate scannable files (`_SCAN_EXTS`, capped at `max_files`) and run the existing PE engine (`Engine.Compiler.SentinelCompiler_v5.VirusScanner`) on each; on a malicious verdict → `emit_threat(USB, HIGH/CRITICAL, detail, file_path=…)` + quarantine the offending file (move to the vault/quarantine dir, config), NOT the whole drive. No access lock by default. Per-drive scan state → `~/.AriaSecurity/usb_guard_state.json` (`scanning` → `clean` / `threat`) for the UI.

### 2.3 Port-locker / access-control (absorbs AccessControl)
User toggle: `set_port_locker(True/False)` disables/enables the `USBSTOR` driver (registry `HKLM\...\Services\USBSTOR\Start` = 4/3 + `Disable-PnpDevice` on `USBSTOR\*` instances) so no USB storage mounts at all; `port_locker_status()` reports it. This is the hard-block path folded in from AccessControl.

### 2.4 Optional strict mode
Config `block_until_scanned` (default **False** per user choice): when True, restores the old lock-then-scan behavior (icacls DENY ACE for the Interactive SID until a clean scan). Default off = scan-then-warn.

### 2.5 Allowlist + API
Trusted device allowlist (`~/.AriaSecurity/usb_allowlist.json`, by volume serial/label) skips scanning. **Preserved module-level API** for the Flask UI: `get_state()`, `get_guard()`, `set_port_locker(bool)`, `port_locker_status()`, `trust_device(serial)`.

### 2.6 Pure testable core
`is_external_storage(drive_info)->bool`; `diff_drives(before:set, after:set)->(new, removed)`; `is_allowlisted(drive_info, allowlist)->bool`; the scan-state transition. The IOCTL/PowerShell bus-type probe, `icacls`, `USBSTOR` toggle, and the file scan are I/O — injected/mocked in tests.

---

## 3. SentinelSense (`Services/Sense/SentinelSense.py`)

`BaseService`, `name="SentinelSense"`. Reframed from a pure uninstall-leftover tool into a **system-change monitor** with security value. Qt window removed (Phase 5 UI renders state).

- **Registry-snapshot diff:** poll the three Uninstall keys (`HKCU`/`HKLM`/`WOW6432Node`) each cycle; `diff_installs(before: dict, after: dict) -> (installed: list, uninstalled: list)` (pure).
- **Suspicious new-software flagging (new security value):** for each newly-installed app, `classify_install(app_info) -> (suspicious: bool, reason: str)` (pure) — flags installs whose main executable is unsigned/untrusted (reuse `Engine.Detection.cert_reputation.CertReputation`), OR whose `InstallLocation` is a suspicious path (`%TEMP%`/Downloads/`%APPDATA%`), OR that registered no proper publisher — a PUP/dropper signal → `emit_threat(BEHAVIORAL, MEDIUM, "Suspicious software install", detail)`.
- **Leftover detection (preserved):** on an uninstall, map file/registry residuals of the removed app; report as `emit_threat(SYSTEM, INFO, "Uninstall leftovers", detail)` + state, not a GUI popup.
- State → `~/.AriaSecurity/.SentinelSense/…` (kept). Module `get_state()` for the UI.
- **Pure testable core:** `diff_installs(before, after)`; `classify_install(app_info)` with an injectable trust check.

---

## 4. Orchestration
Replace the `_UsbThread`/`_SenseThread` `_ModuleThread` wrappers in `Services/SentinelService_v2.py` with `_ServiceHolder` wrapping the new `StorageGuard`/`SentinelSense` `BaseService` instances (same pattern as 3B/3A). Fix any stale imports (`SentinelSenseController` etc.). Other clusters untouched.

## 5. Data flow & error handling
**Flow:** drive-letter poll → new external drive → background scan (VirusScanner) → `emit_threat` + quarantine on hit. Registry poll → install/uninstall diff → `classify_install` → `emit_threat` on suspicious. **Errors:** every probe (IOCTL/PowerShell), scan, icacls/USBSTOR call, and registry read is exception-isolated (a device that can't be probed logs + is skipped); `BaseService` crash isolation applies; missing admin degrades the port-locker gracefully (logs, can't toggle).

## 6. Testing (synthetic — no real devices/registry mutation)
- **StorageGuard:** `is_external_storage` on synthetic drive_info (USB flash → True; external SSD on USB bus reported FIXED → True; internal C: SATA fixed → False; network drive → False); `diff_drives`; `is_allowlisted`; scan flow with a fake VirusScanner (malicious file → `emit_threat` + quarantine-fn called; clean → state `clean`, no emit); `set_port_locker` with the registry/PnP calls mocked. `BaseService` lifecycle with a fake brain.
- **SentinelSense:** `diff_installs(before, after)` (add/remove detection); `classify_install` (unsigned+temp → suspicious; signed+ProgramFiles → clean, with an injected fake cert check); leftover mapping on synthetic data. Lifecycle with a fake brain.

## 7. Dependencies
None new (`ctypes`, `winreg`, `psutil`, `pefile`, `CertReputation`, `VirusScanner` all present).

## 8. Deferred / future
3D support cluster; Phase 4 (Argus) and Phase 5 (UI); the kernel minifilter driver (final phase — would give true device-arrival events and pre-mount blocking, superseding polling).
