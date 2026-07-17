# Phase 1: Restructure & Cleanup — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Quarantine all 69 dead modules into a tagged, reversible `cleanup/` tree, lock `SentinelUI_Flask.py` as the sole entry point, and stand up the new top-level directory skeleton — while keeping the app fully runnable.

**Architecture:** Move-only, git-tracked quarantine. Every retired file is relocated with `git mv` to `cleanup/<tag>/<original/relative/path>`, preserving its path so restoration is trivial. A reachability-invariant checker (`scripts/verify_reachability.py`) is the test harness: after every move batch it must report exactly the same 28 live modules, none resolving into `cleanup/`. No live module is moved in Phase 1 (per-phase reorg comes later).

**Tech Stack:** Python 3.10+ (AST), git 2.52, PowerShell/Bash. No new runtime dependencies.

## Global Constraints

- Sole entry point: `SentinelUI_Flask.py` (must import and boot on `127.0.0.1:8765` after every task).
- Cleanup = **move, never delete.** Use `git mv` only. Fully reversible.
- Live set is exactly **28 modules** (per baseline reachability). This count must never change during Phase 1.
- **Do NOT move** any live module, `models/*`, `Engine_General_ZS1.onnx`, `Plugin/SentinelServices/*.exe`, `install_service.bat`/`uninstall_service.bat`, or `Main_Unit/Service/Pages/UsbAllowlistPage.py` (live import, deferred to Phase 5).
- Tag buckets & counts: qt-ui (31), archive (9), licensing (6), exe-sources (5), tools-rework (17), entry (1) = 69.
- Commit after every task. Never use `--no-verify`.

---

## File Structure

- `scripts/verify_reachability.py` — **new.** The Phase 1 test harness. Walks imports from the entry point; asserts live count == 28 and that no live module resolves under `cleanup/`. Exit 0 = green.
- `cleanup/<tag>/…` — **new.** Quarantine destination, mirrors original paths under each tag.
- `Engine/{Detection,Heuristic,Properties,Model}/`, `Interface/`, `Services/`, `Config/` — **new, empty** (`.gitkeep`). Populated in later phases.
- `docs/superpowers/plans/PHASE1-RESTORE.md` — **new.** One-command restore instructions.

---

### Task 1: Reachability checker + directory skeleton

**Files:**
- Create: `scripts/verify_reachability.py`
- Create: `Engine/Detection/.gitkeep`, `Engine/Heuristic/.gitkeep`, `Engine/Properties/.gitkeep`, `Engine/Model/.gitkeep`, `Interface/.gitkeep`, `Services/.gitkeep`, `Config/.gitkeep`

**Interfaces:**
- Produces: `scripts/verify_reachability.py` — CLI, exit 0 when green, exit 1 with a diff when the live set changed or any live module is under `cleanup/`. Prints `LIVE=<n>`.

- [ ] **Step 1: Write the checker**

```python
# scripts/verify_reachability.py
"""Phase 1 invariant checker. Green = live set unchanged (28) and no live
module resolves under cleanup/. Run from repo root."""
import ast, os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRY = ROOT / "SentinelUI_Flask.py"
EXPECTED_LIVE = 28

def index():
    by_dotted, by_stem = {}, {}
    for p in ROOT.rglob("*.py"):
        s = str(p)
        if ".venv" in s or "__pycache__" in s or f"{os.sep}.claude{os.sep}" in s \
           or f"{os.sep}scripts{os.sep}" in s or f"{os.sep}docs{os.sep}" in s:
            continue
        rel = p.relative_to(ROOT).with_suffix("")
        by_dotted[".".join(rel.parts)] = p
        by_stem.setdefault(p.stem, []).append(p)
    return by_dotted, by_stem

def resolve(name, from_file, by_dotted, by_stem):
    if not name:
        return None
    if name in by_dotted:
        return by_dotted[name]
    for dotted, path in by_dotted.items():
        if dotted.endswith("." + name):
            return path
    last = name.split(".")[-1]
    if last in by_stem:
        same = [c for c in by_stem[last] if c.parent == from_file.parent]
        return same[0] if same else by_stem[last][0]
    return None

def walk(by_dotted, by_stem):
    visited, stack = set(), [ENTRY]
    while stack:
        path = stack.pop()
        if path in visited:
            continue
        visited.add(path)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for n in names:
                t = resolve(n, path, by_dotted, by_stem)
                if t and ROOT in t.parents:
                    stack.append(t)
    return visited

def main():
    by_dotted, by_stem = index()
    live = walk(by_dotted, by_stem)
    live_rel = sorted(str(p.relative_to(ROOT)).replace("\\", "/") for p in live)
    in_cleanup = [p for p in live_rel if p.startswith("cleanup/")]
    print(f"LIVE={len(live)}")
    ok = True
    if len(live) != EXPECTED_LIVE:
        print(f"[FAIL] live count {len(live)} != expected {EXPECTED_LIVE}")
        for p in live_rel:
            print("  L", p)
        ok = False
    if in_cleanup:
        print("[FAIL] live modules resolve under cleanup/:")
        for p in in_cleanup:
            print("  X", p)
        ok = False
    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run it against the baseline — must be green**

Run: `python scripts/verify_reachability.py`
Expected: `LIVE=28` then `PASS`, exit 0.

- [ ] **Step 3: Create the empty directory skeleton**

```bash
cd "D:/ZashironSentinel"
for d in Engine/Detection Engine/Heuristic Engine/Properties Engine/Model Interface Services Config; do
  mkdir -p "$d" && : > "$d/.gitkeep"
done
```

- [ ] **Step 4: Verify skeleton exists and checker still green**

Run: `ls Engine Interface Services Config && python scripts/verify_reachability.py`
Expected: dirs listed; `LIVE=28`, `PASS`.

- [ ] **Step 5: Commit**

```bash
git add scripts/verify_reachability.py Engine Interface Services Config
git commit -m "Phase 1: add reachability checker + target dir skeleton"
```

---

### Task 2: Quarantine the qt-ui bucket (31 files)

**Files (move with `git mv` to `cleanup/qt-ui/<original path>`):**
- `SentinelUI.py`
- `Main_Unit/Service/Pages/` — **all except `UsbAllowlistPage.py`**: `BehavioralRulesPage.py`, `CopilotPage.py`, `FirewallRulesPage.py`, `InterfacePage.py`, `MemoryCleanerPage.py`, `NetworkGeoBlockPage.py`, `PluginSystemPage.py`, `ProcessThreatPage.py`, `ScanHistoryPage.py`, `ScheduledScansPage.py`, `SecureVaultPage.py`, `SentinelAuthenticationPage.py`, `SentinelAuthSetupPage.py`, `SentinelNetScope.py`, `ServiceControlPage.py`, `StoragePage.py`, `ThreatIntelPage.py`, `VirusTotalPage.py`, `YaraRulesPage.py`, `SentinelTaskScope/TaskPage.py`, `Style_Qss/qss.py`
- `Main_Unit/UIComponents/` — all: `AnimatedDropdown.py`, `AnimatedToggle.py`, `AnitmatedDropdown.py`, `Card.py`, `FloatingPanel.py`, `Style_QSS/qss.py`, `UIImports/Auxilary.py`, `UIImports/UIImports.py`
- `Main_Unit/Service/SentinelConnectionView.py`

**Interfaces:**
- Consumes: `scripts/verify_reachability.py` from Task 1.

- [ ] **Step 1: Establish green baseline**

Run: `python scripts/verify_reachability.py`
Expected: `LIVE=28`, `PASS`.

- [ ] **Step 2: Move the bucket (git mv, path-preserving)**

```bash
cd "D:/ZashironSentinel"
files=(
  "SentinelUI.py"
  Main_Unit/Service/Pages/BehavioralRulesPage.py
  Main_Unit/Service/Pages/CopilotPage.py
  Main_Unit/Service/Pages/FirewallRulesPage.py
  Main_Unit/Service/Pages/InterfacePage.py
  Main_Unit/Service/Pages/MemoryCleanerPage.py
  Main_Unit/Service/Pages/NetworkGeoBlockPage.py
  Main_Unit/Service/Pages/PluginSystemPage.py
  Main_Unit/Service/Pages/ProcessThreatPage.py
  Main_Unit/Service/Pages/ScanHistoryPage.py
  Main_Unit/Service/Pages/ScheduledScansPage.py
  Main_Unit/Service/Pages/SecureVaultPage.py
  Main_Unit/Service/Pages/SentinelAuthenticationPage.py
  Main_Unit/Service/Pages/SentinelAuthSetupPage.py
  Main_Unit/Service/Pages/SentinelNetScope.py
  Main_Unit/Service/Pages/ServiceControlPage.py
  Main_Unit/Service/Pages/StoragePage.py
  Main_Unit/Service/Pages/ThreatIntelPage.py
  Main_Unit/Service/Pages/VirusTotalPage.py
  Main_Unit/Service/Pages/YaraRulesPage.py
  Main_Unit/Service/Pages/SentinelTaskScope/TaskPage.py
  Main_Unit/Service/Pages/Style_Qss/qss.py
  Main_Unit/UIComponents/AnimatedDropdown.py
  Main_Unit/UIComponents/AnimatedToggle.py
  Main_Unit/UIComponents/AnitmatedDropdown.py
  Main_Unit/UIComponents/Card.py
  Main_Unit/UIComponents/FloatingPanel.py
  Main_Unit/UIComponents/Style_QSS/qss.py
  Main_Unit/UIComponents/UIImports/Auxilary.py
  Main_Unit/UIComponents/UIImports/UIImports.py
  Main_Unit/Service/SentinelConnectionView.py
)
for f in "${files[@]}"; do
  dest="cleanup/qt-ui/$f"
  mkdir -p "$(dirname "$dest")"
  git mv "$f" "$dest"
done
echo "moved ${#files[@]} files"
```

Expected: `moved 31 files`, no `git mv` errors.

- [ ] **Step 3: Verify invariant holds**

Run: `python scripts/verify_reachability.py`
Expected: `LIVE=28`, `PASS`. (If FAIL: a moved file was actually live — `git mv` it back and re-check.)

- [ ] **Step 4: Import smoke test**

Run: `python -c "import ast,sys; ast.parse(open('SentinelUI_Flask.py',encoding='utf-8').read()); print('entry parses OK')"`
Expected: `entry parses OK`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Phase 1: quarantine retired Qt UI to cleanup/qt-ui (31 files)"
```

---

### Task 3: Quarantine archive + licensing buckets (15 files)

**Files (git mv to `cleanup/archive/<path>` and `cleanup/licensing/<path>`):**
- archive (9): `Main_Unit/Engine/Compiler/Archieve/SentinelCompiler_v4.py`, `Main_Unit/Engine/Service/Archieve/Sentinelactivation_check.py`, `Main_Unit/Engine/Service/Archieve/SentinelNetProtection.py`, `Main_Unit/Engine/Service/Archieve/SentinelNetProtectionNG.py`, `Main_Unit/Engine/Service/Archieve/SentinelService.py`, `Main_Unit/SentinelSense/Archieve/sense_core.py`, `Main_Unit/SentinelSense/Archieve/sense_gui.py`, `Main_Unit/Units/Archieve/Engine-Unit.py`, `Main_Unit/Units/Archieve/Engine_Unit_ML.py`
- licensing (6): `Main_Unit/Engine/Service/SentinelActivation/activate_hwid.py`, `Main_Unit/Engine/Service/SentinelActivation/AVBrainModelDownloader.py`, `Main_Unit/Engine/Service/SentinelActivation/Sentinelhwid_lock.py`, `Main_Unit/Engine/Service/SentinelActivation/Sentinellicense_activation.py`, `Main_Unit/Engine/Service/SentinelActivation/Sentinellicense_downloader.py`, `Main_Unit/Engine/Service/SentinelActivation/SentinellicenseUI.py`

- [ ] **Step 1: Baseline green** — Run: `python scripts/verify_reachability.py` → `LIVE=28`, `PASS`.

- [ ] **Step 2: Move both buckets**

```bash
cd "D:/ZashironSentinel"
archive=(
  Main_Unit/Engine/Compiler/Archieve/SentinelCompiler_v4.py
  Main_Unit/Engine/Service/Archieve/Sentinelactivation_check.py
  Main_Unit/Engine/Service/Archieve/SentinelNetProtection.py
  Main_Unit/Engine/Service/Archieve/SentinelNetProtectionNG.py
  Main_Unit/Engine/Service/Archieve/SentinelService.py
  Main_Unit/SentinelSense/Archieve/sense_core.py
  Main_Unit/SentinelSense/Archieve/sense_gui.py
  Main_Unit/Units/Archieve/Engine-Unit.py
  Main_Unit/Units/Archieve/Engine_Unit_ML.py
)
licensing=(
  Main_Unit/Engine/Service/SentinelActivation/activate_hwid.py
  Main_Unit/Engine/Service/SentinelActivation/AVBrainModelDownloader.py
  Main_Unit/Engine/Service/SentinelActivation/Sentinelhwid_lock.py
  Main_Unit/Engine/Service/SentinelActivation/Sentinellicense_activation.py
  Main_Unit/Engine/Service/SentinelActivation/Sentinellicense_downloader.py
  Main_Unit/Engine/Service/SentinelActivation/SentinellicenseUI.py
)
for f in "${archive[@]}"; do d="cleanup/archive/$f"; mkdir -p "$(dirname "$d")"; git mv "$f" "$d"; done
for f in "${licensing[@]}"; do d="cleanup/licensing/$f"; mkdir -p "$(dirname "$d")"; git mv "$f" "$d"; done
echo "archive=${#archive[@]} licensing=${#licensing[@]}"
```

Expected: `archive=9 licensing=6`.

- [ ] **Step 3: Verify invariant** — Run: `python scripts/verify_reachability.py` → `LIVE=28`, `PASS`.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "Phase 1: quarantine Archieve/ + activation-licensing to cleanup (15 files)"
```

---

### Task 4: Quarantine exe-sources bucket (5 files)

**Files (git mv to `cleanup/exe-sources/<path>`):** `Main_Unit/SentinelSense/AiSense/SentinelAiSenseService.py`, `Main_Unit/SentinelSense/AiSense/SentinelAiSenseClient.py`, `Main_Unit/SentinelSense/TaskAgent/SentinelTaskEntry.py`, `Main_Unit/Engine/Service/SentinelWindowsService.py`, `Main_Unit/Service/SentinelServiceAgent.py`

**Note:** These are the Python sources behind `SentinelSenseService.exe`/`SentinelTaskAgent.exe` and the Windows-service/agent launchers. The **`.exe` files stay** (the live Flask app still launches them via `_BG_SERVICES`); only the unused sources move. They are reworked in Phase 3.

- [ ] **Step 1: Guard — is the Windows service currently installed?**

Run: `sc query AriaSecurity 2>&1 | head -3` (PowerShell: `sc.exe query AriaSecurity`)
Expected: `The specified service does not exist as an installed service` (or `1060`). **If it IS installed/running, STOP** — run `uninstall_service.bat` (or defer `SentinelWindowsService.py`) before moving, and note it for the reviewer.

- [ ] **Step 2: Baseline green** — Run: `python scripts/verify_reachability.py` → `LIVE=28`, `PASS`.

- [ ] **Step 3: Move the bucket**

```bash
cd "D:/ZashironSentinel"
files=(
  Main_Unit/SentinelSense/AiSense/SentinelAiSenseService.py
  Main_Unit/SentinelSense/AiSense/SentinelAiSenseClient.py
  Main_Unit/SentinelSense/TaskAgent/SentinelTaskEntry.py
  Main_Unit/Engine/Service/SentinelWindowsService.py
  Main_Unit/Service/SentinelServiceAgent.py
)
for f in "${files[@]}"; do d="cleanup/exe-sources/$f"; mkdir -p "$(dirname "$d")"; git mv "$f" "$d"; done
echo "moved ${#files[@]}"
```

Expected: `moved 5`.

- [ ] **Step 4: Verify invariant** — Run: `python scripts/verify_reachability.py` → `LIVE=28`, `PASS`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "Phase 1: quarantine .exe-wrapped Python sources to cleanup/exe-sources (5 files)"
```

---

### Task 5: Quarantine tools-rework bucket (17 files)

**Files (git mv to `cleanup/tools-rework/<path>`):** `Main_Unit/Tools/SentinelAccessControler.py`, `Main_Unit/Engine/Service/SentinelModelUpdater.py`, `Main_Unit/Engine/Service/SentinelSelfProtection.py`, `Main_Unit/Engine/Service/SentinelServices/SentinelRemoteService.py`, `Main_Unit/SentinelScannerAPI.py`, `Main_Unit/SentinelSense/SentinelAV_Report/SentinelAV_report.py`, `Main_Unit/SentinelSense/DriverInstaller/SentinelDriverInstallation.py`, `Main_Unit/Service/FirewallCleanWorker.py`, `Main_Unit/Service/PluginInstaller.py`, `Main_Unit/Service/LogTail.py`, `Main_Unit/Service/find_icon.py`, `Main_Unit/Service/SentinelNotify.py`, `Main_Unit/Service/SentinelUserProfile.py`, `Main_Unit/Worker/UpdatorThreads.py`, `Main_Unit/Actions/Check_Update.py`, `Main_Unit/Actions/Create_config.py`, `Main_Unit/Actions/Execute_Action.py`

- [ ] **Step 1: Baseline green** — Run: `python scripts/verify_reachability.py` → `LIVE=28`, `PASS`.

- [ ] **Step 2: Move the bucket**

```bash
cd "D:/ZashironSentinel"
files=(
  Main_Unit/Tools/SentinelAccessControler.py
  Main_Unit/Engine/Service/SentinelModelUpdater.py
  Main_Unit/Engine/Service/SentinelSelfProtection.py
  Main_Unit/Engine/Service/SentinelServices/SentinelRemoteService.py
  Main_Unit/SentinelScannerAPI.py
  Main_Unit/SentinelSense/SentinelAV_Report/SentinelAV_report.py
  Main_Unit/SentinelSense/DriverInstaller/SentinelDriverInstallation.py
  Main_Unit/Service/FirewallCleanWorker.py
  Main_Unit/Service/PluginInstaller.py
  Main_Unit/Service/LogTail.py
  Main_Unit/Service/find_icon.py
  Main_Unit/Service/SentinelNotify.py
  Main_Unit/Service/SentinelUserProfile.py
  Main_Unit/Worker/UpdatorThreads.py
  Main_Unit/Actions/Check_Update.py
  Main_Unit/Actions/Create_config.py
  Main_Unit/Actions/Execute_Action.py
)
for f in "${files[@]}"; do d="cleanup/tools-rework/$f"; mkdir -p "$(dirname "$d")"; git mv "$f" "$d"; done
echo "moved ${#files[@]}"
```

Expected: `moved 17`.

- [ ] **Step 3: Verify invariant** — Run: `python scripts/verify_reachability.py` → `LIVE=28`, `PASS`.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "Phase 1: quarantine orphaned rework-candidate tools to cleanup/tools-rework (17 files)"
```

---

### Task 6: Quarantine entry bucket, lock sole entry, full acceptance & restore doc

**Files:**
- Move: `run_dev.py` → `cleanup/entry/run_dev.py`
- Create: `docs/superpowers/plans/PHASE1-RESTORE.md`

- [ ] **Step 1: Baseline green** — Run: `python scripts/verify_reachability.py` → `LIVE=28`, `PASS`.

- [ ] **Step 2: Move run_dev.py**

```bash
cd "D:/ZashironSentinel"
mkdir -p cleanup/entry
git mv run_dev.py cleanup/entry/run_dev.py
```

- [ ] **Step 3: Verify invariant** — Run: `python scripts/verify_reachability.py` → `LIVE=28`, `PASS`.

- [ ] **Step 4: Confirm SentinelUI_Flask.py is the only remaining root entry point**

Run: `ls *.py` (repo root)
Expected: only `SentinelUI_Flask.py`. (No `SentinelUI.py`, no `run_dev.py`.)

- [ ] **Step 5: Full acceptance — headless boot**

Run (Bash): `SENTINEL_NO_ELEVATE=1 python SentinelUI_Flask.py &` then, after ~8s, probe:
`python -c "import urllib.request as u; print(u.urlopen('http://127.0.0.1:8765',timeout=5).status)"`
Expected: `200`. Then stop the process.
(Alternative: use the preview browser tool to open `http://127.0.0.1:8765` and confirm the SPA renders with no console/import errors.)
**If boot fails on a missing import that points into `cleanup/`:** the checker missed a dynamic load — `git mv` that file back, add it to the live-exclusions, re-verify, and note it for the reviewer.

- [ ] **Step 6: Write the restore doc**

```markdown
# Phase 1 Restore

To restore any quarantined file to its original location:
    git mv cleanup/<tag>/<original/path> <original/path>

To restore an entire bucket (example: qt-ui):
    cd cleanup/qt-ui && git ls-files | while read f; do
      dest="${f#cleanup/qt-ui/}"; mkdir -p "$(dirname "../../$dest")"; git mv "$f" "../../$dest"; done

To restore everything Phase 1 moved, revert the Phase 1 commits:
    git revert --no-commit <first-phase1-sha>..<last-phase1-sha> && git commit

Baseline (pre-Phase-1) snapshot: commit 871bbf3 (run `git rev-parse HEAD` before Task 1
to capture the exact current tip if it has advanced).
```

- [ ] **Step 7: Final commit**

```bash
git add -A
git commit -m "Phase 1: lock SentinelUI_Flask.py as sole entry point + restore doc"
```

---

## Self-Review

- **Spec coverage:** Every spec §4.2 bucket → a task (qt-ui→T2, archive+licensing→T3, exe-sources→T4, tools-rework→T5, entry→T6). §4.4 skeleton→T1. §4.5 verification: import smoke (T2 S4), headless boot (T6 S5), re-run reachability (every task), reversibility (T6 S6). §4.3 "stays put" enforced by Global Constraints + explicit `UsbAllowlistPage.py` exclusion in T2. All covered.
- **Counts:** 31+15(9+6)+5+17+1 = 69. Matches spec.
- **Placeholder scan:** none — all move lists, scripts, and commands are literal.
- **Type consistency:** the only produced interface is `scripts/verify_reachability.py` (exit code + `LIVE=` line), consumed identically by T2–T6.
- **Risk guard:** T4 S1 checks the Windows service isn't installed before moving its source. T6 S5 has a fallback path if a dynamic import was missed.
