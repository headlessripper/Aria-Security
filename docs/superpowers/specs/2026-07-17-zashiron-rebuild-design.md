# AriaSecurity — Full Rebuild Design

**Date:** 2026-07-17
**Author:** Engineering (with Claude)
**Status:** Master design — Phase 1 execution-ready; later phases outlined, each to get its own spec.

---

## 1. Context & Analysis

AriaSecurity is a Windows endpoint-protection platform (~36K LOC Python across ~97
modules) plus a C++ kernel minifilter concept. A parallel reference project, **PYAS**, was
provided as the architectural north star for the detection engine.

### 1.1 Findings

1. **Detection engine is weak (core problem).** The live ML path
   (`Main_Unit/Units/Engine_Unit_ML_v2.py`) converts a PE's raw bytes into a grayscale
   *image* and runs a 2-class CNN (`Engine_General_ZS1.onnx`). This "malware-as-image"
   approach has no semantic understanding of the PE, generalizes poorly, and is trivially
   evaded (packing / byte reordering changes the image). PYAS instead uses **LightGBM
   gradient-boosted trees over PE structural features + CRC32-hashed DLL/API imports**
   (EMBER-style) — the industry-standard, robust, explainable approach. This is the model
   to adopt and extend.

2. **Pickle zoo.** `models/` holds 9 loose scikit-learn `.pkl` files (malware, network,
   NIDS, phishing), stale (Jan–Feb 2026) and trained on small CSVs. Loading pickles
   executes arbitrary code — unacceptable inside an AV. Target: versioned ONNX artifacts.

3. **Two entry points / two UIs.** `SentinelUI.py` (3,038 lines, Qt/PySide6, retired) vs.
   `SentinelUI_Flask.py` (1,973 lines, Flask + pywebview + SocketIO — the designated
   entry). Behind Qt sits a whole parallel stack (`Service/Pages/*`, `UIComponents/*`).

4. **Python → .exe → Python anti-pattern.** `SentinelSenseService.exe` /
   `SentinelTaskAgent.exe` are PyInstaller-frozen Python launched via `subprocess` from
   the Flask app, while their sources live in the tree. Should be in-process workers / clean IPC.

5. **Archive & version sprawl.** Many `Archieve/` folders and live `_v2/_v5/NG2`
   duplicates; a typo-duplicate (`AnimatedDropdown.py` **and** `AnitmatedDropdown.py`).

6. **Structure mismatch.** Deep inconsistent nesting vs. PYAS's clean
   `Engine/ Interface/ Plugins/` + flat core files.

### 1.2 Reachability partition (authoritative)

A pure-AST transitive import walk from `SentinelUI_Flask.py` yields **28 LIVE / 69 DEAD**
of 97 modules. Verified there are no dynamic project-module imports from the live entry
(the `subprocess`/`ShellExecute` calls target system tools + the two `.exe` helpers, not
project `.py`). The dead set is therefore safe to quarantine.

---

## 2. Target Architecture (end state)

```
AriaSecurity/
├── SentinelUI_Flask.py     # THE sole entry point
├── Engine/                 # detection: feature extractor, ONNX inference, YARA, hashes, training
│   ├── Detection/          # advanced engine (replaces Engine_Unit_ML_v2 image-CNN)
│   ├── Heuristic/          # YARA rules, .ips, hashes
│   ├── Properties/         # training scripts + features.json
│   └── Model/              # versioned ONNX artifacts
├── Interface/              # Flask UI (static/ + templates/) — Swiss #000000 / #FFFFFF
├── Services/               # in-process protection services (Brain, Net, Ransom, Exploit, USB, …)
├── Argus/                   # soul.md, mind.md + rebuilt assistant engine
├── Plugins/                # kernel minifilter driver + rules (mirrors PYAS)
├── Config/                 # Sys_Config, whitelist, config.json
├── models/                 # versioned ONNX (no loose pickles)
└── cleanup/                # everything retired — reversible, tagged by reason
```

## 3. Phased Roadmap

Each phase is designed, built, and **verified runnable** before the next. Later phases get
their own spec + plan.

| Phase | Scope | Risk |
|-------|-------|------|
| **1. Restructure & cleanup** | Quarantine dead code (tagged), lock sole entry point, create top-level dirs. **No live-module moves.** | Low |
| **2. Detection engine + model** | EMBER-style LightGBM on PE features → ONNX; new scanner API; sourced public dataset (EMBER 2018 / BODMAS). Retire image-CNN + pickles. | Med |
| **3. Protection services revamp** | Reforge Sense / USBGuard / AccessControl / Ransom / Net / Exploit as robust in-process services; kill the .exe pattern. | Med |
| **4. Argus rebuild** | Fix assistant logic/architecture (tool loop, event grounding). | Med |
| **5. Swiss UI redesign** | #000/#FFF Swiss interface across all pages; extract remaining Qt logic (e.g. UsbAllowlistPage) into services. | Med |

---

## 4. Phase 1 — Restructure & Cleanup (execution-ready)

### 4.1 Decisions (locked)

- **Reorg scope:** *Cleanup now, reorg per-phase.* Quarantine dead code + lock the sole
  entry point + create the top-level dir skeleton. LIVE modules are relocated into
  `Engine/`/`Services/` gradually, by the phase that rewrites them. Keeps the app runnable.
- **Dead-code fate:** *Quarantine all, tagged by reason* under `cleanup/<tag>/`,
  preserving each file's original relative path inside its tag folder.
- **Cleanup = move, never delete.** Fully reversible; nothing is lost.

### 4.2 What moves to `cleanup/` (by tag)

**`cleanup/qt-ui/`** — retired Qt interface (replaced by Flask):
`SentinelUI.py`; all `Main_Unit/Service/Pages/*.py` **except `UsbAllowlistPage.py`**
(that one is still imported by Flask — stays until Phase 5); `Main_Unit/UIComponents/*`
(incl. the typo-dup `AnitmatedDropdown.py`); `Main_Unit/Service/SentinelConnectionView.py`.

**`cleanup/archive/`** — `Archieve/` folders + old versions:
`Engine/Compiler/Archieve/SentinelCompiler_v4.py`;
`Engine/Service/Archieve/*` (Sentinelactivation_check, SentinelNetProtection, SentinelNetProtectionNG, SentinelService);
`SentinelSense/Archieve/*` (sense_core, sense_gui);
`Units/Archieve/*` (Engine-Unit, Engine_Unit_ML v1).

**`cleanup/licensing/`** — activation/HWID/license subsystem (not wired to Flask):
`Engine/Service/SentinelActivation/*` (activate_hwid, AVBrainModelDownloader, Sentinelhwid_lock,
Sentinellicense_activation, Sentinellicense_downloader, SentinellicenseUI).

**`cleanup/exe-sources/`** — Python behind the `.exe` anti-pattern + separate service entries
(sources only; the running `.exe` files stay until Phase 3 replaces them in-process):
`SentinelSense/AiSense/SentinelAiSenseService.py`, `SentinelAiSenseClient.py`;
`SentinelSense/TaskAgent/SentinelTaskEntry.py`;
`Engine/Service/SentinelWindowsService.py`;
`Service/SentinelServiceAgent.py`.

**`cleanup/tools-rework/`** — orphaned but functionally relevant (rework in a later phase):
`Tools/SentinelAccessControler.py`; `Engine/Service/SentinelModelUpdater.py` (→ Phase 2);
`Engine/Service/SentinelSelfProtection.py`;
`Engine/Service/SentinelServices/SentinelRemoteService.py`;
`SentinelScannerAPI.py`; `SentinelSense/SentinelAV_Report/SentinelAV_report.py`;
`SentinelSense/DriverInstaller/SentinelDriverInstallation.py`;
`Service/FirewallCleanWorker.py`, `Service/PluginInstaller.py`, `Service/LogTail.py`,
`Service/find_icon.py`; `Service/SentinelNotify.py`, `Service/SentinelUserProfile.py`;
`Worker/UpdatorThreads.py`;
`Actions/Check_Update.py`, `Actions/Create_config.py`, `Actions/Execute_Action.py`.

> Full accounting: 69 dead modules = qt-ui (31) + archive (9) + licensing (6) +
> exe-sources (5) + tools-rework (17) + entry (1). Every dead module is assigned.

**`cleanup/entry/`** — retired secondary entry point: `run_dev.py`
(its `--no-elevate` capability already exists in the Flask entry via `SENTINEL_NO_ELEVATE=1`).

### 4.3 What stays put (Phase 1)

- All 28 LIVE modules (including `Engine_Unit_ML_v2.py` and `Engine_Unit_SG.py` — replaced
  in Phase 2, not Phase 1).
- `Main_Unit/Service/Pages/UsbAllowlistPage.py` (live import; Phase 5).
- `models/*` and `Engine_General_ZS1.onnx` (retired in Phase 2 with the engine).
- `install_service.bat` / `uninstall_service.bat` (Phase 3 with service model).
- `logs/`, `static/`, `templates/`, `Plugin/SentinelServices/*.exe`.

### 4.4 New directory skeleton (created empty, populated per-phase)

`Engine/{Detection,Heuristic,Properties,Model}`, `Interface/`, `Services/`, `Config/`,
`cleanup/`. (`Argus/`, `Plugin/`, `models/`, `static/`, `templates/` already exist.)

### 4.5 Verification (must pass before Phase 1 is "done")

1. **Import smoke test:** `python -c "import ast; compile(open('SentinelUI_Flask.py').read(), ...)"`
   plus an import-resolution pass — every `from Main_Unit...` in the 28 live modules still
   resolves (no live import points into `cleanup/`).
2. **Headless boot:** launch `SentinelUI_Flask.py` with `SENTINEL_NO_ELEVATE=1` and confirm
   the Flask app binds `127.0.0.1:8765` and serves `index.html` (via the preview browser),
   with no import errors in logs.
3. **Re-run reachability** — LIVE set unchanged at 28; zero live module resolves into `cleanup/`.
4. **Reversibility check:** a documented one-command restore from `cleanup/` back to origin.

### 4.6 Out of scope for Phase 1

New models, engine rewrite, service rewrites, UI redesign, Argus — all later phases.

---

## 5. Open Items / Notes

- **Not a git repo** (`git init` not yet run) — spec is written to disk but not committed.
  Recommend `git init` before Phase 1 execution so cleanup moves are tracked/reversible in VCS.
- **Dataset sourcing (Phase 2):** EMBER 2018 (published *feature vectors*, ~900K train /
  200K test) is primary; BODMAS (modern, EMBER-feature-compatible) is the alternative.
  Both are pre-extracted features, not live malware — safe/legal. Size + source to be
  confirmed with the user before any download.
