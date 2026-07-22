# Aria Minifilter Driver (Plugins/Filter/) — Design

**Date:** 2026-07-22
**Status:** Design (user-approved: real build attempt + scan-on-open/block + Python path-only bridge) → implementation plan.
**Context:** Final planned piece of the Aria Security rebuild (origin/main tip `acc19cd`; all 5 phases + real EMBER model done). A Windows kernel-mode filesystem **minifilter** that intercepts file opens and consults the user-mode Aria scanner to block malware on access. Modeled on Microsoft's WDK `scanner` sample (the canonical AV minifilter).

---

## 1. Environment reality (drives the plan)

- **Present:** WDK kernel headers (`fltKernel.h` under `Windows Kits\10\Include\<ver>\km`), `fltMgr.lib` (`Lib\10.0.26100.0\km\x64`), `signtool.exe`, `stampinf.exe`, Visual Studio 2022, MSBuild.
- **Missing:** the WDK's Visual-Studio MSBuild integration (`Microsoft\WDK` targets) — so a standard driver `.vcxproj` will NOT build through MSBuild on this box.
- **Consequence:** primary build here is a **hand-rolled `cl.exe`/`link.exe` script** (`build.bat`) against the WDK headers/libs, producing `AriaFilter.sys`. A standard `.vcxproj` is also shipped for machines that DO have the WDK VS integration. The command-line kernel build is finicky; if it hits environment-specific snags, the source remains WDK-idiomatic and builds via the `.vcxproj` elsewhere.
- **NOT done by the assistant:** loading/installing the driver. That requires admin, `bcdedit /set testsigning on`, a reboot, and `fltmc load` — and a buggy kernel driver can bug-check (BSOD) the machine. The build output + install steps are delivered; the user loads it at their discretion.

---

## 2. Architecture (modeled on the WDK `scanner` sample)

```
 file open ─▶ [ AriaFilter.sys (kernel minifilter) ]
                 │  post-IRP_MJ_CREATE: get normalized path
                 │  FltSendMessage(path) ──▶ \AriaFilterPort ──▶ [ aria_filter_bridge.py ]
                 │                                                    │ VirusScanner.scan_file(path)
                 │  ◀── reply {SafeToOpen} ◀───────────────────────── │ FilterReplyMessage
                 ▼
     infected ▶ fail the open (STATUS_VIRUS_INFECTED)
     clean    ▶ allow
```

Two components + build/install glue:

- **`Plugins/Filter/AriaFilter/`** — the kernel driver (C, non-KMDF, uses FltMgr directly).
- **`Plugins/Filter/AriaFilterBridge/`** — the user-mode Python service (ctypes → `fltlib`) that runs the real `VirusScanner`.
- INF, `build.bat`, `AriaFilter.vcxproj`, and `README.md` (build + test-sign + install + risks).

---

## 3. Kernel driver — `AriaFilter/`

**Files:** `AriaFilter.c`, `AriaFilter.h` (shared port protocol), `AriaFilter.inf`, `AriaFilter.rc` (version), `AriaFilter.vcxproj`, `build.bat`.

**Registration:**
- `DriverEntry` → `FltRegisterFilter` with an `FLT_REGISTRATION` whose `OperationCallbacks` has **one post-op on `IRP_MJ_CREATE`** (`PostCreate`). `FltStartFiltering` after the port is up.
- `FltCreateCommunicationPort` on `\AriaFilterPort` (name in `AriaFilter.h`), max 1 connection, with `Connect`/`Disconnect`/`Message` notify callbacks. A single global `PFLT_PORT ClientPort` holds the connected bridge.

**PostCreate logic (scan-on-open, block infected):**
- Skip if: create failed (`Data->IoStatus.Status != STATUS_SUCCESS`), directory open (`FLT_IS_REPARSE_POINT`/`FILE_DIRECTORY_FILE`), paging/volume-open, or no connected client port.
- `FltGetFileNameInformation(FLT_FILE_NAME_NORMALIZED)` → `FltParseFileNameInformation` → copy `Name` (bounded to `ARIA_MAX_PATH` WCHARs) into an `ARIA_SCAN_REQUEST`.
- `FltSendMessage(Filter, &ClientPort, &request, sizeof(request), &reply, &replyLen, &timeout)` — synchronous, with a bounded timeout (e.g. 5 s). On timeout/error → **fail open** (allow, log) so the driver never hard-hangs I/O if the bridge is down.
- If `reply.SafeToOpen == FALSE` → set `Data->IoStatus.Status = STATUS_VIRUS_INFECTED`, `Information = 0`, and return `FLT_POSTOP_FINISHED_PROCESSING` (the open fails). Else `FLT_POSTOP_FINISHED_PROCESSING` unchanged (allow).
- Guard against re-entrancy / scanning our own bridge's reads (skip `KernelMode` requests: `FLTFL_CALLBACK_DATA_IRP_OPERATION` + `Data->RequestorMode == KernelMode`).

**Unload:** `FilterUnloadCallback` → close the comm port, `FltUnregisterFilter`. Support unload (`fltmc unload`).

**Altitude:** dev altitude in the FSFilter **Anti-Virus** range `320000–329999` (e.g. `320000`); the INF/`README` note that production altitudes require Microsoft allocation.

---

## 4. Port protocol — `AriaFilter.h` (shared by C driver + Python bridge)

Fixed-layout structs, byte-for-byte identical on both sides:

```c
#define ARIA_PORT_NAME   L"\\AriaFilterPort"
#define ARIA_MAX_PATH    512      // WCHARs

typedef struct _ARIA_SCAN_REQUEST {
    ULONG  PathLength;                 // WCHARs used in Path (excl. NUL)
    WCHAR  Path[ARIA_MAX_PATH];        // normalized file path
} ARIA_SCAN_REQUEST, *PARIA_SCAN_REQUEST;

typedef struct _ARIA_SCAN_REPLY {
    BOOLEAN SafeToOpen;               // FALSE => block the open
} ARIA_SCAN_REPLY, *PARIA_SCAN_REPLY;
```

On the user side each message is wrapped by FltMgr's `FILTER_MESSAGE_HEADER` (request) and `FILTER_REPLY_HEADER` (reply); the Python bridge mirrors these with `ctypes.Structure`. A committed constant (`ARIA_SCAN_REQUEST` size = 4 + 2*512 = 1028 bytes) is asserted equal on both sides by a unit test.

---

## 5. User-mode bridge — `AriaFilterBridge/aria_filter_bridge.py`

Pure-Python via `ctypes.WinDLL("fltlib")`:
- `FilterConnectCommunicationPort(ARIA_PORT_NAME, 0, None, 0, None, &port)`.
- Loop: `FilterGetMessage(port, &msgBuf, sizeof(FILTER_MESSAGE_HEADER)+sizeof(ARIA_SCAN_REQUEST), None)` → parse header (`MessageId`) + `ARIA_SCAN_REQUEST` (path). Run the verdict, then `FilterReplyMessage(port, replyBuf)` where replyBuf = `FILTER_REPLY_HEADER{Status, MessageId}` + `ARIA_SCAN_REPLY{SafeToOpen}`.
- **Verdict function** `scan_verdict(path) -> bool` (True = safe): calls the real engine `Engine.Compiler.SentinelCompiler_v5.VirusScanner.scan_file(path)`; interprets a `MALWARE`/`SUSPICIOUS` verdict as unsafe. Fails **safe** (returns True/allow) on any scanner error or if the engine can't load — the kernel side already fails-open on timeout, so the two agree: never block on infrastructure failure, only on a positive detection.
- Structs (`FILTER_MESSAGE_HEADER`, `FILTER_REPLY_HEADER`, `AriaScanRequest`, `AriaScanReply`) as `ctypes.Structure` with layouts matching `AriaFilter.h`. `scan_verdict` and the message parse/build are unit-testable without the driver loaded (inject a fake scanner; feed raw bytes).

---

## 6. Build & install

- **`build.bat`** — auto-detects the newest `Windows Kits\10` version, sets kernel include (`km`, `shared`, `km\crt`) + lib (`km\x64`) paths, invokes `cl /kernel /c` on `AriaFilter.c` and `link /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB fltMgr.lib ntoskrnl.lib hal.lib wdmsec.lib` → `AriaFilter.sys`. Locates `cl.exe`/`link.exe` via `vcvarsall.bat x64` from the detected VS2022. Then `stampinf` + a **test** `signtool sign /a` (self-signed test cert) so it can load under test-signing.
- **`README.md`** — exact steps: (1) build; (2) `bcdedit /set testsigning on` + reboot (admin); (3) create a self-signed test cert + trust it; (4) `sc create` / copy INF + `fltmc load AriaFilter`; (5) start `aria_filter_bridge.py`; (6) `fltmc unload` / uninstall. Explicit BSOD/testing-VM warning.

---

## 7. Testing & verification (what's provable here vs not)

- **Provable here:**
  - **Compile** `AriaFilter.sys` via `build.bat` (the primary gate). If the CLI kernel build is blocked by environment, document the exact blocker and fall back to the `.vcxproj` as the canonical build.
  - **Python bridge unit tests** (`tests/filter/test_bridge.py`): struct sizes match the C header (`sizeof(ARIA_SCAN_REQUEST) == 1028`); message parse extracts the path from raw bytes; reply builder produces correct bytes for safe/unsafe; `scan_verdict` maps a fake scanner's MALWARE→unsafe, CLEAN→safe, error→safe (fail-safe). Runs with no driver loaded, `fltlib` not required (import the module without connecting).
  - Full existing suite stays green; reachability unchanged (the driver + bridge aren't imported by `SentinelUI_Flask.py`).
- **NOT provable here (documented as manual):** loading the driver, the live kernel↔user round-trip, actual block-on-open. Requires admin + test-signing + reboot on a test machine/VM.

---

## 8. Scope / non-goals

- No auto-load/install; no changes to the running Flask app's reachability graph (standalone plugin).
- Not production-signed (test-sign only; production needs an EV cert + MS attestation/altitude allocation).
- Single client connection (the one Aria bridge). No per-process policy, no content streaming (path-only, per decision).

## 9. Deferred / future

- Production driver signing (EV + Microsoft attestation) and an allocated AV altitude.
- Auto-launch the bridge from the Aria service; wire kernel detections into `SentinelBrain` events.
- Optional content-streaming path and write/cleanup interception for freshly-written malware.
