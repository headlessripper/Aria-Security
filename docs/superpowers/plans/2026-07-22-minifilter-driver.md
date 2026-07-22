# Aria Minifilter Driver Implementation Plan

> **For agentic workers:** VISUAL/SYSTEMS phase executed INLINE with build + pytest gates (kernel C + a hand-rolled WDK build needs direct iteration). Steps use checkbox (`- [ ]`) syntax.

**Goal:** A Windows kernel-mode filesystem minifilter (`Plugins/Filter/`) that hooks file opens (post `IRP_MJ_CREATE`), asks the user-mode Aria scanner for a verdict over an FltMgr communication port, and fails the open (`STATUS_VIRUS_INFECTED`) for detected malware — plus a Python bridge that runs the real `VirusScanner`, a hand-rolled build, and install docs.

**Architecture:** Non-KMDF minifilter (`AriaFilter.sys`) using FltMgr directly + a Python user-mode bridge (`ctypes`→`fltlib`). Path-only protocol in a shared header. Fail-open (kernel) / fail-safe (bridge) on any infrastructure failure — block only on a positive detection.

**Tech Stack:** C (WDK/FltMgr), Python 3 `ctypes`, WDK headers/libs (`10.0.26100.0`), `cl.exe`/`link.exe` (VS2022), `stampinf`/`signtool`, pytest.

## Global Constraints

- Use `.venv/Scripts/python.exe` for python/pytest.
- The assistant does NOT load/install the driver (needs admin + test-signing + reboot; BSOD risk). Build + docs only.
- Port protocol structs must be **byte-identical** between `AriaFilter.h` (C) and the Python `ctypes` mirror; a unit test asserts `sizeof(ARIA_SCAN_REQUEST) == 1028`.
- Fail-safe everywhere: kernel fails-open on send timeout/error; bridge returns "safe" on any scanner error or missing engine. Block only on an explicit MALWARE/SUSPICIOUS verdict.
- Driver + bridge are a standalone plugin — NOT imported by `SentinelUI_Flask.py`; `EXPECTED_LIVE` (45) must stay unchanged.
- Never `git add` `.sys`/`.obj`/PE build outputs (they're PE — the repo's own scanner quarantines PE in `.git`); add build artifacts to `.gitignore`. Commit only source (`.c/.h/.inf/.rc/.vcxproj/.bat/.py/.md`). Do not touch `.venv/`, `cleanup/`, `.superpowers/`, `Config/sentinel_whitelist.json`.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

---

## File Structure

- `Plugins/Filter/AriaFilter/AriaFilter.h` — shared port protocol (name, structs, altitude).
- `Plugins/Filter/AriaFilter/AriaFilter.c` — the minifilter driver.
- `Plugins/Filter/AriaFilter/AriaFilter.inf` — install information.
- `Plugins/Filter/AriaFilter/AriaFilter.rc` — version resource.
- `Plugins/Filter/AriaFilter/AriaFilter.vcxproj` — WDK VS project (for integrated machines).
- `Plugins/Filter/AriaFilter/build.bat` — hand-rolled cl/link build.
- `Plugins/Filter/AriaFilterBridge/aria_filter_bridge.py` — Python user-mode service.
- `Plugins/Filter/README.md` — build/test-sign/install/risks.
- `Plugins/Filter/.gitignore` — ignore build outputs (`*.sys *.obj *.pdb *.lib *.exp *.cer`).
- `tests/filter/test_bridge.py` — bridge unit tests (struct parity, parse/build, verdict).

---

### Task 1: Shared port header `AriaFilter.h`

**Files:** Create `Plugins/Filter/AriaFilter/AriaFilter.h`

- [ ] Write the header (the single source of truth for the protocol; both C and Python match it):
```c
#pragma once
// Shared port protocol for the Aria minifilter <-> user-mode bridge.
#define ARIA_PORT_NAME   L"\\AriaFilterPort"
#define ARIA_ALTITUDE    L"320000"   // dev altitude (FSFilter Anti-Virus range)
#define ARIA_MAX_PATH    512         // WCHARs

#pragma pack(push, 8)
typedef struct _ARIA_SCAN_REQUEST {
    unsigned long PathLength;         // WCHARs used (excl. NUL)
    wchar_t       Path[ARIA_MAX_PATH];
} ARIA_SCAN_REQUEST, *PARIA_SCAN_REQUEST;

typedef struct _ARIA_SCAN_REPLY {
    unsigned char SafeToOpen;         // 0 => block the open
} ARIA_SCAN_REPLY, *PARIA_SCAN_REPLY;
#pragma pack(pop)
// sizeof(ARIA_SCAN_REQUEST) == 4 + 2*512 == 1028
```
- [ ] Commit `AriaFilter.h`.

---

### Task 2: Kernel driver `AriaFilter.c`

**Files:** Create `Plugins/Filter/AriaFilter/AriaFilter.c`

**Interfaces:** consumes `AriaFilter.h`. Produces `AriaFilter.sys` (built in Task 3).

- [ ] Write the driver. Key structure (full file written during execution; the load-bearing pieces):
```c
#include <fltKernel.h>
#include "AriaFilter.h"

PFLT_FILTER   gFilter = NULL;
PFLT_PORT     gServerPort = NULL;
PFLT_PORT     gClientPort = NULL;

// --- comm port callbacks ---
NTSTATUS AriaPortConnect(PFLT_PORT ClientPort, PVOID, PVOID, ULONG, PVOID*) {
    gClientPort = ClientPort; return STATUS_SUCCESS;
}
VOID AriaPortDisconnect(PVOID) {
    FltCloseClientPort(gFilter, &gClientPort); gClientPort = NULL;
}
NTSTATUS AriaPortMessage(PVOID, PVOID, ULONG, PVOID, ULONG, PULONG ReturnLen) {
    *ReturnLen = 0; return STATUS_SUCCESS;   // bridge -> driver not used
}

// --- post-create: scan-on-open, block infected ---
FLT_POSTOP_CALLBACK_STATUS
PostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
           PVOID, FLT_POST_OPERATION_FLAGS Flags) {
    if (Flags & FLTFL_POST_OPERATION_DRAINING) return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE)
        return FLT_POSTOP_FINISHED_PROCESSING;
    if (!gClientPort) return FLT_POSTOP_FINISHED_PROCESSING;
    if (Data->RequestorMode == KernelMode) return FLT_POSTOP_FINISHED_PROCESSING;

    PFLT_FILE_NAME_INFORMATION nameInfo;
    if (!NT_SUCCESS(FltGetFileNameInformation(Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
        return FLT_POSTOP_FINISHED_PROCESSING;
    FltParseFileNameInformation(nameInfo);

    ARIA_SCAN_REQUEST req; RtlZeroMemory(&req, sizeof(req));
    ULONG chars = min(nameInfo->Name.Length / sizeof(WCHAR), ARIA_MAX_PATH - 1);
    RtlCopyMemory(req.Path, nameInfo->Name.Buffer, chars * sizeof(WCHAR));
    req.PathLength = chars;
    FltReleaseFileNameInformation(nameInfo);

    ARIA_SCAN_REPLY reply; ULONG replyLen = sizeof(reply);
    LARGE_INTEGER timeout; timeout.QuadPart = -50000000LL; // 5s (100ns units, relative)
    NTSTATUS st = FltSendMessage(gFilter, &gClientPort, &req, sizeof(req),
                                 &reply, &replyLen, &timeout);
    if (st == STATUS_SUCCESS && replyLen == sizeof(reply) && reply.SafeToOpen == 0) {
        Data->IoStatus.Status = STATUS_VIRUS_INFECTED;   // block the open
        Data->IoStatus.Information = 0;
    }
    // any other result (timeout/error) => fail-open (allow)
    return FLT_POSTOP_FINISHED_PROCESSING;
}

const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, NULL, PostCreate },
    { IRP_MJ_OPERATION_END }
};
NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS) {
    if (gServerPort) FltCloseCommunicationPort(gServerPort);
    if (gFilter) FltUnregisterFilter(gFilter);
    return STATUS_SUCCESS;
}
const FLT_REGISTRATION Registration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL,
    Callbacks, FilterUnload, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
    NTSTATUS st = FltRegisterFilter(DriverObject, &Registration, &gFilter);
    if (!NT_SUCCESS(st)) return st;
    UNICODE_STRING name; RtlInitUnicodeString(&name, ARIA_PORT_NAME);
    PSECURITY_DESCRIPTOR sd;
    st = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(st)) {
        OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, &name,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
        st = FltCreateCommunicationPort(gFilter, &gServerPort, &oa, NULL,
            AriaPortConnect, AriaPortDisconnect, AriaPortMessage, 1);
        FltFreeSecurityDescriptor(sd);
    }
    if (!NT_SUCCESS(st)) { FltUnregisterFilter(gFilter); return st; }
    st = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(st)) { FltCloseCommunicationPort(gServerPort); FltUnregisterFilter(gFilter); }
    return st;
}
```
- [ ] Commit `AriaFilter.c`.

---

### Task 3: Build files + compile `AriaFilter.sys`

**Files:** Create `AriaFilter.inf`, `AriaFilter.rc`, `AriaFilter.vcxproj`, `build.bat`, `Plugins/Filter/.gitignore`

- [ ] `.gitignore`: `*.sys` `*.obj` `*.pdb` `*.lib` `*.exp` `*.cer` `*.cat` build dirs.
- [ ] `AriaFilter.inf` — minifilter service install: `ServiceType=2` (FILE_SYSTEM_DRIVER), `StartType=3` (DEMAND), `LoadOrderGroup="FSFilter Anti-Virus"`, `Altitude=320000`, `Dependencies=FltMgr`, DefaultInstall + AddRegistry `Instances`.
- [ ] `AriaFilter.rc` — `VS_VERSION_INFO` (product "Aria Security Minifilter", `VFT_DRV`).
- [ ] `AriaFilter.vcxproj` — `WindowsKernelModeDriver10.0` toolset, `Driver` type `KMDF`? No — `WDM`/non-KMDF minifilter; for machines with WDK-VS integration.
- [ ] `build.bat` — detect newest `Windows Kits\10\{Include,Lib}\<ver>`; call `vcvarsall.bat x64`; `cl /kernel /c /I<km> /I<shared> /I<km\crt> AriaFilter.c`; `link /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB /LIBPATH:<km\x64> fltMgr.lib ntoskrnl.lib hal.lib wdmsec.lib AriaFilter.obj /OUT:AriaFilter.sys`; then `stampinf` + self-signed test `signtool`.
- [ ] **Run `build.bat`.** Expected: `AriaFilter.sys` produced. If the CLI kernel build hits an environment blocker (missing target, header conflict), capture the exact error in `README.md` and rely on the `.vcxproj` as the canonical build path — the source stays correct.
- [ ] Commit source build files (NOT the `.sys`).

---

### Task 4: Python bridge + unit tests

**Files:** Create `Plugins/Filter/AriaFilterBridge/aria_filter_bridge.py`, `tests/filter/__init__.py`, `tests/filter/test_bridge.py`

**Interfaces:** mirrors `AriaFilter.h`. `AriaScanRequest` (`ctypes`) size == 1028. `scan_verdict(path, scanner=None) -> bool`.

- [ ] Write `aria_filter_bridge.py`:
  - `ctypes.Structure` mirrors: `FILTER_MESSAGE_HEADER{ReplyLength:ULONG, MessageId:ULONGLONG}`, `FILTER_REPLY_HEADER{Status:LONG, MessageId:ULONGLONG}`, `AriaScanRequest{PathLength:ULONG, Path:WCHAR*512}` (`_pack_=8`), `AriaScanReply{SafeToOpen:BYTE}`.
  - `parse_request(buf: bytes) -> (message_id:int, path:str)`.
  - `build_reply(message_id:int, safe:bool) -> bytes`.
  - `scan_verdict(path, scanner=None) -> bool` — lazy-import `VirusScanner`; MALWARE/SUSPICIOUS → False; anything else / any exception / no engine → True (fail-safe).
  - `run()` — `ctypes.WinDLL("fltlib")`, `FilterConnectCommunicationPort`, loop `FilterGetMessage`/verdict/`FilterReplyMessage`. Guarded so `import`/tests work without `fltlib` or a driver.
- [ ] Write `tests/filter/test_bridge.py`:
```python
import ctypes, types
from Plugins.Filter.AriaFilterBridge import aria_filter_bridge as b

def test_request_struct_size_matches_c_header():
    assert ctypes.sizeof(b.AriaScanRequest) == 1028   # 4 + 2*512

def test_parse_then_build_roundtrip():
    mid = 42
    hdr = b.FILTER_MESSAGE_HEADER(ReplyLength=0, MessageId=mid)
    req = b.AriaScanRequest(); p = r"C:\x\evil.exe"
    req.PathLength = len(p); req.Path = p
    raw = bytes(hdr) + bytes(req)
    got_mid, got_path = b.parse_request(raw)
    assert got_mid == mid and got_path == p
    reply = b.build_reply(mid, safe=False)
    rh = b.FILTER_REPLY_HEADER.from_buffer_copy(reply[:ctypes.sizeof(b.FILTER_REPLY_HEADER)])
    assert rh.MessageId == mid
    ar = b.AriaScanReply.from_buffer_copy(reply[ctypes.sizeof(b.FILTER_REPLY_HEADER):])
    assert ar.SafeToOpen == 0

def test_scan_verdict_malware_unsafe():
    fake = types.SimpleNamespace(scan_file=lambda p: {"verdict": "MALWARE"})
    assert b.scan_verdict("x", scanner=fake) is False

def test_scan_verdict_clean_safe():
    fake = types.SimpleNamespace(scan_file=lambda p: {"verdict": "CLEAN"})
    assert b.scan_verdict("x", scanner=fake) is True

def test_scan_verdict_error_fails_safe():
    def boom(p): raise RuntimeError("x")
    fake = types.SimpleNamespace(scan_file=boom)
    assert b.scan_verdict("x", scanner=fake) is True
```
- [ ] Run `.venv/Scripts/python.exe -m pytest tests/filter/ -q` → pass.
- [ ] Commit bridge + tests + `Plugins/Filter/AriaFilterBridge/__init__.py` + `Plugins/Filter/__init__.py`.

---

### Task 5: README + final verification

**Files:** Create `Plugins/Filter/README.md`

- [ ] `README.md`: architecture summary; build (`build.bat` / `.vcxproj`); **install** (admin: `bcdedit /set testsigning on` + reboot; create+trust self-signed test cert; copy INF; `fltmc load AriaFilter`; start `aria_filter_bridge.py`); **uninstall** (`fltmc unload`); explicit **BSOD/test-in-a-VM** warning; note test-sign-only + dev altitude.
- [ ] `.venv/Scripts/python.exe -m pytest tests/ -q` → full suite green (incl. new filter tests).
- [ ] `.venv/Scripts/python.exe scripts/verify_reachability.py` → PASS, `EXPECTED_LIVE` still 45 (driver/bridge not imported by the entry point).
- [ ] Report build outcome (`AriaFilter.sys` built, or the documented environment blocker + `.vcxproj` fallback).
- [ ] Commit `README.md`.

---

## Self-Review

**Spec coverage:** header/protocol → T1; driver (post-create scan-on-open, port, block, unload, fail-open) → T2; INF/rc/vcxproj/build.bat + compile → T3; Python bridge (path-only, fail-safe verdict, struct mirror) + tests → T4; README/install/risks + final gates → T5. All spec §3–§7 mapped.

**Placeholder scan:** real code for header, driver core, bridge tests. `build.bat` + `.vcxproj` + `.inf` + `.rc` bodies are described precisely (exact flags/keys) and written in full during execution — flagged, not vague.

**Type consistency:** `ARIA_SCAN_REQUEST` (C) == `AriaScanRequest` (ctypes), both 1028 bytes (`ULONG`+`WCHAR[512]`), asserted by `test_request_struct_size_matches_c_header`. `ARIA_PORT_NAME`/`ARIA_ALTITUDE`/`ARIA_MAX_PATH` shared. `scan_verdict` MALWARE/SUSPICIOUS→False consistent between spec §5 and T4 tests.
