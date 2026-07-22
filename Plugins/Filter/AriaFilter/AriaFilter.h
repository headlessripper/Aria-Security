/*++

    AriaFilter.h  --  Shared port protocol for the Aria Security minifilter.

    This header is the single source of truth for the kernel<->user-mode
    communication protocol. The Python bridge (aria_filter_bridge.py) mirrors
    these structures byte-for-byte with ctypes; a unit test asserts the sizes
    match. Keep the two in sync.

--*/

#pragma once

//
// Name of the FltMgr communication port the driver creates and the user-mode
// bridge connects to.
//
#define ARIA_PORT_NAME   L"\\AriaFilterPort"

//
// Load-order altitude. 320000 is inside the "FSFilter Anti-Virus" range
// (320000-329999). This is a DEVELOPMENT altitude; a production driver needs an
// altitude allocated by Microsoft. Must match AriaFilter.inf.
//
#define ARIA_ALTITUDE    L"320000"

//
// Maximum path length carried in a scan request, in WCHARs (includes room for a
// terminating NUL).
//
#define ARIA_MAX_PATH    512

#pragma pack(push, 8)

//
// Driver -> bridge: "please produce a verdict for this file".
// sizeof == 4 (PathLength) + 2*512 (Path) == 1028 bytes.
//
typedef struct _ARIA_SCAN_REQUEST {
    unsigned long PathLength;            // number of WCHARs used in Path (excl. NUL)
    wchar_t       Path[ARIA_MAX_PATH];   // normalized file path
} ARIA_SCAN_REQUEST, *PARIA_SCAN_REQUEST;

//
// Bridge -> driver: the verdict. SafeToOpen == 0 means block the open.
//
typedef struct _ARIA_SCAN_REPLY {
    unsigned char SafeToOpen;            // 0 => block (STATUS_VIRUS_INFECTED), else allow
} ARIA_SCAN_REPLY, *PARIA_SCAN_REPLY;

#pragma pack(pop)
