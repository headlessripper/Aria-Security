/*++

    AriaFilter.c  --  Aria Security on-access anti-virus minifilter.

    A non-KMDF filesystem minifilter modeled on the WDK "scanner" sample. On
    every successful user-mode file open (post IRP_MJ_CREATE) it asks the
    user-mode Aria bridge for a verdict over an FltMgr communication port; if the
    bridge reports the file unsafe, the open is failed with STATUS_VIRUS_INFECTED.

    Safety posture: FAIL-OPEN. If no bridge is connected, or the round-trip times
    out or errors, the open is allowed. The driver never blocks I/O because of an
    infrastructure problem -- only on an explicit "unsafe" verdict.

    NOTE: development/test driver. Test-signing + an allocated altitude are
    required to load; see ../README.md. Loading a kernel driver can bug-check the
    machine -- test in a VM.

--*/

#include <fltKernel.h>
#include "AriaFilter.h"

//
// Globals: the filter, the server port, and the single connected client (bridge).
//
PFLT_FILTER gFilter      = NULL;
PFLT_PORT   gServerPort  = NULL;
PFLT_PORT   gClientPort  = NULL;

//
// Round-trip timeout for a verdict: 5 seconds, expressed as a negative
// (relative) 100-nanosecond interval for FltSendMessage.
//
#define ARIA_TIMEOUT_100NS  (-50000000LL)

//-----------------------------------------------------------------------------
//  Communication port callbacks
//-----------------------------------------------------------------------------

NTSTATUS
AriaPortConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
    )
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    gClientPort = ClientPort;
    if (ConnectionCookie) {
        *ConnectionCookie = NULL;
    }
    return STATUS_SUCCESS;
}

VOID
AriaPortDisconnect (
    _In_opt_ PVOID ConnectionCookie
    )
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    FltCloseClientPort(gFilter, &gClientPort);
    gClientPort = NULL;
}

NTSTATUS
AriaPortMessage (
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    //
    // The bridge does not push unsolicited messages to the driver; only the
    // driver -> bridge request/reply path (FltSendMessage) is used.
    //
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
}

//-----------------------------------------------------------------------------
//  Post-create: scan on open, block infected
//-----------------------------------------------------------------------------

FLT_POSTOP_CALLBACK_STATUS
AriaPostCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    ARIA_SCAN_REQUEST request;
    ARIA_SCAN_REPLY reply;
    ULONG replyLength = sizeof(reply);
    ULONG chars;
    LARGE_INTEGER timeout;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    //
    // Bail out cheaply on the common "nothing to do" cases.
    //
    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!NT_SUCCESS(Data->IoStatus.Status) ||
        Data->IoStatus.Status == STATUS_REPARSE) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (gClientPort == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;   // fail-open: no bridge connected
    }
    //
    // Skip kernel-originated opens (including the bridge's own file reads while
    // scanning) to avoid recursion and pointless work.
    //
    if (Data->RequestorMode == KernelMode) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;   // can't name it -> allow
    }
    FltParseFileNameInformation(nameInfo);

    //
    // Build the request: copy the normalized path (bounded), NUL-terminated.
    //
    RtlZeroMemory(&request, sizeof(request));
    chars = nameInfo->Name.Length / sizeof(WCHAR);
    if (chars > (ARIA_MAX_PATH - 1)) {
        chars = ARIA_MAX_PATH - 1;
    }
    RtlCopyMemory(request.Path, nameInfo->Name.Buffer, chars * sizeof(WCHAR));
    request.Path[chars] = L'\0';
    request.PathLength = chars;

    FltReleaseFileNameInformation(nameInfo);

    //
    // Ask the bridge. Any non-success / short reply -> fail-open (allow).
    //
    timeout.QuadPart = ARIA_TIMEOUT_100NS;
    status = FltSendMessage(
        gFilter, &gClientPort,
        &request, sizeof(request),
        &reply, &replyLength,
        &timeout);

    if (status == STATUS_SUCCESS &&
        replyLength == sizeof(reply) &&
        reply.SafeToOpen == 0) {
        //
        // Positive detection: fail the open.
        //
        Data->IoStatus.Status = STATUS_VIRUS_INFECTED;
        Data->IoStatus.Information = 0;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

//-----------------------------------------------------------------------------
//  Registration
//-----------------------------------------------------------------------------

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, NULL, AriaPostCreate },
    { IRP_MJ_OPERATION_END }
};

NTSTATUS
AriaFilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER(Flags);

    if (gServerPort != NULL) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }
    if (gFilter != NULL) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    return STATUS_SUCCESS;
}

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),           //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags
    NULL,                               //  Context registration
    Callbacks,                          //  Operation callbacks
    AriaFilterUnload,                   //  FilterUnload
    NULL,                               //  InstanceSetup
    NULL,                               //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete
    NULL, NULL, NULL, NULL              //  Name/GUID callbacks (unused)
};

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    UNICODE_STRING portName;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;

    UNREFERENCED_PARAMETER(RegistryPath);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilter);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Create the communication port the user-mode bridge connects to.
    //
    RtlInitUnicodeString(&portName, ARIA_PORT_NAME);
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(
            &oa, &portName,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
            NULL, sd);
        status = FltCreateCommunicationPort(
            gFilter, &gServerPort, &oa, NULL,
            AriaPortConnect, AriaPortDisconnect, AriaPortMessage, 1);
        FltFreeSecurityDescriptor(sd);
    }
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        return status;
    }

    status = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    return status;
}
