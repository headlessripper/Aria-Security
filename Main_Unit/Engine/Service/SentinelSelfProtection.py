# SentinelSelfProtection.py
# Hardens the Sentinel process against external tampering.
#
# Layers applied:
#   1. DEP (Data Execution Prevention) — blocks shellcode on the stack/heap
#   2. Heap-terminate-on-corruption  — crashes fast before exploits spread
#   3. ASLR enforcement              — randomises stack/heap layout
#   4. DACL deny-terminate           — prevents ordinary processes from killing Sentinel
#
# Call activate_self_protection() once at startup.
# Every sub-step soft-fails so a missing API never crashes the app.

from __future__ import annotations
import ctypes
import ctypes.wintypes
import os


def _log(msg: str) -> None:
    print(f"[SelfProt] {msg}")


def _enable_dep() -> None:
    """Enable DEP for this process (also disables ATL thunk emulation)."""
    try:
        ctypes.windll.kernel32.SetProcessDEPPolicy(3)
    except Exception:
        pass


def _enable_heap_terminate_on_corruption() -> None:
    """Crash immediately on heap corruption — blocks heap-spray exploits."""
    try:
        ctypes.windll.kernel32.HeapSetInformation(None, 1, None, 0)
    except Exception:
        pass


def _enable_aslr() -> None:
    """Apply high-entropy ASLR via NtSetInformationProcess (Windows 8+)."""
    try:
        # ProcessMitigationPolicy = 52; index 1 = ProcessASLRPolicy
        policy = ctypes.c_uint64(
            0x01 |  # EnableBottomUpRandomization
            0x02 |  # EnableForceRelocateImages
            0x04    # EnableHighEntropy
        )
        ctypes.windll.ntdll.NtSetInformationProcess(
            ctypes.windll.kernel32.GetCurrentProcess(),
            52,
            ctypes.byref(policy),
            ctypes.sizeof(policy),
        )
    except Exception:
        pass


def _set_dacl_deny_terminate() -> None:
    """
    Add a Deny-PROCESS_TERMINATE ACE for the Everyone SID to this process
    DACL.  Ordinary (non-elevated) processes can no longer terminate Sentinel.
    SYSTEM / UAC-elevated processes are unaffected.
    """
    try:
        import win32security
        import win32api

        PROCESS_ALL_ACCESS = 0x1F0FFF
        PROCESS_TERMINATE  = 0x0001

        handle = win32api.OpenProcess(PROCESS_ALL_ACCESS, False, os.getpid())
        sd = win32security.GetKernelObjectSecurity(
            handle, win32security.DACL_SECURITY_INFORMATION
        )
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            dacl = win32security.ACL()

        everyone = win32security.CreateWellKnownSid(win32security.WinWorldSid, None)
        dacl.AddAccessDeniedAce(win32security.ACL_REVISION, PROCESS_TERMINATE, everyone)

        sd.SetSecurityDescriptorDacl(True, dacl, False)
        win32security.SetKernelObjectSecurity(
            handle, win32security.DACL_SECURITY_INFORMATION, sd
        )
        handle.Close()
        _log("DACL deny-terminate set — process protected from unauthorised kill")
    except ImportError:
        _log("pywin32 not available — DACL protection skipped")
    except Exception as e:
        _log(f"DACL protection skipped: {e}")


def activate_self_protection() -> None:
    """
    Harden the Sentinel process.
    Call once from start_app() before the main window is shown.
    Never raises — every step soft-fails independently.
    """
    _log("Activating self-protection…")
    _enable_dep()
    _enable_heap_terminate_on_corruption()
    _enable_aslr()
    _set_dacl_deny_terminate()
    _log("Self-protection active")
