"""Aria minifilter user-mode bridge.

Connects to the AriaFilter kernel driver's communication port (via fltlib),
receives scan requests (a file path), runs the real Aria VirusScanner, and
replies with a verdict. The kernel driver blocks the file open when the reply
says "unsafe".

Protocol mirrors Plugins/Filter/AriaFilter/AriaFilter.h byte-for-byte
(ARIA_SCAN_REQUEST == 1028 bytes). Fail-SAFE: any scanner error, or a missing
engine, yields "safe" (allow) — the kernel side likewise fails-open, so the two
agree to never block on an infrastructure problem, only on a real detection.

The module imports cleanly without the driver loaded or `fltlib` present; only
run() touches fltlib, so the pure logic (parse/build/verdict) is unit-testable.

Requires admin + a loaded AriaFilter driver to actually run(); see ../README.md.
"""
from __future__ import annotations
import ctypes
import sys

# ── protocol constants (match AriaFilter.h) ─────────────────────────────────
ARIA_PORT_NAME = "\\AriaFilterPort"
ARIA_MAX_PATH = 512
_MALWARE_VERDICTS = ("MALWARE", "SUSPICIOUS")

_ULONG = ctypes.c_ulong
_ULONGLONG = ctypes.c_ulonglong
_LONG = ctypes.c_long
_WCHAR = ctypes.c_wchar
_BYTE = ctypes.c_ubyte


# ── FltMgr message envelopes (fltUserStructures.h) ──────────────────────────
class FILTER_MESSAGE_HEADER(ctypes.Structure):
    _fields_ = [("ReplyLength", _ULONG), ("MessageId", _ULONGLONG)]


class FILTER_REPLY_HEADER(ctypes.Structure):
    _fields_ = [("Status", _LONG), ("MessageId", _ULONGLONG)]


# ── Aria protocol structs (AriaFilter.h) ────────────────────────────────────
class AriaScanRequest(ctypes.Structure):
    _pack_ = 8
    _fields_ = [("PathLength", _ULONG), ("Path", _WCHAR * ARIA_MAX_PATH)]


class AriaScanReply(ctypes.Structure):
    _pack_ = 8
    _fields_ = [("SafeToOpen", _BYTE)]


_HDR_SIZE = ctypes.sizeof(FILTER_MESSAGE_HEADER)
_REQ_SIZE = ctypes.sizeof(AriaScanRequest)
_MSG_SIZE = _HDR_SIZE + _REQ_SIZE


# ── pure logic (unit-testable, no driver/fltlib needed) ─────────────────────
def parse_request(buf: bytes):
    """(message_id, path) from a raw [FILTER_MESSAGE_HEADER][ARIA_SCAN_REQUEST]."""
    hdr = FILTER_MESSAGE_HEADER.from_buffer_copy(buf[:_HDR_SIZE])
    req = AriaScanRequest.from_buffer_copy(buf[_HDR_SIZE:_HDR_SIZE + _REQ_SIZE])
    n = min(int(req.PathLength), ARIA_MAX_PATH - 1)
    return int(hdr.MessageId), req.Path[:n]


def build_reply(message_id: int, safe: bool) -> bytes:
    """Raw [FILTER_REPLY_HEADER][ARIA_SCAN_REPLY] bytes for FilterReplyMessage."""
    hdr = FILTER_REPLY_HEADER(Status=0, MessageId=message_id)
    rep = AriaScanReply(SafeToOpen=1 if safe else 0)
    return bytes(hdr) + bytes(rep)


_scanner_singleton = None


def _get_scanner():
    """Lazily build the real VirusScanner; None if the engine can't load."""
    global _scanner_singleton
    if _scanner_singleton is None:
        try:
            from Engine.Compiler.SentinelCompiler_v5 import VirusScanner
            _scanner_singleton = VirusScanner()
        except Exception:
            return None
    return _scanner_singleton


def scan_verdict(path: str, scanner=None) -> bool:
    """True == safe to open. Fail-safe: any error / no engine -> True (allow);
    block only on an explicit MALWARE/SUSPICIOUS verdict."""
    try:
        sc = scanner if scanner is not None else _get_scanner()
        if sc is None:
            return True
        result = sc.scan_file(path) or {}
        verdict = str(result.get("verdict", "") or "").upper()
        return verdict not in _MALWARE_VERDICTS
    except Exception:
        return True


# ── driver connection loop (needs admin + loaded driver; not unit-tested) ───
def run():  # pragma: no cover - requires the loaded kernel driver
    fltlib = ctypes.WinDLL("fltlib")
    fltlib.FilterConnectCommunicationPort.argtypes = [
        ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ushort,
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    fltlib.FilterConnectCommunicationPort.restype = ctypes.c_long
    fltlib.FilterGetMessage.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_ulong, ctypes.c_void_p]
    fltlib.FilterGetMessage.restype = ctypes.c_long
    fltlib.FilterReplyMessage.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_ulong]
    fltlib.FilterReplyMessage.restype = ctypes.c_long

    port = ctypes.c_void_p()
    hr = fltlib.FilterConnectCommunicationPort(
        ARIA_PORT_NAME, 0, None, 0, None, ctypes.byref(port))
    if hr != 0:
        raise OSError(f"FilterConnectCommunicationPort failed hr=0x{hr & 0xffffffff:08x} "
                      "(is AriaFilter loaded? run as admin)")
    print("[aria-bridge] connected to", ARIA_PORT_NAME, flush=True)
    try:
        while True:
            buf = (ctypes.c_char * _MSG_SIZE)()
            hr = fltlib.FilterGetMessage(port, buf, _MSG_SIZE, None)
            if hr != 0:
                print(f"[aria-bridge] FilterGetMessage hr=0x{hr & 0xffffffff:08x}", flush=True)
                continue
            mid, path = parse_request(bytes(buf))
            safe = scan_verdict(path)
            if not safe:
                print(f"[aria-bridge] BLOCK {path}", flush=True)
            reply = build_reply(mid, safe)
            rbuf = (ctypes.c_char * len(reply)).from_buffer_copy(reply)
            fltlib.FilterReplyMessage(port, rbuf, len(reply))
    finally:
        ctypes.windll.kernel32.CloseHandle(port)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run())
