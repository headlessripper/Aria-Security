"""Unit tests for the Aria minifilter user-mode bridge.

Pure logic only — no driver loaded, no fltlib. Verifies the ctypes protocol
mirror matches AriaFilter.h, the message parse/build round-trips, and the
verdict maps scanner results correctly (fail-safe on error)."""
import ctypes
import types

from Plugins.Filter.AriaFilterBridge import aria_filter_bridge as b


def test_request_struct_size_matches_c_header():
    # AriaFilter.h: ULONG(4) + WCHAR[512](1024) == 1028
    assert ctypes.sizeof(b.AriaScanRequest) == 1028


def test_reply_struct_size():
    assert ctypes.sizeof(b.AriaScanReply) == 1


def test_parse_then_build_roundtrip():
    mid = 42
    hdr = b.FILTER_MESSAGE_HEADER(ReplyLength=0, MessageId=mid)
    req = b.AriaScanRequest()
    p = r"C:\Users\me\evil.exe"
    req.PathLength = len(p)
    req.Path = p
    raw = bytes(hdr) + bytes(req)

    got_mid, got_path = b.parse_request(raw)
    assert got_mid == mid
    assert got_path == p

    reply = b.build_reply(mid, safe=False)
    rh = b.FILTER_REPLY_HEADER.from_buffer_copy(reply[:ctypes.sizeof(b.FILTER_REPLY_HEADER)])
    assert rh.MessageId == mid
    ar = b.AriaScanReply.from_buffer_copy(reply[ctypes.sizeof(b.FILTER_REPLY_HEADER):])
    assert ar.SafeToOpen == 0


def test_build_reply_safe_sets_flag():
    reply = b.build_reply(7, safe=True)
    ar = b.AriaScanReply.from_buffer_copy(reply[ctypes.sizeof(b.FILTER_REPLY_HEADER):])
    assert ar.SafeToOpen == 1


def test_scan_verdict_malware_unsafe():
    fake = types.SimpleNamespace(scan_file=lambda p: {"verdict": "MALWARE"})
    assert b.scan_verdict("x", scanner=fake) is False


def test_scan_verdict_suspicious_unsafe():
    fake = types.SimpleNamespace(scan_file=lambda p: {"verdict": "SUSPICIOUS"})
    assert b.scan_verdict("x", scanner=fake) is False


def test_scan_verdict_clean_safe():
    fake = types.SimpleNamespace(scan_file=lambda p: {"verdict": "CLEAN"})
    assert b.scan_verdict("x", scanner=fake) is True


def test_scan_verdict_error_fails_safe():
    def boom(p):
        raise RuntimeError("scanner exploded")
    fake = types.SimpleNamespace(scan_file=boom)
    assert b.scan_verdict("x", scanner=fake) is True


def test_scan_verdict_none_result_safe():
    fake = types.SimpleNamespace(scan_file=lambda p: None)
    assert b.scan_verdict("x", scanner=fake) is True
