import os
import pytest
from Engine.Detection.cert_reputation import CertReputation

_EMBEDDED_SIGNED = [r"C:\Windows\explorer.exe", r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\dwm.exe"]

def _first_existing(paths):
    for p in paths:
        if os.path.exists(p):
            return p
    return None

def test_signed_windows_binary():
    exe = _first_existing(_EMBEDDED_SIGNED)
    if exe is None:
        pytest.skip("no embedded-signed system binary available")
    cr = CertReputation()
    r = cr.evaluate(exe)
    assert r["trusted"] is True and r["signed"] is True
    assert r["abused"] is False

def test_unsigned_file(tmp_path):
    p = tmp_path / "unsigned.exe"
    p.write_bytes(b"MZ" + b"\x00" * 2048)
    cr = CertReputation()
    r = cr.evaluate(str(p))
    assert r["trusted"] is False and r["signed"] is False
