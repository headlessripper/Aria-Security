import types
from Argus import tools


def test_kind_lookup():
    assert tools.kind("get_threats") == "read"
    assert tools.kind("block_ip") == "action"
    assert tools.kind("nope") is None


def test_run_unknown():
    assert tools.run("nope", "") == "Unknown command: nope"


def test_get_protection_level(monkeypatch):
    fake_av = types.SimpleNamespace(get_protection_level=lambda: 87)
    monkeypatch.setattr(tools, "_avbrain", lambda: fake_av)
    assert "87" in tools.run("get_protection_level", "")


def test_get_threats_none(monkeypatch):
    monkeypatch.setattr(tools, "_avbrain", lambda: types.SimpleNamespace(get_active_threats=lambda: []))
    assert tools.run("get_threats", "") == "No active threats."


def test_block_ip_executes(monkeypatch):
    calls = {}
    fake_brain = types.SimpleNamespace(emit_block=lambda ip, reason: calls.update(ip=ip, reason=reason))
    monkeypatch.setattr(tools, "_brain", lambda: fake_brain)
    out = tools.run("block_ip", "1.2.3.4")
    assert calls["ip"] == "1.2.3.4"
    assert "1.2.3.4" in out


def test_scan_file_no_scanner():
    tools.set_scanner_provider(lambda: None)
    assert "not available" in tools.run("scan_file", r"C:\x.exe").lower()


def test_scan_file_with_scanner(monkeypatch):
    svc = types.SimpleNamespace(scan_file=lambda p: {"verdict": "MALWARE", "reasons": ["yara:x"]})
    tools.set_scanner_provider(lambda: svc)
    out = tools.run("scan_file", r"C:\evil.exe")
    assert "MALWARE" in out


def test_handler_exception_is_safe(monkeypatch):
    def boom():
        raise RuntimeError("kaboom")
    monkeypatch.setattr(tools, "_avbrain", lambda: (_ for _ in ()).throw(RuntimeError("kaboom")))
    out = tools.run("get_protection_level", "")
    assert out.startswith("⚠") and "get_protection_level" in out
