"""
Tests for Sandbox hardening (Phase 3D Task 6):
  - diff_snapshots is a pure function that finds new processes + new connections
  - detonate() degrades gracefully to run_restricted when WSB is unavailable,
    and never performs a real detonation or raises in that path.

Adaptation note: the brief's illustrative stub calls
`sb.SandboxReport(status="restricted_ok")` with no other fields, but the real
SandboxReport dataclass has three required positional fields (file_path,
sha256, mode) with no defaults. Both tests below construct SandboxReport with
those three fields supplied explicitly, plus status=..., to match the real
dataclass signature.
"""
import Services.SentinelSandbox as sb


def test_diff_snapshots():
    before = {"procs": {1: "a.exe"}, "conns": {("1.2.3.4", 80)}}
    after = {"procs": {1: "a.exe", 2: "evil.exe"}, "conns": {("1.2.3.4", 80), ("9.9.9.9", 443)}}

    d = sb.diff_snapshots(before, after)

    assert d["new_processes"] == {2: "evil.exe"}
    assert ("9.9.9.9", 443) in d["new_connections"]
    assert ("1.2.3.4", 80) not in d["new_connections"]


def test_diff_snapshots_no_changes():
    snap = {"procs": {1: "a.exe"}, "conns": {("1.2.3.4", 80)}}

    d = sb.diff_snapshots(snap, snap)

    assert d["new_processes"] == {}
    assert d["new_connections"] == set()


def test_detonate_unavailable_is_graceful(tmp_path, monkeypatch):
    target = tmp_path / "x.exe"
    target.write_bytes(b"not a real pe")

    monkeypatch.setattr(sb, "_is_wsb_available", lambda: False)

    stub_report = sb.SandboxReport(
        file_path=str(target), sha256="", mode="restricted", status="restricted_ok",
    )
    called = {}

    def fake_run_restricted(p, **k):
        called["path"] = p
        return stub_report

    monkeypatch.setattr(sb, "run_restricted", fake_run_restricted)

    rep = sb.detonate(str(target))

    assert rep is stub_report
    assert rep.status == "restricted_ok"
    assert called["path"] == str(target)


def test_run_in_windows_sandbox_unavailable_returns_status_not_raise(tmp_path, monkeypatch):
    target = tmp_path / "x.exe"
    target.write_bytes(b"not a real pe")

    monkeypatch.setattr(sb, "_is_wsb_available", lambda: False)

    rep = sb.run_in_windows_sandbox(str(target))

    assert rep.status == "unavailable"
    assert rep.verdict == "ERROR"


def test_detonate_missing_file_is_graceful():
    rep = sb.detonate("C:/definitely/does/not/exist.exe")

    assert rep.status == "unavailable"
    assert rep.error == "File not found"
