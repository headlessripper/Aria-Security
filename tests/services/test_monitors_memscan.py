import types
from Services.monitors import mem_scan


class _FakeScanner:
    def __init__(self, verdicts):
        self._v = verdicts  # dict: exe -> verdict dict
    def scan_file(self, exe):
        return self._v.get(exe)


def _fake_iter(rows):
    def _it(attrs=None):
        return [types.SimpleNamespace(info=r) for r in rows]
    return _it


def test_scan_collects_only_threats(monkeypatch, tmp_path):
    good = tmp_path / "good.exe"; good.write_text("x")
    bad = tmp_path / "bad.exe"; bad.write_text("x")
    rows = [
        {"pid": 1, "name": "good.exe", "exe": str(good)},
        {"pid": 2, "name": "bad.exe", "exe": str(bad)},
    ]
    monkeypatch.setattr(mem_scan.psutil, "process_iter", _fake_iter(rows))
    scanner = _FakeScanner({
        str(good): {"verdict": "CLEAN"},
        str(bad): {"verdict": "MALWARE", "reasons": ["a", "b", "c", "d"]},
    })
    threats = []
    progress = []
    out = mem_scan.scan_processes(
        scanner,
        on_progress=lambda c, t: progress.append((c, t)),
        on_threat=lambda row: threats.append(row),
    )
    assert len(out) == 1 and out[0]["pid"] == 2 and out[0]["verdict"] == "MALWARE"
    assert out[0]["reasons"] == ["a", "b", "c"]  # capped at 3
    assert threats == out
    assert progress and progress[0][1] == 2  # total reported


def test_scan_skips_missing_exe(monkeypatch):
    rows = [{"pid": 3, "name": "ghost.exe", "exe": r"C:\nope\ghost_xyz.exe"}]
    monkeypatch.setattr(mem_scan.psutil, "process_iter", _fake_iter(rows))
    called = {"n": 0}
    class _S:
        def scan_file(self, exe):
            called["n"] += 1
            return {"verdict": "MALWARE"}
    out = mem_scan.scan_processes(_S())
    assert out == [] and called["n"] == 0  # never scanned a nonexistent exe
