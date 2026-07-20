import types
from Services.monitors import process_monitor as pm


def test_risk_score_benign_is_zero():
    assert pm.risk_score("explorer.exe", r"C:\Windows\explorer.exe", 1234) == 0


def test_risk_score_miner_keyword():
    assert pm.risk_score("cryptominer.exe", r"C:\x\cryptominer.exe", 1000) >= 50


def test_risk_score_missing_exe_adds_25():
    # exe path that does not exist on disk -> +25
    assert pm.risk_score("weird.exe", r"C:\does\not\exist_xyz.exe", 1000) >= 25


def test_risk_score_temp_dir():
    assert pm.risk_score("a.exe", r"C:\Users\x\AppData\Local\Temp\a.exe", 1000) >= 20


def test_risk_score_capped_at_100():
    # Original brief inputs ("m.exe", ppid=1000) can't reach 100: m.exe has no
    # miner keyword, and ppid=1000 doesn't trigger the ppid-0/4 bonus, so the
    # true sum is only 25 (missing exe) + 20 (temp) + 10 (short name) = 55.
    # Reworked inputs below are self-consistent with the authoritative
    # risk_score constants and genuinely exceed 100 before capping:
    #   miner keyword (50) + ppid in (0,4) & "system" not in name (15)
    #   + missing exe on disk (25) + temp dir in path (20) = 110 -> capped to 100.
    # "miner.exe" is 9 chars, so the <=5-char short-name bonus does not apply
    # (and cannot combine with a keyword hit anyway, since every keyword is
    # itself >=5 chars).
    assert pm.risk_score("miner.exe", r"C:\Temp\miner.exe", 0) == 100


class _FakeProc:
    def __init__(self, info):
        self.info = info


def _fake_iter(rows):
    def _it(attrs=None):
        return [_FakeProc(r) for r in rows]
    return _it


def test_process_threats_shape_and_sort(monkeypatch):
    rows = [
        {"pid": 1, "name": "explorer.exe", "exe": r"C:\Windows\explorer.exe", "ppid": 1},
        {"pid": 2, "name": "cryptominer.exe", "exe": r"C:\x\cryptominer.exe", "ppid": 1},
    ]
    monkeypatch.setattr(pm.psutil, "process_iter", _fake_iter(rows))
    out = pm.process_threats()
    assert out[0]["name"] == "cryptominer.exe"  # highest score first
    assert set(out[0].keys()) == {"pid", "name", "path", "score"}


def test_task_list_sorted_by_mb(monkeypatch):
    rows = [
        {"pid": 1, "name": "a", "exe": "", "status": "running",
         "cpu_percent": 1.0, "memory_info": types.SimpleNamespace(rss=1048576)},
        {"pid": 2, "name": "b", "exe": "", "status": "running",
         "cpu_percent": 2.0, "memory_info": types.SimpleNamespace(rss=5 * 1048576)},
    ]
    monkeypatch.setattr(pm.psutil, "process_iter", _fake_iter(rows))
    out = pm.task_list()
    assert out[0]["pid"] == 2 and out[0]["mb"] == 5.0
    assert set(out[0].keys()) == {"pid", "name", "status", "cpu", "mb", "path"}


def test_kill_not_found(monkeypatch):
    class _NSP(Exception):
        pass
    monkeypatch.setattr(pm.psutil, "NoSuchProcess", _NSP)
    def _raise(pid):
        raise _NSP()
    monkeypatch.setattr(pm.psutil, "Process", _raise)
    assert pm.kill(999999) == {"error": "process not found"}
