import types
from Services.monitors import system_monitor as sm


class _FakeProc:
    def __init__(self, info):
        self.info = info


def test_memory_snapshot_shape(monkeypatch):
    monkeypatch.setattr(sm.psutil, "virtual_memory",
                        lambda: types.SimpleNamespace(total=100, used=40, free=60, percent=40.0))
    monkeypatch.setattr(sm.psutil, "Process",
                        lambda: types.SimpleNamespace(memory_info=lambda: types.SimpleNamespace(rss=2 * 1048576)))
    procs = [
        _FakeProc({"pid": 1, "name": "a", "memory_info": types.SimpleNamespace(rss=1 * 1048576)}),
        _FakeProc({"pid": 2, "name": "b", "memory_info": types.SimpleNamespace(rss=9 * 1048576)}),
    ]
    monkeypatch.setattr(sm.psutil, "process_iter", lambda attrs=None: procs)
    out = sm.memory_snapshot()
    assert out["total"] == 100 and out["sentinel_mb"] == 2.0
    assert out["top_procs"][0]["pid"] == 2  # sorted by mb desc
    assert set(out.keys()) == {"total", "used", "free", "percent", "sentinel_mb", "top_procs"}


def test_list_disks_shape(monkeypatch):
    part = types.SimpleNamespace(device="C:\\", mountpoint="C:\\", fstype="NTFS")
    monkeypatch.setattr(sm.psutil, "disk_partitions", lambda all=False: [part])
    monkeypatch.setattr(sm.psutil, "disk_usage",
                        lambda mp: types.SimpleNamespace(total=100, used=30, free=70, percent=30.0))
    out = sm.list_disks()
    assert out[0]["device"] == "C:\\" and out[0]["percent"] == 30.0
    assert set(out[0].keys()) == {"device", "mountpoint", "fstype", "total", "used", "free", "percent"}
