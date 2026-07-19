from Services.Sense.SentinelSense import SentinelSense


def test_lifecycle(fake_brain):
    s = SentinelSense(brain=fake_brain)
    s.start()
    assert s.is_running() is True
    s.stop()
    assert s.is_running() is False


def test_new_suspicious_install_emits(fake_brain, monkeypatch):
    s = SentinelSense(brain=fake_brain)
    # drive two snapshots through the internal handler with an injected classifier
    before = {"AppA": {"name": "AppA", "publisher": "Acme", "install_location": r"C:\Program Files\A", "main_exe": None}}
    after = dict(before)
    after["Evil"] = {"name": "Evil", "publisher": "", "install_location": r"C:\Users\u\AppData\Local\Temp\evil", "main_exe": None}
    s._process_snapshot(before, after)   # helper: diffs + classifies + emits
    assert any("Suspicious" in (t.get("title", "")) or t.get("category") for t in fake_brain.threats)


def test_benign_install_no_emit(fake_brain):
    s = SentinelSense(brain=fake_brain)
    before = {"AppA": {"name": "AppA", "publisher": "Acme", "install_location": r"C:\Program Files\A", "main_exe": None}}
    after = dict(before)
    after["Good"] = {"name": "Good", "publisher": "BigCo", "install_location": r"C:\Program Files\Good", "main_exe": None}
    s._process_snapshot(before, after)
    assert fake_brain.threats == []


def test_uninstall_leftovers_emit(fake_brain, tmp_path):
    from Services.Sense.SentinelSense import SentinelSense
    s = SentinelSense(brain=fake_brain)
    leftover_dir = tmp_path / "GhostApp"; leftover_dir.mkdir()
    before = {"Ghost": {"name": "GhostApp", "publisher": "X", "install_location": str(leftover_dir), "main_exe": None}}
    after = {}   # uninstalled, but the dir still exists on disk
    s._process_snapshot(before, after)
    assert any("leftover" in (t.get("title","").lower()) for t in fake_brain.threats)
