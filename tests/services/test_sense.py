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
