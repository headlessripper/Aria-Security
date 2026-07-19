from Services.SentinelUSBGuard import StorageGuard


def test_lifecycle(fake_brain):
    g = StorageGuard(brain=fake_brain)
    g.start()
    assert g.is_running() is True
    g.stop()
    assert g.is_running() is False


def test_scan_emits_and_quarantines_on_malware(fake_brain, tmp_path, monkeypatch):
    g = StorageGuard(brain=fake_brain)
    bad = tmp_path / "evil.exe"; bad.write_bytes(b"MZ" + b"\x00" * 100)
    # fake VirusScanner: reports the file malicious
    class FakeVS:
        def scan_file(self, p): return {"verdict": "MALWARE", "reasons": ["test"], "details": {}}
    g._scanner = FakeVS()
    quarantined = []
    monkeypatch.setattr(g, "_quarantine", lambda p: quarantined.append(p))
    g._scan_files([str(bad)], "E:")
    assert any(t["category"] for t in fake_brain.threats)   # a threat was emitted
    assert quarantined == [str(bad)]


def test_scan_clean_no_emit(fake_brain, tmp_path):
    g = StorageGuard(brain=fake_brain)
    good = tmp_path / "ok.exe"; good.write_bytes(b"MZ" + b"\x00" * 100)
    class FakeVS:
        def scan_file(self, p): return {"verdict": "CLEAN", "reasons": [], "details": {}}
    g._scanner = FakeVS()
    g._scan_files([str(good)], "E:")
    assert fake_brain.threats == []


def test_allowlisted_drive_skipped(fake_brain):
    g = StorageGuard(brain=fake_brain, config={"allowlist": {"VOL-1"}})
    # a helper that decides whether to scan a newly-seen drive
    assert g._should_scan({"letter": "E:", "drive_type": 2, "bus_type": 7, "serial": "VOL-1"}) is False
    assert g._should_scan({"letter": "F:", "drive_type": 2, "bus_type": 7, "serial": "OTHER"}) is True
