from Services.Protection.Sentinelpsds import SynRateTracker, PSDS

def test_syn_rate_tracker_threshold():
    t = SynRateTracker(threshold=5, window=10)
    for i in range(4):
        t.record("1.2.3.4", i)
    assert t.exceeded("1.2.3.4", now=4) is False
    t.record("1.2.3.4", 5)
    assert t.exceeded("1.2.3.4", now=5) is True

def test_syn_rate_window_expiry():
    t = SynRateTracker(threshold=3, window=5)
    for i in range(3):
        t.record("1.2.3.4", i)          # ts 0,1,2
    assert t.exceeded("1.2.3.4", now=100) is False   # all outside a 5s window

def test_unknown_ip_not_exceeded():
    t = SynRateTracker(threshold=1, window=1)
    assert t.exceeded("9.9.9.9", now=0) is False

def test_psds_degrades_without_pydivert(fake_brain, monkeypatch):
    # simulate pydivert unavailable -> service must not raise, stays alive
    import Services.Protection.Sentinelpsds as psds_mod
    monkeypatch.setattr(psds_mod, "pydivert", None, raising=False)
    p = PSDS(brain=fake_brain)
    p.start()
    import time; time.sleep(0.1)
    assert p.is_running() is True          # inert but alive, not ERROR
    p.stop()
