import os
from Services.Protection.SentinelRansomProtection import (
    RansomProtection, shannon_entropy, _Window,
)
from Services.SentinelBrain import ThreatCategory, ThreatSeverity

def test_shannon_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1000) < 0.1          # all-same → ~0
    assert shannon_entropy(bytes(range(256)) * 4) > 7.9   # uniform → ~8

def test_window_counts_within_horizon():
    w = _Window()
    for t in range(10):        # timestamps 0..9
        w.add(t)
    # count() is pure (no mutation); horizon is half-open (now-seconds, now]
    assert w.count(now=10, seconds=5) == 4    # {6,7,8,9}
    assert w.count(now=10, seconds=100) == 10 # all (pure count, unaffected by the prior call)

def test_canary_trip_is_high_confidence_suspend(fake_brain, tmp_path, monkeypatch):
    rp = RansomProtection(config={"watch_dirs": [str(tmp_path)], "action": "auto"}, brain=fake_brain)
    suspended = {}
    monkeypatch.setattr(rp, "_suspend_pid", lambda pid: suspended.setdefault("pid", pid) or True)
    # canary trips are highest confidence -> suspend chosen
    action = rp._classify_and_respond({"canary"}, str(tmp_path / "canary.dat"), pid=1234)
    assert action == "suspend"

def test_single_heuristic_is_alert_only(fake_brain, tmp_path):
    rp = RansomProtection(config={"watch_dirs": [str(tmp_path)], "action": "auto"}, brain=fake_brain)
    action = rp._classify_and_respond({"velocity"}, str(tmp_path / "f"), pid=None)
    assert action == "alert"

def test_two_detectors_together_suspend(fake_brain, tmp_path, monkeypatch):
    rp = RansomProtection(config={"watch_dirs": [str(tmp_path)], "action": "auto"}, brain=fake_brain)
    monkeypatch.setattr(rp, "_suspend_pid", lambda pid: True)
    action = rp._classify_and_respond({"velocity", "entropy"}, str(tmp_path / "f"), pid=99)
    assert action == "suspend"

def test_safety_guard_never_suspends_trusted(fake_brain, tmp_path, monkeypatch):
    rp = RansomProtection(config={"watch_dirs": [str(tmp_path)], "action": "auto"}, brain=fake_brain)
    monkeypatch.setattr(rp, "_pid_is_protected", lambda pid: True)  # trusted/critical
    called = {"n": 0}
    monkeypatch.setattr(rp, "_suspend_pid", lambda pid: called.__setitem__("n", called["n"] + 1))
    action = rp._classify_and_respond({"canary"}, str(tmp_path / "c"), pid=4)
    assert action == "alert_safeguarded" and called["n"] == 0

def test_trip_emits_critical_ransomware(fake_brain, tmp_path, monkeypatch):
    rp = RansomProtection(config={"watch_dirs": [str(tmp_path)], "action": "alert_only"}, brain=fake_brain)
    rp._on_trip({"canary"}, str(tmp_path / "c"), pid=None)
    assert any(e.category == ThreatCategory.RANSOMWARE and e.severity == ThreatSeverity.CRITICAL
               for e in fake_brain.events)
