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


def _capture_trips(rp, monkeypatch):
    """Replace _on_trip with a recorder and stub the slow pid lookup."""
    trips = []
    monkeypatch.setattr(rp, "_pid_for_path", lambda path: None)
    monkeypatch.setattr(rp, "_on_trip",
                        lambda reasons, path, pid: trips.append((set(reasons), path)))
    return trips


def test_canary_rename_trips_canary(fake_brain, monkeypatch):
    # Ransomware renaming a canary to encrypt it (canary -> canary.locked) must
    # be caught via the ORIGINAL (src) path, not just the destination.
    rp = RansomProtection(config={"watch_dirs": [], "action": "auto",
                                  "velocity_threshold": 10 ** 9}, brain=fake_brain)
    canary = os.path.join("C:\\watch", ".~sentinel_canary_0.tmp")
    rp._canaries = {canary}                      # seed deterministically (no Observer)
    trips = _capture_trips(rp, monkeypatch)

    rp._handle_fs_event("moved", canary, canary + ".locked")

    assert any("canary" in reasons for (reasons, path) in trips), \
        f"canary rename must produce a canary trip; got {trips}"


def test_canary_delete_trips_canary(fake_brain, monkeypatch):
    # A deleted canary (wiper / delete-to-encrypt behaviour) must trip canary.
    rp = RansomProtection(config={"watch_dirs": [], "action": "auto",
                                  "velocity_threshold": 10 ** 9}, brain=fake_brain)
    canary = os.path.join("C:\\watch", ".~sentinel_canary_1.tmp")
    rp._canaries = {canary}
    trips = _capture_trips(rp, monkeypatch)

    rp._handle_fs_event("deleted", canary)

    assert any("canary" in reasons for (reasons, path) in trips), \
        f"canary delete must produce a canary trip; got {trips}"


def test_per_file_correlation_not_global(fake_brain, tmp_path, monkeypatch):
    # Two SINGLE-detector trips on TWO DIFFERENT files within the window must
    # NOT combine into a >=2-detector high-confidence set.
    rp = RansomProtection(config={"watch_dirs": [], "action": "auto",
                                  "velocity_threshold": 10 ** 9}, brain=fake_brain)
    trips = _capture_trips(rp, monkeypatch)

    rp._handle_fs_event("created", "C:\\watch\\a.locked")   # extension only
    rp._handle_fs_event("created", "C:\\watch\\b.crypto")   # extension only

    assert len(trips) == 2
    for reasons, path in trips:
        assert reasons == {"extension"}, f"different files must stay single-reason; got {reasons}"
        assert rp._classify_and_respond(reasons, path, pid=None) == "alert"

    # But two detectors on the SAME file within the window DO combine (extension
    # on create, entropy on the follow-up modify) -> suspend-eligible set.
    victim = tmp_path / "victim.locked"
    victim.write_bytes(os.urandom(9000))        # naturally high entropy
    rp2 = RansomProtection(config={"watch_dirs": [], "action": "auto",
                                   "velocity_threshold": 10 ** 9}, brain=fake_brain)
    trips2 = _capture_trips(rp2, monkeypatch)

    rp2._handle_fs_event("created", str(victim))    # -> {extension}
    rp2._handle_fs_event("modified", str(victim))   # -> correlates {extension, entropy}

    combined = [reasons for (reasons, path) in trips2 if len(reasons) >= 2]
    assert combined, f"same-file detectors must combine; got {trips2}"
    assert {"extension", "entropy"} <= combined[-1]
    # and that combined set is suspend-eligible
    monkeypatch.setattr(rp2, "_suspend_pid", lambda pid: True)
    assert rp2._classify_and_respond(combined[-1], str(victim), pid=42) == "suspend"
