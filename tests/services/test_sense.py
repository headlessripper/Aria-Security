import pytest

from Services.Sense.SentinelSense import SentinelSense
from Services.Sense.sense_map import SenseMap
from Services.Sense.fs_journal import FsJournal


@pytest.fixture
def sense(fake_brain, tmp_path):
    """SentinelSense with an isolated Sense_Map + journal.

    The map/journal MUST be injected: the service records footprints on every
    processed snapshot, and the default singletons write to the user's real
    ~/.AriaSecurity/Sense_Map.json.
    """
    def _make():
        return SentinelSense(
            brain=fake_brain,
            sense_map=SenseMap(tmp_path / "Sense_Map.json"),
            journal=FsJournal(),
        )
    return _make


def test_lifecycle(sense):
    s = sense()
    s.start()
    assert s.is_running() is True
    s.stop()
    assert s.is_running() is False


def test_new_suspicious_install_emits(fake_brain, sense):
    s = sense()
    before = {"AppA": {"name": "AppA", "publisher": "Acme", "install_location": r"C:\Program Files\A", "main_exe": None}}
    after = dict(before)
    after["Evil"] = {"name": "Evil", "publisher": "", "install_location": r"C:\Users\u\AppData\Local\Temp\evil", "main_exe": None}
    s._process_snapshot(before, after)   # helper: diffs + classifies + emits
    assert any("Suspicious" in (t.get("title", "")) or t.get("category") for t in fake_brain.threats)


def test_benign_install_no_emit(fake_brain, sense):
    s = sense()
    before = {"AppA": {"name": "AppA", "publisher": "Acme", "install_location": r"C:\Program Files\A", "main_exe": None}}
    after = dict(before)
    after["Good"] = {"name": "Good", "publisher": "BigCo", "install_location": r"C:\Program Files\Good", "main_exe": None}
    s._process_snapshot(before, after)
    assert fake_brain.threats == []


def test_uninstall_leftovers_emit(fake_brain, sense, tmp_path):
    s = sense()
    leftover_dir = tmp_path / "GhostApp"; leftover_dir.mkdir()
    before = {"Ghost": {"name": "GhostApp", "publisher": "X", "install_location": str(leftover_dir), "main_exe": None}}
    after = {}   # uninstalled, but the dir still exists on disk
    s._process_snapshot(before, after)
    assert any("leftover" in (t.get("title", "").lower()) for t in fake_brain.threats)


def test_uninstall_records_residuals_in_sense_map(fake_brain, sense, tmp_path):
    """The surviving install dir is recorded as a residual awaiting a decision."""
    s = sense()
    leftover = tmp_path / "GhostApp"; leftover.mkdir()
    (leftover / "cfg.ini").write_text("x", encoding="utf-8")
    before = {"Ghost": {"name": "GhostApp", "publisher": "X",
                        "install_location": str(leftover), "main_exe": None}}
    s._process_snapshot(before, {})
    rec = s.sense_map.get("Ghost")
    assert rec is not None
    assert rec["status"] == "uninstalled"
    assert str(leftover) in rec["residuals"]
    assert "Ghost" in s.sense_map.pending_residuals()


def test_service_does_not_touch_the_real_sense_map(sense, tmp_path):
    """Guard against the injected map being bypassed (would write user data)."""
    s = sense()
    assert s.sense_map._path == tmp_path / "Sense_Map.json"
