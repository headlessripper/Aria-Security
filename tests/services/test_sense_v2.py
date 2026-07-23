"""Phase 6 — SentinelSense v2: footprint store, attribution, deletion rails."""
import os

from Services.Sense import attribution, residuals
from Services.Sense.sense_map import (
    SenseMap, STATUS_INSTALLED, STATUS_UNINSTALLED, STATUS_RESIDUAL_KEPT,
    STATUS_CLEANED,
)


# ── Sense_Map store ──────────────────────────────────────────────────────────

def test_sense_map_roundtrip_and_persistence(tmp_path):
    p = tmp_path / "Sense_Map.json"
    m = SenseMap(p)
    m.upsert_app("app1", {"name": "Acme Reader", "publisher": "Acme",
                          "install_location": r"C:\Program Files\Acme"})
    m.set_footprint("app1", files=[r"C:\Program Files\Acme\a.exe"],
                    dirs=[r"C:\Program Files\Acme"], registry=[r"HKLM\Software\Acme"])
    again = SenseMap(p)                      # reload from disk
    rec = again.get("app1")
    assert rec["name"] == "Acme Reader"
    assert rec["files"] == [r"C:\Program Files\Acme\a.exe"]
    assert rec["registry"] == [r"HKLM\Software\Acme"]
    assert rec["status"] == STATUS_INSTALLED


def test_sense_map_uninstall_then_keep_keeps_tracking(tmp_path):
    m = SenseMap(tmp_path / "m.json")
    m.upsert_app("k", {"name": "App"})
    m.mark_uninstalled("k")
    m.set_residuals("k", [r"C:\x\leftover.log"], 123)
    assert list(m.pending_residuals()) == ["k"]
    m.mark_kept("k")
    rec = m.get("k")
    # declined cleanup: still tracked, residuals still recorded, nothing deleted
    assert rec["status"] == STATUS_RESIDUAL_KEPT
    assert rec["residuals"] == [r"C:\x\leftover.log"]
    assert m.pending_residuals() == {}


def test_sense_map_cleaned_clears_residuals(tmp_path):
    m = SenseMap(tmp_path / "m.json")
    m.upsert_app("k", {"name": "App"})
    m.mark_uninstalled("k")
    m.set_residuals("k", [r"C:\x\a"], 10)
    m.mark_cleaned("k", freed_bytes=10)
    rec = m.get("k")
    assert rec["status"] == STATUS_CLEANED and rec["residuals"] == [] and rec["freed_bytes"] == 10


# ── attribution ──────────────────────────────────────────────────────────────

def test_attribute_matches_install_location_within_window():
    info = {"name": "Acme Reader", "publisher": "Acme",
            "install_location": r"C:\Program Files\Acme"}
    journal = [
        (r"C:\Program Files\Acme\bin\app.exe", 1000.0, False),
        (r"C:\Program Files\Acme\bin", 1000.0, True),
        (r"C:\Program Files\Other\z.dll", 1000.0, False),   # unrelated
    ]
    files, dirs = attribution.attribute(journal, info, installed_at=1000.0)
    assert files == [r"C:\Program Files\Acme\bin\app.exe"]
    assert dirs == [r"C:\Program Files\Acme\bin"]


def test_attribute_matches_name_token_outside_install_dir():
    info = {"name": "Acme Reader", "publisher": "Acme", "install_location": ""}
    journal = [(r"C:\Users\x\AppData\Roaming\AcmeReader\cfg.ini", 500.0, False)]
    files, _ = attribution.attribute(journal, info, installed_at=500.0)
    assert files == [r"C:\Users\x\AppData\Roaming\AcmeReader\cfg.ini"]


def test_attribute_excludes_entries_outside_time_window():
    info = {"name": "Acme", "publisher": "", "install_location": r"C:\PF\Acme"}
    journal = [(r"C:\PF\Acme\old.dat", 0.0, False)]      # long before install
    files, dirs = attribution.attribute(journal, info, installed_at=100000.0)
    assert files == [] and dirs == []


def test_name_tokens_drops_generic_words():
    toks = attribution.name_tokens("Acme Software Inc", "Microsoft Corporation")
    assert "acme" in toks
    for generic in ("software", "inc", "microsoft", "corporation"):
        assert generic not in toks


# ── deletion rails (safety-critical) ─────────────────────────────────────────

def _under_temp(*parts):
    return os.path.join(os.environ["TEMP"], *parts)


def test_safe_to_delete_accepts_recorded_path_under_tracked_root():
    target = _under_temp("AriaSenseTest", "leftover.log")
    assert residuals.is_safe_to_delete(target, [target]) is True


def test_refuses_path_not_in_footprint():
    target = _under_temp("AriaSenseTest", "leftover.log")
    other = _under_temp("AriaSenseTest", "other.log")
    assert residuals.is_safe_to_delete(target, [other]) is False


def test_refuses_tracked_root_itself():
    root = os.environ["TEMP"]
    assert residuals.is_safe_to_delete(root, [root]) is False


def test_refuses_drive_root():
    assert residuals.is_safe_to_delete("C:\\", ["C:\\"]) is False


def test_refuses_windows_and_system32():
    win = os.environ.get("SystemRoot", r"C:\Windows")
    sys32 = os.path.join(win, "System32")
    assert residuals.is_safe_to_delete(win, [win]) is False
    assert residuals.is_safe_to_delete(sys32, [sys32]) is False


def test_refuses_path_outside_tracked_roots():
    p = r"C:\SomeRandomDir\file.txt"
    assert residuals.is_safe_to_delete(p, [p]) is False


def test_refuses_parent_traversal():
    p = _under_temp("AriaSenseTest", "..", "escape.txt")
    assert residuals.is_safe_to_delete(p, [p]) is False


# ── residual discovery + guarded deletion (real files under TEMP) ────────────

def test_find_residuals_reports_existing_only(tmp_path):
    real = tmp_path / "kept.log"
    real.write_text("hello", encoding="utf-8")
    missing = tmp_path / "gone.log"
    found, total = residuals.find_residuals([str(real), str(missing)])
    assert found == [str(real)] and total == 5


def test_delete_residuals_removes_only_guarded_paths():
    base = _under_temp("AriaSenseDelTest")
    nested = os.path.join(base, "sub")
    os.makedirs(nested, exist_ok=True)
    f = os.path.join(nested, "a.txt")
    with open(f, "w", encoding="utf-8") as fh:
        fh.write("xyz")
    # An EXISTING but unsafe path: the TEMP root itself. Even though it is listed
    # in the footprint, the rails must refuse it (deleting it would be catastrophic).
    temp_root = os.environ["TEMP"]

    footprint = [f, nested, base, temp_root]
    deleted, failed, freed = residuals.delete_residuals(footprint)

    assert f in deleted and base in deleted      # real footprint removed
    assert not os.path.exists(base)
    assert temp_root in failed                   # refused by the rails
    assert os.path.isdir(temp_root)              # ...and still very much there
    assert freed >= 3


def test_delete_residuals_skips_missing_paths_without_failing():
    missing = _under_temp("AriaSenseMissing", "gone.txt")
    deleted, failed, freed = residuals.delete_residuals([missing])
    assert deleted == [] and failed == [] and freed == 0
