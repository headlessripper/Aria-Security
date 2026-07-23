"""Native file/folder picker dispatch + result handling.

The Tk dialog itself is never opened here — `_run_dialog` is monkeypatched, so
these tests cover the contract the Flask route depends on (path normalization,
cancel, failure, unknown mode) without needing a GUI.
"""
import os

from Services import native_dialogs as nd


def _fake_run(result):
    return lambda pick: result


def test_pick_file_returns_normalized_path(monkeypatch):
    monkeypatch.setattr(nd, "_run_dialog", _fake_run({"path": "C:/Users/x/thing.exe"}))
    out = nd.pick_file()
    assert out == {"path": os.path.normpath("C:/Users/x/thing.exe")}


def test_pick_folder_returns_normalized_path(monkeypatch):
    monkeypatch.setattr(nd, "_run_dialog", _fake_run({"path": "C:/Program Files/Acme"}))
    out = nd.pick_folder()
    assert out == {"path": os.path.normpath("C:/Program Files/Acme")}


def test_cancelled_dialog_returns_empty_path(monkeypatch):
    monkeypatch.setattr(nd, "_run_dialog", _fake_run({"path": ""}))
    assert nd.pick_file() == {"path": ""}


def test_dialog_failure_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr(nd, "_run_dialog", _fake_run({"error": "no display"}))
    out = nd.pick_file()
    assert out["path"] == "" and "no display" in out["error"]


def test_pick_dispatches_on_mode(monkeypatch):
    calls = []
    monkeypatch.setattr(nd, "pick_file", lambda t="", d="": calls.append(("file", t)) or {"path": "F"})
    monkeypatch.setattr(nd, "pick_folder", lambda t="", d="": calls.append(("folder", t)) or {"path": "D"})
    assert nd.pick("file")["path"] == "F"
    assert nd.pick("folder")["path"] == "D"
    assert [c[0] for c in calls] == ["file", "folder"]


def test_pick_unknown_mode_errors_without_raising():
    out = nd.pick("carrier-pigeon")
    assert out["path"] == "" and "unknown picker mode" in out["error"]


def test_initial_dir_only_used_when_it_exists(monkeypatch, tmp_path):
    seen = {}

    class _FD:
        @staticmethod
        def askopenfilename(**kw):
            seen.update(kw)
            return str(tmp_path / "f.txt")

    def fake_run(pick):
        return {"path": pick(_FD, object())}

    monkeypatch.setattr(nd, "_run_dialog", fake_run)

    nd.pick_file(initial_dir=str(tmp_path))          # exists -> passed through
    assert seen.get("initialdir") == str(tmp_path)

    seen.clear()
    nd.pick_file(initial_dir=r"C:\definitely\not\here")   # missing -> omitted
    assert "initialdir" not in seen
