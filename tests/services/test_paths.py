"""Data-directory resolution.

Matters because the backend is becoming a Windows service: as LocalSystem,
Path.home() is C:\\Windows\\System32\\config\\systemprofile, so anything that
hardcoded ~/.AriaSecurity would write where the user can't see it.
"""
import importlib
import os
from pathlib import Path

from Config import paths as P


def _reload(monkeypatch, **env):
    for k in ("ARIA_DATA_DIR", "ARIA_RUN_AS_SERVICE"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return importlib.reload(P)


def test_explicit_override_wins(monkeypatch, tmp_path):
    m = _reload(monkeypatch, ARIA_DATA_DIR=str(tmp_path / "explicit"))
    assert m.data_dir() == tmp_path / "explicit"


def test_service_context_uses_program_data(monkeypatch):
    m = _reload(monkeypatch, ARIA_RUN_AS_SERVICE="1")
    d = str(m.data_dir()).lower()
    assert "programdata" in d and "ariasecurity" in d
    assert "systemprofile" not in d, "service data must not land in the SYSTEM profile"


def test_desktop_context_uses_home(monkeypatch):
    m = _reload(monkeypatch)
    assert m.data_dir() == Path.home() / ".AriaSecurity"


def test_sub_joins_under_data_dir(monkeypatch, tmp_path):
    m = _reload(monkeypatch, ARIA_DATA_DIR=str(tmp_path))
    assert m.sub("SecureVault") == tmp_path / "SecureVault"
    assert m.sub("a", "b.json") == tmp_path / "a" / "b.json"


def test_data_dir_is_created(monkeypatch, tmp_path):
    target = tmp_path / "made" / "here"
    m = _reload(monkeypatch, ARIA_DATA_DIR=str(target))
    assert m.data_dir().exists()


def test_migration_copies_without_clobbering(monkeypatch, tmp_path):
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / "keep.json").write_text("from-legacy", encoding="utf-8")
    (legacy / "existing.json").write_text("from-legacy", encoding="utf-8")

    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "existing.json").write_text("newer-service-side", encoding="utf-8")

    m = _reload(monkeypatch, ARIA_DATA_DIR=str(dest))
    monkeypatch.setattr(m, "_LEGACY_DIR", legacy)

    moved = m.migrate_legacy_data(dest)
    assert "keep.json" in moved
    assert (dest / "keep.json").read_text(encoding="utf-8") == "from-legacy"
    # must not overwrite state the service already wrote
    assert (dest / "existing.json").read_text(encoding="utf-8") == "newer-service-side"
    assert "existing.json" not in moved


def test_migration_is_noop_when_source_is_destination(monkeypatch, tmp_path):
    m = _reload(monkeypatch, ARIA_DATA_DIR=str(tmp_path))
    monkeypatch.setattr(m, "_LEGACY_DIR", tmp_path)
    assert m.migrate_legacy_data(tmp_path) == []
