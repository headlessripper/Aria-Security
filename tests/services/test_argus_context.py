import types
from Argus import context


def _wire(monkeypatch, level=90, threats=None, modules=None):
    threats = threats or []
    modules = modules or []
    monkeypatch.setattr(context, "_avbrain", lambda: types.SimpleNamespace(
        get_protection_level=lambda: level,
        get_active_threats=lambda: threats,
    ))
    monkeypatch.setattr(context, "_brain", lambda: types.SimpleNamespace(
        get_module_statuses=lambda: modules,
    ))


def test_context_reports_level_and_counts(monkeypatch):
    mods = [types.SimpleNamespace(name="A", running=True),
            types.SimpleNamespace(name="B", running=False)]
    _wire(monkeypatch, level=72, threats=[], modules=mods)
    out = context.build_context()
    assert "72" in out
    assert "1/2" in out or "1 of 2" in out  # modules up


def test_context_never_mentions_isolationforest(monkeypatch):
    _wire(monkeypatch)
    out = context.build_context().lower()
    assert "isolationforest" not in out and "isolation forest" not in out and "anomaly" not in out
