# tests/services/test_monitors_console.py
from Services.monitors import console_logs


def _make_logs(tmp_path):
    (tmp_path / "network.log").write_text("net line 1\nnet line 2\n", encoding="utf-8")
    (tmp_path / "ransom.log").write_text("ransom line 1\n", encoding="utf-8")
    return ["network.log", "ransom.log"]


def test_tail_prefixes_stem_and_aggregates(tmp_path):
    files = _make_logs(tmp_path)
    out = console_logs.tail(tmp_path, files, lines=100)
    assert "[network] net line 1" in out
    assert "[ransom] ransom line 1" in out


def test_tail_module_filter(tmp_path):
    files = _make_logs(tmp_path)
    out = console_logs.tail(tmp_path, files, lines=100, module="ransom")
    assert all("net line" not in l for l in out)
    assert any("ransom line 1" in l for l in out)


def test_tail_line_limit(tmp_path):
    files = _make_logs(tmp_path)
    out = console_logs.tail(tmp_path, files, lines=1)
    assert len(out) == 1


def test_tail_skips_missing_files(tmp_path):
    out = console_logs.tail(tmp_path, ["ghost.log"], lines=100)
    assert out == []


def test_clear_truncates_and_counts(tmp_path):
    files = _make_logs(tmp_path)
    n = console_logs.clear(tmp_path, files)
    assert n == 2
    assert (tmp_path / "network.log").read_text(encoding="utf-8") == ""


def test_clear_module_filter(tmp_path):
    files = _make_logs(tmp_path)
    n = console_logs.clear(tmp_path, files, module="network")
    assert n == 1
    assert (tmp_path / "ransom.log").read_text(encoding="utf-8") == "ransom line 1\n"
