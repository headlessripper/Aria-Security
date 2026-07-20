import json
from pathlib import Path
from Services.monitors import geo_blocks


def test_load_missing_returns_empty(tmp_path):
    assert geo_blocks.load(tmp_path / "nope.json") == {}


def test_save_then_load_roundtrip(tmp_path):
    p = tmp_path / "sub" / "geo.json"  # parent does not exist yet
    data = {"RU": True, "CN": False}
    geo_blocks.save(p, data)
    assert geo_blocks.load(p) == data


def test_save_is_atomic_no_tmp_left(tmp_path):
    p = tmp_path / "geo.json"
    geo_blocks.save(p, {"US": True})
    leftovers = [f.name for f in tmp_path.iterdir() if f.name != "geo.json"]
    assert leftovers == []


def test_load_corrupt_returns_empty(tmp_path):
    p = tmp_path / "geo.json"
    p.write_text("{ not json", encoding="utf-8")
    assert geo_blocks.load(p) == {}
