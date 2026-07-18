import json

from Engine.Properties.make_smoke_model import build
from Engine.Detection.ml_scanner import MLScanner

def _tmp_model(tmp_path, seed=3):
    out = tmp_path / "m.onnx"; feat = tmp_path / "f.json"
    build(n=1500, seed=seed, out=out, feat=feat)
    return str(out), str(feat)

def test_load_and_score(benign_pe, tmp_path):
    onnx, feat = _tmp_model(tmp_path)
    s = MLScanner(threshold=0.5)
    assert s.load_file(onnx, feat) is True
    p = s.score(benign_pe)
    assert p is not None and 0.0 <= p <= 1.0

def test_model_scan_contract(benign_pe, tmp_path):
    onnx, feat = _tmp_model(tmp_path)
    s = MLScanner(threshold=0.5)
    assert s.load_file(onnx, feat) is True
    r = s.model_scan(benign_pe)
    assert (r == (False, False)) or (isinstance(r, tuple) and r[0] == "Malware" and isinstance(r[1], int))

def test_missing_model():
    s = MLScanner()
    assert s.load_file("does/not/exist.onnx") is False
    assert s.score("whatever") is None

def test_feature_version_mismatch_refused(tmp_path):
    onnx, feat = _tmp_model(tmp_path)
    # tamper the metadata to an incompatible feature version
    meta = json.loads(open(feat).read()); meta["feature_version"] = 999
    open(feat, "w").write(json.dumps(meta))
    s = MLScanner()
    assert s.load_file(onnx, feat) is False        # refused
    assert s.score("whatever") is None             # scoring disabled
