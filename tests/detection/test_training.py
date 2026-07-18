import json
import numpy as np
import onnxruntime as ort
from Engine.Properties.make_smoke_model import build

def test_smoke_model_builds_and_loads(tmp_path):
    out = tmp_path / "pe_detector.onnx"
    feat = tmp_path / "features.json"
    model, X, y = build(n=2000, seed=7, out=out, feat=feat)
    assert out.exists() and feat.exists()
    meta = json.loads(feat.read_text())
    assert meta["feature_version"] == 2 and meta["dim"] == 2381
    sess = ort.InferenceSession(str(out), providers=["CPUExecutionProvider"])
    out_names = [o.name for o in sess.get_outputs()]
    assert "probabilities" in out_names
    res = sess.run(None, {"float_input": X[:8].astype(np.float32)})
    # probabilities output must have one entry per input row
    prob_idx = out_names.index("probabilities")
    assert len(res[prob_idx]) == 8
