import json
from pathlib import Path
import numpy as np
import onnxruntime as ort
from Engine.Properties.make_smoke_model import build, OUT, FEAT

def test_smoke_model_builds_and_loads():
    model, X, y = build(n=2000, seed=7)
    assert OUT.exists() and FEAT.exists()
    meta = json.loads(FEAT.read_text())
    assert meta["feature_version"] == 2 and meta["dim"] == 2381
    sess = ort.InferenceSession(str(OUT), providers=["CPUExecutionProvider"])
    out = sess.run(None, {"float_input": X[:8].astype(np.float32)})
    assert out is not None and len(out) >= 1
