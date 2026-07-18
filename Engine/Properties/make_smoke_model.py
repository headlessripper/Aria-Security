"""Generate a throwaway LightGBM model on synthetic data and export ONNX.
NON-PRODUCTION: exists only to validate the extract->ONNX->verdict path until
the real model is trained on a PE dataset. Malicious iff sum(first 10 feats)>0."""
import json
from pathlib import Path
import numpy as np
import lightgbm as lgb
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

DIM = 2381
OUT = Path("Engine/Model/pe_detector.onnx")
FEAT = Path("Engine/Model/features.json")

def build(n=4000, seed=42):
    rng = np.random.default_rng(seed)
    X = rng.standard_normal((n, DIM)).astype(np.float32)
    y = (X[:, :10].sum(axis=1) > 0).astype(np.int8)
    model = lgb.train(
        {"objective": "binary", "metric": "binary_logloss",
         "num_leaves": 31, "verbose": -1, "seed": seed},
        lgb.Dataset(X, label=y), num_boost_round=60,
    )
    onnx = onnxmltools.convert_lightgbm(
        model, initial_types=[("float_input", FloatTensorType([None, DIM]))])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    onnxmltools.utils.save_model(onnx, str(OUT))
    FEAT.write_text(json.dumps(
        {"feature_version": 2, "dim": DIM, "synthetic": True,
         "note": "smoke model — replace via Engine/Properties/train.py"}, indent=2))
    print(f"[smoke] wrote {OUT} and {FEAT}")
    return model, X, y

if __name__ == "__main__":
    build()
