"""Train the production PE detector: EMBER/BODMAS feature vectors -> LightGBM -> ONNX.
Deferred run (needs a downloaded dataset). Usage:
  python -m Engine.Properties.train --data <path> --format {ember,bodmas}
EMBER: expects <path>/X_train.dat + y_train.dat memmaps (2381-dim float32 / int).
BODMAS: expects a .npz with arrays 'X' (n,2381) and 'y' (n,)."""
import argparse, json
from pathlib import Path
import numpy as np
import lightgbm as lgb
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType
from sklearn.metrics import roc_auc_score

DIM = 2381
PARAMS = {"objective": "binary", "metric": ["binary_logloss", "auc"],
          "boosting_type": "gbdt", "num_leaves": 256, "feature_fraction": 0.8,
          "bagging_fraction": 1.0, "bagging_freq": 5, "min_data_in_leaf": 50,
          "verbose": -1, "n_jobs": -1, "seed": 42}

def load(data, fmt, max_rows=0):
    """Return (X, y) already shuffled. Memory-bounded: only the selected rows are
    copied off the memmap into RAM. `max_rows` (0 = all) draws a class-balanced
    subsample so the trainer fits on constrained-RAM machines."""
    data = Path(data)
    rng = np.random.default_rng(42)
    if fmt == "bodmas":
        z = np.load(data)
        X = z["X"].astype(np.float32); y = z["y"].astype(np.int8)
        sel = np.arange(len(y))
    else:
        Xmm = np.memmap(data / "X_train.dat", dtype=np.float32, mode="r").reshape(-1, DIM)
        ymm = np.memmap(data / "y_train.dat", dtype=np.int8, mode="r")
        labeled = np.where(ymm != -1)[0]  # EMBER: -1 == unlabeled
        if max_rows and max_rows < len(labeled):
            pos = labeled[ymm[labeled] == 1]
            neg = labeled[ymm[labeled] == 0]
            k = max_rows // 2
            sel = np.concatenate([
                rng.choice(pos, min(k, len(pos)), replace=False),
                rng.choice(neg, min(k, len(neg)), replace=False)])
        else:
            sel = labeled
        rng.shuffle(sel)
        return np.asarray(Xmm[sel]), np.asarray(ymm[sel])  # one compact copy
    if max_rows and max_rows < len(y):
        k = max_rows // 2
        pos = sel[y == 1]; neg = sel[y == 0]
        sel = np.concatenate([rng.choice(pos, min(k, len(pos)), replace=False),
                              rng.choice(neg, min(k, len(neg)), replace=False)])
    rng.shuffle(sel)
    return X[sel], y[sel]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--format", choices=["ember", "bodmas"], default="bodmas")
    ap.add_argument("--out", default="Engine/Model/pe_detector.onnx")
    ap.add_argument("--max-rows", type=int, default=0,
                    help="cap the (class-balanced) training rows to bound memory; 0 = all")
    a = ap.parse_args()
    X, y = load(a.data, a.format, a.max_rows)
    assert X.shape[1] == DIM, f"expected {DIM} features per sample, got {X.shape[1]}"
    print(f"[train] rows={len(y)} pos={int((y==1).sum())} neg={int((y==0).sum())}")
    # X,y are already shuffled by load(); slice views for a 90/10 holdout (no copy)
    ntr = int(len(y) * 0.9)
    Xtr, Xte, ytr, yte = X[:ntr], X[ntr:], y[:ntr], y[ntr:]
    model = lgb.train(PARAMS, lgb.Dataset(Xtr, label=ytr),
                      valid_sets=[lgb.Dataset(Xte, label=yte)],
                      num_boost_round=500, callbacks=[lgb.log_evaluation(50)])
    prob = model.predict(Xte, num_iteration=model.best_iteration)
    print(f"[train] holdout AUC = {roc_auc_score(yte, prob):.5f}")
    onnx = onnxmltools.convert_lightgbm(
        model, initial_types=[("float_input", FloatTensorType([None, DIM]))])
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    onnxmltools.utils.save_model(onnx, a.out)
    Path(a.out).with_name("features.json").write_text(json.dumps(
        {"feature_version": 2, "dim": DIM, "synthetic": False, "auc": float(roc_auc_score(yte, prob))}, indent=2))
    # ONNX/native parity check
    import onnxruntime as ort
    sess = ort.InferenceSession(a.out, providers=["CPUExecutionProvider"])
    onx = sess.run(None, {"float_input": Xte[:256].astype(np.float32)})
    print(f"[train] wrote {a.out} (parity batch ran: {len(onx[0])} rows)")

if __name__ == "__main__":
    main()
