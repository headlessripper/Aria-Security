# Phase 2 — Advanced Detection Engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the malware-as-image CNN with an advanced 4-layer PE detection engine — EMBER-LightGBM ML + fuzzy hashing (imphash/TLSH) + curated YARA + cert reputation — combined by an explicit fusion policy, with the ML pipeline built now and trained later.

**Architecture:** Each detection layer is a focused unit in `Engine/Detection/`. `VirusScanner` (`Engine/Compiler/SentinelCompiler_v5.py`) stays the orchestrator: it runs the layers on a confirmed PE, collects per-layer results, and delegates the verdict to `Engine/Detection/fusion.py`. The ML layer uses a vendored EMBER v2 feature extractor (train/inference parity) → LightGBM → ONNX. A synthetic smoke model keeps the whole path verifiable before real training.

**Tech Stack:** Python 3.10+, LightGBM, LIEF (EMBER features), onnxmltools/onnxruntime, python-tlsh, pefile, yara-python, pytest.

## Global Constraints

- Feature vector is **exactly 2381 float32** dims; feature schema is EMBER **feature_version = 2**.
- `Engine/Model/features.json` `feature_version` must equal `PEFeatureExtractor.version`; on mismatch the scanner logs and refuses to trust the model.
- Fusion precedence (spec §4), thresholds as named constants: `ML_HIGH=0.90`, `ML_MED=0.50`, `TLSH_NEAR=40`.
- New deps into `.venv` + `requirements.txt`: `lightgbm`, `lief`, `onnxmltools`, `python-tlsh`.
- Trained weights are **deferred**: ship the synthetic smoke ONNX; real model comes in the post-dataset phase. This is expected, not a defect.
- App must stay runnable (`SENTINEL_NO_ELEVATE=1` boot → HTTP 200 on 127.0.0.1:8765) and `python scripts/verify_reachability.py` must stay `LIVE=28`/`PASS` (the live count changes only by the net of Task 9's add/retire — update `EXPECTED_LIVE` there, see Task 9).
- **Never `git add` any `.exe`/`.ips`/PE binary** — the live AV scanner quarantines PE bytes inside `.git`. The `pe_detector.onnx` (ML model) IS allowed (it is an ONNX graph, not a PE). Test PE files used by tests must NOT be committed.
- Commit after every task. Never use `--no-verify`.

---

## File Structure

- `Engine/Detection/pe_features.py` — **new.** Vendored EMBER v2 extractor. `bytez → float32[2381]`.
- `Engine/Detection/ml_scanner.py` — **new.** ONNX inference; drop-in for old `model_scanner`.
- `Engine/Detection/fuzzy_hash.py` — **new.** imphash + TLSH + known-bad DB matching.
- `Engine/Detection/cert_reputation.py` — **new.** WinVerifyTrust (reuses `Engine_Unit_SG`) + signer/abused checks.
- `Engine/Detection/fusion.py` — **new.** Pure verdict policy.
- `Engine/Properties/train.py` — **new.** LightGBM trainer → ONNX + features.json (deferred run).
- `Engine/Properties/make_smoke_model.py` — **new.** Synthetic → ONNX for validation.
- `Engine/Heuristic/` — **new content.** Curated YARA rulesets.
- `Engine/Compiler/SentinelCompiler_v5.py` — **modified.** Wire new layers + fusion.
- `Config/Sys_Config.py` — **modified.** Model/DB/features paths.
- `requirements.txt` — **new.**
- `tests/detection/…` — **new.** pytest suite.
- `cleanup/phase2-old-engine/` — **new.** Retired image-CNN + old ONNX.

---

### Task 1: Dependencies + test scaffolding

**Files:**
- Create: `requirements.txt`, `tests/__init__.py`, `tests/detection/__init__.py`, `tests/conftest.py`, `pytest.ini`

**Interfaces:**
- Produces: a working `pytest` run; `tests/conftest.py::benign_pe` fixture returning a path to a real signed Windows PE for reuse by later tasks.

- [ ] **Step 1: Install dependencies**

Run:
```bash
cd "D:/ZashironSentinel"
.venv/Scripts/python.exe -m pip install lightgbm lief onnxmltools python-tlsh pytest 2>&1 | tail -5
```
Expected: `Successfully installed ...` including lightgbm, lief, onnxmltools, python-tlsh, pytest. If `lief` fails to build, try `.venv/Scripts/python.exe -m pip install "lief>=0.14,<0.16"`; record the installed `lief` version — Task 2 depends on it.

- [ ] **Step 2: Write requirements.txt**

```
# Aria Security — Python dependencies
flask
flask-socketio
pywebview
pefile
yara-python
onnxruntime
numpy
scikit-learn
pandas
psutil
winotify
# Phase 2 detection engine
lightgbm
lief
onnxmltools
python-tlsh
# dev
pytest
```

- [ ] **Step 3: Create pytest config + conftest**

`pytest.ini`:
```ini
[pytest]
testpaths = tests
python_files = test_*.py
addopts = -q
```

`tests/__init__.py` and `tests/detection/__init__.py`: empty files.

`tests/conftest.py`:
```python
import os
import pytest

@pytest.fixture(scope="session")
def benign_pe():
    """A real, Microsoft-signed Windows PE for extractor/cert/fuzzy tests."""
    for cand in (r"C:\Windows\System32\notepad.exe",
                 r"C:\Windows\System32\calc.exe",
                 r"C:\Windows\System32\cmd.exe"):
        if os.path.exists(cand):
            return cand
    pytest.skip("no system PE available")

@pytest.fixture(scope="session")
def benign_pe_bytes(benign_pe):
    with open(benign_pe, "rb") as f:
        return f.read()
```

- [ ] **Step 4: Verify pytest runs and deps import**

Run:
```bash
.venv/Scripts/python.exe -m pytest -q 2>&1 | tail -3
.venv/Scripts/python.exe -c "import lightgbm, lief, onnxmltools, tlsh; print('deps OK', lief.__version__)"
```
Expected: pytest collects 0 tests (no error); `deps OK <lief version>`.

- [ ] **Step 5: Commit**

```bash
git add requirements.txt pytest.ini tests/
git commit -m "Phase 2 Task 1: deps (lightgbm/lief/onnxmltools/python-tlsh) + pytest scaffold"
```

---

### Task 2: EMBER v2 feature extractor (`pe_features.py`)

**Highest-risk task (LIEF API drift). Verify it runs on a real PE before anything depends on it.**

**Files:**
- Create: `Engine/Detection/pe_features.py`
- Test: `tests/detection/test_pe_features.py`

**Interfaces:**
- Produces: `class PEFeatureExtractor` with attribute `version: int = 2`, `dim: int = 2381`, and method `feature_vector(bytez: bytes) -> numpy.ndarray` (dtype float32, shape (2381,)). Never raises on malformed input — returns `numpy.zeros(2381, float32)` instead.

- [ ] **Step 1: Obtain EMBER's feature extractor**

EMBER's `features.py` (Apache-2.0) is the canonical 2381-dim v2 extractor. Fetch it:
```bash
cd "D:/ZashironSentinel"
curl -sL https://raw.githubusercontent.com/elastic/ember/master/ember/features.py -o Engine/Detection/pe_features.py
head -20 Engine/Detection/pe_features.py
```
Prepend a provenance header to the file (keep Apache-2.0 attribution):
```
# pe_features.py — EMBER v2 PE feature extractor.
# Vendored from elastic/ember (Apache-2.0). Adapted for the installed LIEF version.
# Produces a fixed 2381-dim float32 vector; feature_version = 2.
```

- [ ] **Step 2: Write the failing test**

`tests/detection/test_pe_features.py`:
```python
import numpy as np
from Engine.Detection.pe_features import PEFeatureExtractor

def test_dim_and_version():
    ext = PEFeatureExtractor()
    assert ext.version == 2
    assert ext.dim == 2381

def test_vector_shape_and_dtype(benign_pe_bytes):
    ext = PEFeatureExtractor()
    v = ext.feature_vector(benign_pe_bytes)
    assert isinstance(v, np.ndarray)
    assert v.shape == (2381,)
    assert v.dtype == np.float32
    assert np.isfinite(v).all()

def test_deterministic(benign_pe_bytes):
    ext = PEFeatureExtractor()
    a = ext.feature_vector(benign_pe_bytes)
    b = ext.feature_vector(benign_pe_bytes)
    assert np.array_equal(a, b)

def test_garbage_input_does_not_raise():
    ext = PEFeatureExtractor()
    v = ext.feature_vector(b"not a pe file")
    assert v.shape == (2381,)
```

- [ ] **Step 3: Run test to see it fail**

Run: `.venv/Scripts/python.exe -m pytest tests/detection/test_pe_features.py -q 2>&1 | tail -20`
Expected: failures — likely `AttributeError`/`TypeError` from LIEF API differences, or missing `version`/`dim` attributes.

- [ ] **Step 4: Adapt the extractor to the installed LIEF + add the contract**

Apply these concrete adaptations to `pe_features.py`:
1. Ensure `class PEFeatureExtractor` exposes `self.version = 2` and `self.dim = 2381` in `__init__` (EMBER sets `self.dim` already; add `self.version = 2`).
2. Wrap the LIEF parse so malformed input never raises. In `feature_vector`, EMBER does `lief.PE.parse(list(bytez))`. Modern LIEF returns `None` (not an exception) on failure and accepts `bytes`/`memoryview`. Change the parse to:
   ```python
   try:
       lief_binary = lief.PE.parse(bytez)  # bytes accepted in modern lief
   except Exception:
       lief_binary = None
   ```
   and make every sub-feature's `raw_features`/`process_raw_features` tolerate `lief_binary is None` (EMBER's code already special-cases None for most; verify each `*FeatureType.raw_features` handles None).
3. LIEF enum/attribute renames to fix as the test surfaces them (common ones): `lief.PE.HEADER_CHARACTERISTICS` → `lief.PE.Header.CHARACTERISTICS`; `dll_characteristics_lists` / `characteristics_lists` may be `.characteristics_list` (property) in newer LIEF; `entry.name` on imports/exports may need `.name` guarded for bytes vs str; `data_directories` iteration attribute names. Fix each at the exact line the traceback points to, keeping the produced value semantically identical (name string / size int / count).
4. Keep the FeatureHasher dims and ordering **unchanged** — those define the 2381 layout and must not drift.

Then wrap the public method so it always returns the right shape:
```python
# at end of feature_vector, EMBER already returns np.array(...). Ensure:
#   return vec.astype(np.float32)
# and guard the whole body:
def feature_vector(self, bytez):
    try:
        return self._feature_vector_impl(bytez).astype(np.float32)
    except Exception:
        import numpy as np
        return np.zeros(self.dim, dtype=np.float32)
```
(Rename EMBER's existing `feature_vector` body to `_feature_vector_impl`.)

- [ ] **Step 5: Run tests until green**

Run: `.venv/Scripts/python.exe -m pytest tests/detection/test_pe_features.py -q 2>&1 | tail -20`
Expected: 4 passed. Iterate Step 4 for each LIEF error until green. **Do not proceed past this task until all 4 pass** — everything downstream depends on a working extractor.

- [ ] **Step 6: Commit**

```bash
git add Engine/Detection/pe_features.py tests/detection/test_pe_features.py
git commit -m "Phase 2 Task 2: vendored EMBER v2 feature extractor (2381-dim), adapted to installed LIEF"
```

---

### Task 3: Training pipeline + synthetic smoke model

**Files:**
- Create: `Engine/Properties/make_smoke_model.py`, `Engine/Properties/train.py`
- Test: `tests/detection/test_training.py`

**Interfaces:**
- Produces: `Engine/Model/pe_detector.onnx` + `Engine/Model/features.json` (`{"feature_version":2,"dim":2381,...}`). The ONNX takes input `float_input` shape `[None, 2381]` and outputs a malware probability extractable by `MLScanner._extract_prob` (Task 4).

- [ ] **Step 1: Write `make_smoke_model.py`**

```python
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
```

- [ ] **Step 2: Write `train.py`**

```python
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
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score

DIM = 2381
PARAMS = {"objective": "binary", "metric": ["binary_logloss", "auc"],
          "boosting_type": "gbdt", "num_leaves": 256, "feature_fraction": 0.8,
          "bagging_fraction": 1.0, "bagging_freq": 5, "min_data_in_leaf": 50,
          "verbose": -1, "n_jobs": -1, "seed": 42}

def load(data, fmt):
    data = Path(data)
    if fmt == "bodmas":
        z = np.load(data)
        return z["X"].astype(np.float32), z["y"].astype(np.int8)
    X = np.memmap(data / "X_train.dat", dtype=np.float32, mode="r").reshape(-1, DIM)
    y = np.memmap(data / "y_train.dat", dtype=np.int8, mode="r")
    keep = y != -1  # EMBER: -1 == unlabeled
    return np.asarray(X[keep]), np.asarray(y[keep])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--format", choices=["ember", "bodmas"], default="bodmas")
    ap.add_argument("--out", default="Engine/Model/pe_detector.onnx")
    a = ap.parse_args()
    X, y = load(a.data, a.format)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.1, random_state=42, stratify=y)
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
```

- [ ] **Step 3: Write the test**

`tests/detection/test_training.py`:
```python
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
```

- [ ] **Step 4: Run test (build the smoke model)**

Run: `.venv/Scripts/python.exe -m pytest tests/detection/test_training.py -q 2>&1 | tail -10`
Expected: 1 passed; `Engine/Model/pe_detector.onnx` and `features.json` now exist.

- [ ] **Step 5: Commit** (the ONNX is a graph, not a PE — safe to commit)

```bash
git add Engine/Properties/make_smoke_model.py Engine/Properties/train.py tests/detection/test_training.py Engine/Model/pe_detector.onnx Engine/Model/features.json
git commit -m "Phase 2 Task 3: LightGBM trainer + synthetic smoke model -> pe_detector.onnx"
```

---

### Task 4: ML inference scanner (`ml_scanner.py`)

**Files:**
- Create: `Engine/Detection/ml_scanner.py`
- Test: `tests/detection/test_ml_scanner.py`

**Interfaces:**
- Consumes: `PEFeatureExtractor` (Task 2); `Engine/Model/pe_detector.onnx` (Task 3).
- Produces: `class MLScanner` with `load_file(onnx_path, features_json=None) -> bool`, `score(file_path) -> float | None`, `model_scan(file_path, full_output=False) -> tuple`. `model_scan` returns `("Malware", int_conf)` when `score >= threshold` else `(False, False)` — matching the old `model_scanner` contract that `VirusScanner` consumes.

- [ ] **Step 1: Write the implementation**

```python
import json, os
from pathlib import Path
import numpy as np
import onnxruntime as ort
from Engine.Detection.pe_features import PEFeatureExtractor

class MLScanner:
    def __init__(self, threshold: float = 0.5):
        self.session = None
        self.input_name = None
        self.threshold = threshold
        self.extractor = PEFeatureExtractor()
        self.feature_version = None

    def load_file(self, onnx_path, features_json=None):
        if not onnx_path or not os.path.exists(onnx_path):
            return False
        try:
            self.session = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
            self.input_name = self.session.get_inputs()[0].name
        except Exception as e:
            print(f"[MLScanner] load error: {e}")
            self.session = None
            return False
        meta_path = features_json or str(Path(onnx_path).with_name("features.json"))
        try:
            meta = json.loads(Path(meta_path).read_text())
            self.feature_version = meta.get("feature_version")
            if self.feature_version != self.extractor.version:
                print(f"[MLScanner] feature_version mismatch: model={self.feature_version} "
                      f"extractor={self.extractor.version}")
        except Exception:
            pass
        return True

    def score(self, file_path):
        if self.session is None:
            return None
        try:
            with open(file_path, "rb") as f:
                bytez = f.read()
            vec = self.extractor.feature_vector(bytez).reshape(1, -1).astype(np.float32)
            out = self.session.run(None, {self.input_name: vec})
            return float(self._extract_prob(out))
        except Exception as e:
            print(f"[MLScanner] score error: {e}")
            return None

    @staticmethod
    def _extract_prob(out):
        # onnxmltools LightGBM export: out[0]=label, out[1]=probabilities.
        # ZipMap on -> list[dict{0:p0,1:p1}]; off -> array [n,2].
        try:
            probs = out[1]
            row = probs[0]
            if isinstance(row, dict):
                return row.get(1, row.get(True, 0.0))
            return float(np.ravel(row)[-1])
        except Exception:
            return float(np.ravel(out[0])[0])

    def model_scan(self, file_path, full_output=False):
        p = self.score(file_path)
        if p is None:
            return (False, False)
        if p >= self.threshold:
            return ("Malware", int(round(p * 100)))
        return (False, False)
```

- [ ] **Step 2: Write the test**

`tests/detection/test_ml_scanner.py`:
```python
from Engine.Properties.make_smoke_model import build, OUT
from Engine.Detection.ml_scanner import MLScanner

def test_load_and_score(benign_pe):
    build(n=1500, seed=3)  # ensure a smoke ONNX exists
    s = MLScanner(threshold=0.5)
    assert s.load_file(str(OUT)) is True
    p = s.score(benign_pe)
    assert p is not None and 0.0 <= p <= 1.0

def test_model_scan_contract(benign_pe):
    s = MLScanner(threshold=0.5)
    assert s.load_file(str(OUT)) is True
    r = s.model_scan(benign_pe)
    assert (r == (False, False)) or (isinstance(r, tuple) and r[0] == "Malware" and isinstance(r[1], int))

def test_missing_model():
    s = MLScanner()
    assert s.load_file("does/not/exist.onnx") is False
    assert s.score("whatever") is None
```

- [ ] **Step 3: Run tests**

Run: `.venv/Scripts/python.exe -m pytest tests/detection/test_ml_scanner.py -q 2>&1 | tail -12`
Expected: 3 passed.

- [ ] **Step 4: Commit**

```bash
git add Engine/Detection/ml_scanner.py tests/detection/test_ml_scanner.py
git commit -m "Phase 2 Task 4: ONNX ML scanner (EMBER features -> pe_detector.onnx)"
```

---

### Task 5: Fuzzy hashing (`fuzzy_hash.py`)

**Files:**
- Create: `Engine/Detection/fuzzy_hash.py`, `Engine/Signatures/fuzzy_bad.txt` (empty seed DB with a header comment)
- Test: `tests/detection/test_fuzzy_hash.py`

**Interfaces:**
- Produces: `class FuzzyHasher(db_path=None, tlsh_near=40)` with `imphash(file_path) -> str|None`, `tlsh(bytez) -> str|None`, `match(file_path) -> dict{"matched":bool,"best_distance":int|None,"source":str|None}`. DB line format: `imphash:<hex>` or `tlsh:<hash>`.

- [ ] **Step 1: Write the implementation**

```python
import os
from pathlib import Path
try:
    import tlsh as _tlsh
    _HAS_TLSH = True
except Exception:
    _HAS_TLSH = False
import pefile

class FuzzyHasher:
    def __init__(self, db_path=None, tlsh_near: int = 40):
        self.tlsh_near = tlsh_near
        self.bad_imphashes = set()
        self.bad_tlsh = []
        if db_path and os.path.exists(db_path):
            self._load_db(db_path)

    def _load_db(self, db_path):
        for line in Path(db_path).read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("imphash:"):
                self.bad_imphashes.add(line[8:].lower())
            elif line.startswith("tlsh:"):
                self.bad_tlsh.append(line[5:])

    def imphash(self, file_path):
        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            h = pe.get_imphash()
            return h.lower() if h else None
        except Exception:
            return None

    def tlsh(self, bytez):
        if not _HAS_TLSH or not bytez or len(bytez) < 256:
            return None
        try:
            h = _tlsh.hash(bytez)
            return h if h and h != "TNULL" else None
        except Exception:
            return None

    def match(self, file_path):
        result = {"matched": False, "best_distance": None, "source": None}
        imp = self.imphash(file_path)
        if imp and imp in self.bad_imphashes:
            return {"matched": True, "best_distance": 0, "source": f"imphash:{imp}"}
        try:
            with open(file_path, "rb") as f:
                bytez = f.read()
        except Exception:
            return result
        th = self.tlsh(bytez)
        if th and self.bad_tlsh:
            dists = []
            for b in self.bad_tlsh:
                try:
                    dists.append(_tlsh.diff(th, b))
                except Exception:
                    pass
            if dists:
                best = min(dists)
                result["best_distance"] = best
                if best <= self.tlsh_near:
                    result.update(matched=True, source=f"tlsh:{best}")
        return result
```

`Engine/Signatures/fuzzy_bad.txt`:
```
# Known-bad fuzzy-hash reference DB. One entry per line:
#   imphash:<hex>   or   tlsh:<hash>
# Populated in the post-dataset phase from a malware corpus.
```

- [ ] **Step 2: Write the test**

`tests/detection/test_fuzzy_hash.py`:
```python
from Engine.Detection.fuzzy_hash import FuzzyHasher

def test_imphash_on_real_pe(benign_pe):
    fh = FuzzyHasher()
    h = fh.imphash(benign_pe)
    assert h is None or (isinstance(h, str) and len(h) == 32)

def test_tlsh_compute(benign_pe_bytes):
    fh = FuzzyHasher()
    t = fh.tlsh(benign_pe_bytes)
    assert t is None or isinstance(t, str)

def test_match_empty_db(benign_pe):
    fh = FuzzyHasher()  # empty DB
    r = fh.match(benign_pe)
    assert r["matched"] is False

def test_match_seeded_imphash(benign_pe, tmp_path):
    fh0 = FuzzyHasher()
    imp = fh0.imphash(benign_pe)
    if not imp:
        return  # PE has no imports; skip
    db = tmp_path / "bad.txt"
    db.write_text(f"imphash:{imp}\n")
    fh = FuzzyHasher(db_path=str(db))
    r = fh.match(benign_pe)
    assert r["matched"] is True and r["source"].startswith("imphash:")
```

- [ ] **Step 3: Run tests**

Run: `.venv/Scripts/python.exe -m pytest tests/detection/test_fuzzy_hash.py -q 2>&1 | tail -12`
Expected: 4 passed.

- [ ] **Step 4: Commit**

```bash
git add Engine/Detection/fuzzy_hash.py Engine/Signatures/fuzzy_bad.txt tests/detection/test_fuzzy_hash.py
git commit -m "Phase 2 Task 5: fuzzy hashing (imphash + TLSH) with known-bad DB matching"
```

---

### Task 6: Cert reputation (`cert_reputation.py`)

**Files:**
- Create: `Engine/Detection/cert_reputation.py`
- Test: `tests/detection/test_cert_reputation.py`

**Interfaces:**
- Consumes: `Engine/Detection/Engine_Unit_SG.sign_scanner` (existing WinVerifyTrust wrapper).
- Produces: `class CertReputation(abused_signers=None)` with `evaluate(file_path) -> dict{"signed":bool,"trusted":bool,"revoked":bool,"abused":bool,"signer":str|None}`.

- [ ] **Step 1: Write the implementation**

```python
from Engine.Detection.Engine_Unit_SG import sign_scanner

class CertReputation:
    """Signature trust via Windows WinVerifyTrust, plus an abused-signer list.
    Full Authenticode signer-name extraction (PKCS#7) is deferred; `signer` is
    best-effort None for now, so `abused` only fires when a signer is provided."""
    def __init__(self, abused_signers=None):
        self.sign = sign_scanner()
        try:
            self.sign.init_windll(["wintrust"])
        except Exception:
            pass
        self.abused = {s.lower() for s in (abused_signers or [])}

    def evaluate(self, file_path):
        try:
            trusted = bool(self.sign.sign_verify(file_path))
        except Exception:
            trusted = False
        signer = self._signer_name(file_path)
        return {
            "signed": trusted,          # WinVerifyTrust trusts only valid signatures
            "trusted": trusted,
            "revoked": False,           # best-effort; full revocation check deferred
            "abused": bool(signer and signer.lower() in self.abused),
            "signer": signer,
        }

    def _signer_name(self, file_path):
        # Best-effort placeholder: proper PKCS#7 subject extraction is deferred to
        # the post-dataset phase (needs signtool/cryptography parsing). Returns None.
        return None
```

- [ ] **Step 2: Write the test**

`tests/detection/test_cert_reputation.py`:
```python
from Engine.Detection.cert_reputation import CertReputation

def test_signed_windows_binary(benign_pe):
    cr = CertReputation()
    r = cr.evaluate(benign_pe)
    # System32 binaries are Microsoft-signed and trusted on a healthy Windows.
    assert r["trusted"] is True and r["signed"] is True
    assert r["abused"] is False

def test_unsigned_file(tmp_path):
    p = tmp_path / "unsigned.exe"
    p.write_bytes(b"MZ" + b"\x00" * 2048)
    cr = CertReputation()
    r = cr.evaluate(str(p))
    assert r["trusted"] is False and r["signed"] is False
```

- [ ] **Step 3: Run tests**

Run: `.venv/Scripts/python.exe -m pytest tests/detection/test_cert_reputation.py -q 2>&1 | tail -12`
Expected: 2 passed. (If `test_signed_windows_binary` fails because WinVerifyTrust returns non-zero for a system file, verify `Engine_Unit_SG.sign_scanner.sign_verify` returns `s == 0`; the fixture uses a real signed exe.)

- [ ] **Step 4: Commit**

```bash
git add Engine/Detection/cert_reputation.py tests/detection/test_cert_reputation.py
git commit -m "Phase 2 Task 6: cert reputation via WinVerifyTrust + abused-signer list"
```

---

### Task 7: Fusion policy (`fusion.py`)

**Files:**
- Create: `Engine/Detection/fusion.py`
- Test: `tests/detection/test_fusion.py`

**Interfaces:**
- Produces: `fuse(results: dict) -> dict{"verdict":str,"confidence":int,"reasons":list,"details":dict}`.
  Input keys (all optional): `whitelisted:bool`, `hash_exact:bool`, `fuzzy:dict` (from `FuzzyHasher.match`), `yara:list[str]`, `ml_prob:float|None`, `cert:dict` (from `CertReputation.evaluate`). `verdict ∈ {"CLEAN","SUSPICIOUS","MALWARE"}`.

- [ ] **Step 1: Write the implementation** (encodes spec §4 precedence)

```python
ML_HIGH = 0.90
ML_MED = 0.50
TLSH_NEAR = 40           # informational; FuzzyHasher already applies it
TRUST_CONF_RELIEF = 20   # confidence reduction when a valid trusted signature is present

def _verdict(v, conf, reasons, details):
    return {"verdict": v, "confidence": int(conf), "reasons": reasons, "details": details}

def fuse(results):
    details = dict(results)
    if results.get("whitelisted"):
        return _verdict("CLEAN", 100, ["Whitelisted"], details)
    if results.get("hash_exact"):
        return _verdict("MALWARE", 100, ["Known-bad hash"], details)
    fz = results.get("fuzzy") or {}
    if fz.get("matched"):
        return _verdict("MALWARE", 90, [f"Fuzzy match ({fz.get('source')})"], details)
    yara_hits = results.get("yara") or []
    if yara_hits:
        return _verdict("MALWARE", 90, ["YARA: " + ", ".join(yara_hits[:3])], details)
    cert = results.get("cert") or {}
    if cert.get("abused"):
        return _verdict("MALWARE", 95, ["Signed by known-abused certificate"], details)
    p = results.get("ml_prob")
    if p is not None:
        trusted = bool(cert.get("trusted"))
        if p >= ML_HIGH:
            conf = 85 - (TRUST_CONF_RELIEF if trusted else 0)
            verdict = "SUSPICIOUS" if trusted else "MALWARE"
            reason = f"ML p={p:.2f}" + (" (trusted-signed → downgraded)" if trusted else "")
            return _verdict(verdict, max(conf, 60), [reason], details)
        if p >= ML_MED:
            return _verdict("SUSPICIOUS", int(p * 100), [f"ML p={p:.2f}"], details)
    return _verdict("CLEAN", 0, ["No layer fired"], details)
```

- [ ] **Step 2: Write the test** (one case per precedence rule)

`tests/detection/test_fusion.py`:
```python
from Engine.Detection.fusion import fuse

def test_whitelist_wins_over_everything():
    r = fuse({"whitelisted": True, "hash_exact": True, "ml_prob": 0.99})
    assert r["verdict"] == "CLEAN" and r["confidence"] == 100

def test_exact_hash_definitive():
    r = fuse({"hash_exact": True, "ml_prob": 0.1})
    assert r["verdict"] == "MALWARE" and r["confidence"] == 100

def test_fuzzy_match():
    r = fuse({"fuzzy": {"matched": True, "source": "imphash:abc"}})
    assert r["verdict"] == "MALWARE" and r["confidence"] == 90

def test_yara_hit():
    r = fuse({"yara": ["Win32_Trojan_X"]})
    assert r["verdict"] == "MALWARE"

def test_abused_signer():
    r = fuse({"cert": {"abused": True, "trusted": True}})
    assert r["verdict"] == "MALWARE" and r["confidence"] == 95

def test_ml_high_untrusted_is_malware():
    r = fuse({"ml_prob": 0.95, "cert": {"trusted": False}})
    assert r["verdict"] == "MALWARE"

def test_ml_high_trusted_downgraded():
    r = fuse({"ml_prob": 0.95, "cert": {"trusted": True}})
    assert r["verdict"] == "SUSPICIOUS"

def test_ml_medium_suspicious():
    r = fuse({"ml_prob": 0.6})
    assert r["verdict"] == "SUSPICIOUS"

def test_nothing_fires_clean():
    r = fuse({"ml_prob": 0.1, "cert": {"trusted": True}})
    assert r["verdict"] == "CLEAN"
```

- [ ] **Step 3: Run tests**

Run: `.venv/Scripts/python.exe -m pytest tests/detection/test_fusion.py -q 2>&1 | tail -12`
Expected: 9 passed.

- [ ] **Step 4: Commit**

```bash
git add Engine/Detection/fusion.py tests/detection/test_fusion.py
git commit -m "Phase 2 Task 7: fusion policy (spec precedence table)"
```

---

### Task 8: Curated YARA rulesets

**Files:**
- Create: `Engine/Rules/curated/` (rules land here — `RULE_PATH` already points at `Engine/Rules`), `Engine/Rules/curated/README.md`
- Test: `tests/detection/test_yara_rules.py`

**Interfaces:**
- Produces: at least one compilable `.yar` ruleset under `Engine/Rules/` plus a self-authored `aria_test.yar` containing an EICAR rule, so YARA is verifiable without external malware.

- [ ] **Step 1: Fetch a permissively-licensed ruleset**

Use the Yara-Rules community set (GPL-friendly, widely used) or the smaller Elastic protections. Fetch a curated subset:
```bash
cd "D:/ZashironSentinel"
mkdir -p Engine/Rules/curated
curl -sL https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Eicar.yar -o Engine/Rules/curated/MALW_Eicar.yar
head -5 Engine/Rules/curated/MALW_Eicar.yar
```
Write `Engine/Rules/curated/README.md` recording the source repo, commit/date, and license (attribution). If a broader set is wanted, add more `.yar` files from the same repo here; keep each file self-contained (no cross-file `include`).

- [ ] **Step 2: Author a guaranteed-matchable test rule**

`Engine/Rules/curated/aria_test.yar`:
```
rule Aria_EICAR_Test_File
{
    meta:
        description = "EICAR standard antivirus test string"
        author = "Aria Security"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
```

- [ ] **Step 3: Write the test**

`tests/detection/test_yara_rules.py`:
```python
import os, glob
import yara

RULES_DIR = "Engine/Rules/curated"
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def _compile():
    files = {os.path.splitext(os.path.basename(f))[0]: f
             for f in glob.glob(os.path.join(RULES_DIR, "*.yar"))}
    return yara.compile(filepaths=files)

def test_ruleset_compiles():
    rules = _compile()
    assert rules is not None

def test_eicar_matches():
    rules = _compile()
    matches = rules.match(data=EICAR.encode())
    assert any("EICAR" in m.rule.upper() for m in matches)
```

- [ ] **Step 4: Run tests**

Run: `.venv/Scripts/python.exe -m pytest tests/detection/test_yara_rules.py -q 2>&1 | tail -12`
Expected: 2 passed. If a fetched `.yar` fails to compile (imports/deps), remove that file — keep the set to what compiles cleanly.

- [ ] **Step 5: Commit**

```bash
git add Engine/Rules/curated/ tests/detection/test_yara_rules.py
git commit -m "Phase 2 Task 8: curated YARA rulesets + EICAR test rule"
```

---

### Task 9: Integrate into VirusScanner + retire the image-CNN

**Files:**
- Modify: `Engine/Compiler/SentinelCompiler_v5.py` (swap ML layer, add fuzzy + cert, delegate to fusion)
- Modify: `Config/Sys_Config.py` (add `FUZZY_DB_PATH`, `FEATURES_META_PATH`; `DETECTION_MODEL_PATH` already `Engine/Model/…` — set to `Engine/Model/pe_detector.onnx`)
- Modify: `scripts/verify_reachability.py` (`EXPECTED_LIVE`)
- Move: `Engine/Detection/Engine_Unit_ML_v2.py` + `Engine/Model/Engine_General_ZS1.onnx` → `cleanup/phase2-old-engine/`
- Test: `tests/detection/test_virusscanner_integration.py`

**Interfaces:**
- Consumes: `MLScanner` (T4), `FuzzyHasher` (T5), `CertReputation` (T6), `fuse` (T7).

- [ ] **Step 1: Point config at the new model + DBs**

In `Config/Sys_Config.py`, set/confirm:
```python
DETECTION_MODEL_PATH = "Engine/Model/pe_detector.onnx"
FEATURES_META_PATH = "Engine/Model/features.json"
FUZZY_DB_PATH = "Engine/Signatures/fuzzy_bad.txt"
```

- [ ] **Step 2: Swap the ML layer + add fuzzy/cert + fusion in `SentinelCompiler_v5.py`**

Change the import (line ~22) from:
```python
from Engine.Detection.Engine_Unit_ML_v2 import model_scanner
```
to:
```python
from Engine.Detection.ml_scanner import MLScanner
from Engine.Detection.fuzzy_hash import FuzzyHasher
from Engine.Detection.cert_reputation import CertReputation
from Engine.Detection import fusion as _fusion
from Config.Sys_Config import FUZZY_DB_PATH, FEATURES_META_PATH
```
In `_load_resources`, replace the `model_scanner()` block with:
```python
        write_to_log("Loading ML model...")
        self.ml_scanner = MLScanner(threshold=0.5)
        model_path = find_items(DETECTION_MODEL_PATH)
        if model_path and self.ml_scanner.load_file(model_path, find_items(FEATURES_META_PATH)):
            write_to_log("✅ Loaded ONNX PE detector")
        else:
            write_to_log("❌ ML model load failed (scanner will run without ML layer)")
        self.fuzzy = FuzzyHasher(db_path=find_items(FUZZY_DB_PATH))
        self.cert = CertReputation()
```
In `scan_file`, after the exact-hash/whitelist/cache checks compute the layer results and delegate. Locate where the old code called `self.ml_scanner.model_scan(...)` and where it assembled `verdict/reasons/details`, and replace that assembly with:
```python
        # --- gather layer results ---
        ml_prob = self.ml_scanner.score(file_path)
        fuzzy_res = self.fuzzy.match(file_path)
        cert_res = self.cert.evaluate(file_path)
        yara_hits = []
        if self.rules:
            try:
                yara_hits = [m.rule for m in self.rules.match(file_path)]
            except Exception:
                yara_hits = []
        hash_exact = bool(
            (file_hash_md5 and file_hash_md5 in self.known_virus_hashes_md5) or
            (file_hash_sha256 and file_hash_sha256 in self.known_virus_hashes_sha256))

        decision = _fusion.fuse({
            "whitelisted": False,  # whitelist already returned earlier
            "hash_exact": hash_exact,
            "fuzzy": fuzzy_res,
            "yara": yara_hits,
            "ml_prob": ml_prob,
            "cert": cert_res,
        })
        result = {"verdict": decision["verdict"], "reasons": decision["reasons"],
                  "details": {**details, **decision["details"],
                              "md5": file_hash_md5, "sha256": file_hash_sha256,
                              "confidence": decision["confidence"]}}
        if file_hash_sha256:
            self._verdict_cache[file_hash_sha256] = result
        return result
```
Remove now-dead ML-only verdict code below this point in `scan_file` (the old image-CNN branch). Keep `should_scan_file`, hashing, whitelist, and cache logic intact.

- [ ] **Step 3: Retire the image-CNN**

```bash
cd "D:/ZashironSentinel"
mkdir -p cleanup/phase2-old-engine/Engine/Detection cleanup/phase2-old-engine/Engine/Model
git mv Engine/Detection/Engine_Unit_ML_v2.py cleanup/phase2-old-engine/Engine/Detection/
git mv Engine/Model/Engine_General_ZS1.onnx cleanup/phase2-old-engine/Engine/Model/
```

- [ ] **Step 4: Update the reachability expectation**

The live set loses `Engine_Unit_ML_v2` (retired) and gains `ml_scanner`, `pe_features`, `fuzzy_hash`, `cert_reputation`, `fusion` (all reachable from `SentinelCompiler_v5`). Run the checker to get the true new number, then set `EXPECTED_LIVE` in `scripts/verify_reachability.py` to that value:
```bash
.venv/Scripts/python.exe scripts/verify_reachability.py 2>&1 | tail -3
```
Edit `EXPECTED_LIVE = <printed LIVE count>`. Re-run → `PASS`.

- [ ] **Step 5: Write the integration test**

`tests/detection/test_virusscanner_integration.py`:
```python
from Engine.Properties.make_smoke_model import build
from Engine.Compiler.SentinelCompiler_v5 import VirusScanner

def test_scanner_initializes_all_layers():
    build(n=1500, seed=5)  # ensure model present
    vs = VirusScanner(max_workers=2)
    assert vs.ml_scanner is not None
    assert vs.fuzzy is not None
    assert vs.cert is not None

def test_scan_benign_system_pe(benign_pe):
    vs = VirusScanner(max_workers=2)
    r = vs.scan_file(benign_pe)
    assert r["verdict"] in ("CLEAN", "SUSPICIOUS", "MALWARE", "WHITELISTED", "IGNORED")
    # a Microsoft-signed system exe must not be a definitive MALWARE by hash/fuzzy
    assert "Known-bad hash" not in r["reasons"]
```

- [ ] **Step 6: Run tests**

Run: `.venv/Scripts/python.exe -m pytest tests/detection/ -q 2>&1 | tail -15`
Expected: entire detection suite passes.

- [ ] **Step 7: Boot verification**

Run:
```bash
SENTINEL_NO_ELEVATE=1 timeout 100 .venv/Scripts/python.exe -c "import os,sys,threading,time,urllib.request,importlib.util; os.environ['SENTINEL_NO_ELEVATE']='1'; sys.argv=['x','--no-elevate']; os.chdir(r'D:/ZashironSentinel'); sys.path.insert(0,r'D:/ZashironSentinel'); spec=importlib.util.spec_from_file_location('e','SentinelUI_Flask.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); threading.Thread(target=m._start_flask,daemon=True).start(); time.sleep(6); print('HTTP', urllib.request.urlopen('http://127.0.0.1:8765',timeout=5).status); os._exit(0)" 2>&1 | grep -E "HTTP|Error|Traceback"
```
Expected: `HTTP 200`, no traceback.

- [ ] **Step 8: Commit**

```bash
git add Engine/Compiler/SentinelCompiler_v5.py Config/Sys_Config.py scripts/verify_reachability.py tests/detection/test_virusscanner_integration.py cleanup/phase2-old-engine/
git commit -m "Phase 2 Task 9: integrate advanced engine into VirusScanner; retire image-CNN"
```

---

## Self-Review

- **Spec coverage:** §2 architecture → T9 orchestration + fusion. §3 components: pe_features→T2, ml_scanner→T4, fuzzy_hash→T5, cert_reputation→T6, fusion→T7, train→T3, make_smoke_model→T3, YARA→T8, VirusScanner/Sys_Config edits→T9, retirement→T9, deps→T1. §4 fusion precedence → T7 (test per rule). §5 data flows → T4 (scan) + T3 (train). §6 deps → T1. §7 verification: extractor(T2), smoke(T3), fuzzy(T5), cert(T6), fusion(T7), integration+boot(T9), reachability(T9). §1.1 built-now vs later → smoke model (T3) + empty fuzzy DB (T5) + deferred train (T3). All covered.
- **Placeholder scan:** none — every code step has complete code; the two external-artifact tasks (T2 extractor, T8 rules) give exact fetch commands + adaptation guidance + tests (the only honest form for vendored/downloaded artifacts).
- **Type consistency:** `MLScanner.score→float|None`, `.model_scan→("Malware",int)|(False,False)`, `FuzzyHasher.match→dict{matched,best_distance,source}`, `CertReputation.evaluate→dict{signed,trusted,revoked,abused,signer}`, `fuse→dict{verdict,confidence,reasons,details}` — used identically in T9 wiring. `PEFeatureExtractor.version/dim/feature_vector` consistent T2↔T4.
- **Known open detail:** `EXPECTED_LIVE` new value is computed at T9 Step 4 (can't be known until the files exist), not hard-coded — intentional.
