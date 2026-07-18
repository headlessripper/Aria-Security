# Phase 2 — Advanced Detection Engine + Model — Design

**Date:** 2026-07-18
**Status:** Design (awaiting user review) → then implementation plan.
**Predecessor:** Phase 1 (cleanup) + reorg done. Master spec: `2026-07-17-zashiron-rebuild-design.md`.

---

## 1. Context & Scope

Aria Security's PE-file malware detector is the 4-layer `VirusScanner`
(`Engine/Compiler/SentinelCompiler_v5.py`): **exact-hash + YARA + ML + signature**.
The ML layer is currently a **malware-as-image CNN** (`Engine/Detection/Engine_Unit_ML_v2.py`
+ `Engine/Model/Engine_General_ZS1.onnx`) — weak and easily evaded.

Phase 2 rebuilds this into an **advanced 4-layer engine** where each layer is the best
version of what it does, combined by an explicit fusion policy:

1. **ML** — EMBER-style static-PE features → LightGBM → ONNX (replaces the image-CNN).
2. **Hash** — exact (MD5/SHA256) **+ fuzzy/similarity** (imphash + TLSH nearest-neighbor).
3. **YARA** — advanced curated open-source rulesets (replaces the small current set).
4. **Signature** — Windows `WinVerifyTrust` (kept) + signer/cert reputation; signer trust
   also flows into the ML feature vector for free.

**Out of scope (Phase 3 / post-dataset):** the network/NIDS/phishing `.pkl` models
(used only by `Services/Protection/SentinelNetProtectionNG2.py`); ML-*generated* YARA
rules and a trained cert-reputation *model* (both need a malware corpus we don't have yet).

### 1.1 Built now vs. populated later (the data-dependency reality)

Per the approved "pipeline first, train later" decision, all **machinery** is built and
verifiable now; the **knowledge** for two data-dependent layers is loaded later with a corpus:

| Capability | Built now | Populated later (with corpus/dataset) |
|---|---|---|
| EMBER feature extractor | ✅ full | — |
| LightGBM trainer + ONNX export | ✅ full | trained weights (mid-size test, then full EMBER 2018) |
| ML inference scanner | ✅ full | loads the real ONNX when trained |
| Fuzzy hash (imphash/TLSH) compute + index | ✅ full | the known-bad reference DB |
| Curated YARA rulesets | ✅ full & functional | — |
| Signature / cert reputation (WinVerifyTrust + revocation) | ✅ full & functional | optional known-abused-cert seed list |
| Fusion policy | ✅ full & functional | — |

To keep the engine verifiable now, a **synthetic smoke model** (throwaway LightGBM on
generated data) produces a valid ONNX so the whole `extract → ONNX → verdict` path runs.

---

## 2. Architecture

`VirusScanner` stays the orchestrator: it loads resources, runs each layer on a confirmed
PE, collects per-layer results, and calls a new **fusion** module for the final verdict.
Each layer is a focused, independently testable unit.

```
scan_file(path)
   ├─ gate: is_pe + whitelist
   ├─ exact hash  ──► HashLayer   (known-bad MD5/SHA256 set)        → hit? verdict
   ├─ fuzzy hash  ──► FuzzyHasher (imphash + TLSH vs known-bad DB)  → similarity score
   ├─ YARA        ──► yara.rules  (curated rulesets)                → rule matches
   ├─ ML          ──► MLScanner   (EMBER features → ONNX prob)      → malware probability
   ├─ signature   ──► CertReputation (WinVerifyTrust + revocation)  → trust signal
   └─ fusion.fuse(results) ──► {verdict, confidence, reasons, details}
```

---

## 3. Components

| File | Responsibility | Key interface |
|---|---|---|
| `Engine/Detection/pe_features.py` | Vendored EMBER v2 feature extractor (Apache-2.0, attributed). Deps: `lief`, `numpy`. | `PEFeatureExtractor().feature_vector(bytez: bytes) -> np.ndarray[float32, 2381]`; `.dim` |
| `Engine/Detection/ml_scanner.py` | ONNX ML scanner; drop-in for the old `model_scanner`. | `MLScanner(threshold=0.5)`; `.load_file(onnx_path) -> bool`; `.model_scan(path) -> (label:str, conf:int) | (False, False)`; `.score(path) -> float|None` |
| `Engine/Detection/fuzzy_hash.py` | imphash (via `pefile`) + TLSH (via `python-tlsh`); nearest-neighbor vs known-bad DB. | `FuzzyHasher(db_path)`; `.imphash(path) -> str|None`; `.tlsh(bytez) -> str|None`; `.match(path) -> {matched:bool, best_distance:int, source:str}` |
| `Engine/Detection/cert_reputation.py` | Wraps `Engine/Detection/Engine_Unit_SG.sign_scanner` (WinVerifyTrust) + signer name + revocation + known-abused seed list. | `CertReputation()`; `.evaluate(path) -> {signed:bool, trusted:bool, revoked:bool, abused:bool, signer:str|None}` |
| `Engine/Detection/fusion.py` | Pure decision policy combining all layer results. | `fuse(results: dict) -> {verdict, confidence, reasons, details}` |
| `Engine/Properties/train.py` | Trainer: EMBER/BODMAS vectors → LightGBM → ONNX + `features.json`. Deferred run. | CLI: `python -m Engine.Properties.train --data <path> --format {ember,bodmas} --out Engine/Model/pe_detector.onnx` |
| `Engine/Properties/make_smoke_model.py` | Synthetic-data LightGBM → valid ONNX for pipeline validation. Non-production. | CLI: `python -m Engine.Properties.make_smoke_model` |
| `Engine/Heuristic/*.yar[a]` | Advanced curated open-source YARA rulesets (permissively licensed; attributed). | consumed by `VirusScanner._load_yara` via `RULE_PATH` |
| `Engine/Compiler/SentinelCompiler_v5.py` (edit) | Orchestrator: swap ML layer to `MLScanner`, add `FuzzyHasher` + `CertReputation`, delegate verdict to `fusion.fuse`. | — |
| `Config/Sys_Config.py` (edit) | `DETECTION_MODEL_PATH → Engine/Model/pe_detector.onnx`; add `FUZZY_DB_PATH`, `FEATURES_META_PATH`. | — |

### 3.1 Retirement
Move to `cleanup/phase2-old-engine/`: `Engine/Detection/Engine_Unit_ML_v2.py` (image-CNN)
and `Engine/Model/Engine_General_ZS1.onnx`. `Engine_Unit_SG.py` (WinVerifyTrust) is **kept**
and reused by `cert_reputation.py`.

---

## 4. Fusion Policy (`fusion.fuse`)

Deterministic precedence, producing `verdict ∈ {CLEAN, SUSPICIOUS, MALWARE}` + confidence 0-100 + reasons:

1. **Whitelist** (path or hash) → `CLEAN` (handled before fusion).
2. **Exact known-bad hash** → `MALWARE`, confidence 100 (definitive).
3. **Fuzzy match** to known-bad (TLSH distance ≤ `TLSH_NEAR` or known-bad imphash) → `MALWARE`, 90.
4. **YARA** family/malware rule hit → `MALWARE`, 90 (rule-tagged severity may downgrade to `SUSPICIOUS`).
5. **ML** probability `p`: `p ≥ HIGH (0.9)` → `MALWARE` (85, minus trust bonus); `p ≥ MED (0.5)` → `SUSPICIOUS`.
6. **Signature** modifier: `trusted & valid` signature lowers score (strong benign prior);
   `signed-by-abused-cert` raises to `MALWARE`.
7. No layer fires → `CLEAN`.

Multiple concurrent hits raise confidence. All thresholds are named constants in `fusion.py`.

---

## 5. Data Flows

**Scan (runtime):** PE bytes → PE-header gate → parallel layers (hash/fuzzy/YARA/ML/sig) →
`fusion.fuse` → verdict dict consumed by the existing `VirusScanner` callers/quarantine flow.

**Train (deferred, one command):** dataset vectors `(X[n,2381], y[n])` → `train_test_split` →
LightGBM (`objective=binary`, EMBER-style params) → evaluate (AUC, TPR@FPR, top features) →
export `pe_detector.onnx` (via `onnxmltools.convert_lightgbm`) + `features.json` (order + feature-version).
`features.json` version must match `pe_features.py`'s version, else the scanner refuses to load (guard).

---

## 6. Dependencies
Add to `.venv` + a `requirements.txt`: `lightgbm`, `lief`, `onnxmltools`, `python-tlsh`.
Already present: `onnxruntime`, `numpy`, `pefile`, `scikit-learn`, `yara-python`.

---

## 7. Verification (must pass to call Phase 2 done — pipeline scope)

1. **Extractor** — `feature_vector()` returns a finite `float32[2381]` on a real benign PE
   (a Windows system exe), deterministic across two runs; handles a truncated/non-PE input
   without raising (returns zeros or a defined error).
2. **Smoke model** — `make_smoke_model` yields a loadable ONNX; `MLScanner.score()` returns a
   float in [0,1] on a benign PE.
3. **Fuzzy** — `imphash`/`tlsh` compute on a real PE; `match()` returns `matched=False` against
   an empty known-bad DB without error.
4. **Cert** — `evaluate()` on a signed Windows binary returns `trusted=True`; on an unsigned
   file returns `signed=False`.
5. **Fusion** — unit tests over synthetic layer-result dicts assert the precedence table (each
   rule 1-7) produces the expected verdict/confidence.
6. **Integration + boot** — `VirusScanner` initializes all layers with no error; app boots
   (HTTP 200 on :8765); `scan_file` on a benign PE returns `CLEAN`, on the smoke-flagged
   synthetic case returns `MALWARE`.
7. **Reachability gate** stays green; retired image-CNN no longer imported.

---

## 8. Risks & Mitigations
- **LIEF API drift** — EMBER's extractor targets an older `lief`. Mitigation: pin `lief` to a
  compatible version, or adapt the vendored extractor to the installed `lief`; **verify the
  extractor runs on a real PE before building dependents.**
- **YARA ruleset licensing/size** — pick a permissively-licensed ruleset (attribution kept),
  vendor a curated subset; keep the load path tolerant of malformed rules.
- **ONNX/LightGBM export parity** — validate exported ONNX predictions match the native
  LightGBM on a holdout batch (parity test in `train.py`).
- **No trained weights yet** — engine ships with the smoke model; real detection quality
  arrives with the deferred training. This is expected and documented, not a defect.

---

## 9. Deferred to post-dataset phase
Real training (mid-size test → full EMBER 2018 production); populating the fuzzy-hash known-bad
DB; ML-generated YARA rules; a trained cert-reputation model.
