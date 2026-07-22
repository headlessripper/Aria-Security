"""Vectorize EMBER 2018 raw-feature JSONL into the X_*.dat / y_*.dat memmaps
that Engine/Properties/train.py consumes.

Uses the project's OWN EMBER extractor (Engine/Detection/pe_features.py, adapted
to LIEF 0.15.1) rather than the upstream `ember` package, so no extra dependency
or LIEF-version pinning is required. The EMBER JSONL already contains the raw
feature dicts (keys: histogram, byteentropy, strings, general, header, section,
imports, exports, datadirectories), which PEFeatureExtractor.process_raw_features
turns into the fixed 2381-dim float32 vector.

Written incrementally (one vector at a time appended to X_<split>.dat) so memory
stays flat regardless of dataset size.

Usage:
  python -m Engine.Properties.vectorize_ember --data <ember_dir> --out <dir> \
      --split train [--labeled-only] [--limit N]
"""
import argparse
import glob
import json
import time
from pathlib import Path

import numpy as np

from Engine.Detection.pe_features import PEFeatureExtractor

DIM = 2381


def jsonl_files(data: Path, split: str):
    if split == "train":
        pats = ["train_features_*.jsonl"]
    else:
        pats = ["test_features.jsonl", "test_features_*.jsonl"]
    files = []
    for p in pats:
        files += glob.glob(str(data / p))
    return sorted(set(files))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="dir with EMBER *_features*.jsonl")
    ap.add_argument("--out", required=True, help="output dir for X_/y_ .dat files")
    ap.add_argument("--split", choices=["train", "test"], default="train")
    ap.add_argument("--labeled-only", action="store_true",
                    help="skip unlabeled (label == -1) rows")
    ap.add_argument("--limit", type=int, default=0, help="stop after N kept rows (0 = all)")
    a = ap.parse_args()

    data = Path(a.data)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    ext = PEFeatureExtractor(feature_version=2, print_feature_warning=False)
    assert ext.dim == DIM, f"extractor dim {ext.dim} != {DIM}"

    files = jsonl_files(data, a.split)
    if not files:
        raise SystemExit(f"no {a.split} JSONL found under {data}")
    print(f"[vectorize] {a.split}: {len(files)} file(s); dim={DIM}; "
          f"labeled_only={a.labeled_only} limit={a.limit or 'all'}", flush=True)

    xpath = out / f"X_{a.split}.dat"
    ypath = out / f"y_{a.split}.dat"
    labels = []
    n = 0
    skipped = 0
    t0 = time.time()
    with open(xpath, "wb") as xf:
        for fp in files:
            with open(fp, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        raw = json.loads(line)  # tolerate a truncated/partial line
                    except Exception:
                        skipped += 1
                        continue
                    y = int(raw.get("label", -1))
                    if a.labeled_only and y == -1:
                        continue
                    vec = ext.process_raw_features(raw).astype(np.float32)
                    if vec.shape[0] != DIM:
                        raise SystemExit(f"bad vector dim {vec.shape[0]} at row {n}")
                    xf.write(vec.tobytes())
                    labels.append(y)
                    n += 1
                    if n % 25000 == 0:
                        rate = n / max(1e-6, time.time() - t0)
                        print(f"[vectorize] {n} rows ({rate:.0f}/s)", flush=True)
                    if a.limit and n >= a.limit:
                        break
            if a.limit and n >= a.limit:
                break

    np.array(labels, dtype=np.int8).tofile(ypath)
    dt = time.time() - t0
    print(f"[vectorize] DONE: {n} x {DIM} -> {xpath} ({xpath.stat().st_size/1048576:.0f} MB), "
          f"labels -> {ypath}  in {dt:.0f}s (skipped {skipped} unparseable lines)", flush=True)
    # label balance sanity
    ya = np.fromfile(ypath, dtype=np.int8)
    uniq, cnt = np.unique(ya, return_counts=True)
    print(f"[vectorize] label counts: {dict(zip(uniq.tolist(), cnt.tolist()))}", flush=True)


if __name__ == "__main__":
    main()
