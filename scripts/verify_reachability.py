# scripts/verify_reachability.py
"""Reachability invariant checker. Green = live set matches EXPECTED_LIVE and
no live module resolves under cleanup/. Run from repo root."""
import ast, os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRY = ROOT / "SentinelUI_Flask.py"
EXPECTED_LIVE = 33

def index():
    by_dotted, by_stem = {}, {}
    for p in ROOT.rglob("*.py"):
        s = str(p)
        if ".venv" in s or "__pycache__" in s or f"{os.sep}.claude{os.sep}" in s \
           or f"{os.sep}scripts{os.sep}" in s or f"{os.sep}docs{os.sep}" in s:
            continue
        rel = p.relative_to(ROOT).with_suffix("")
        by_dotted[".".join(rel.parts)] = p
        by_stem.setdefault(p.stem, []).append(p)
    return by_dotted, by_stem

def resolve(name, from_file, by_dotted, by_stem):
    if not name:
        return None
    if name in by_dotted:
        return by_dotted[name]
    for dotted, path in by_dotted.items():
        if dotted.endswith("." + name):
            return path
    last = name.split(".")[-1]
    if last in by_stem:
        same = [c for c in by_stem[last] if c.parent == from_file.parent]
        return same[0] if same else by_stem[last][0]
    return None

def walk(by_dotted, by_stem):
    visited, stack = set(), [ENTRY]
    while stack:
        path = stack.pop()
        if path in visited:
            continue
        visited.add(path)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for n in names:
                t = resolve(n, path, by_dotted, by_stem)
                if t and ROOT in t.parents:
                    stack.append(t)
    return visited

def main():
    by_dotted, by_stem = index()
    live = walk(by_dotted, by_stem)
    live_rel = sorted(str(p.relative_to(ROOT)).replace("\\", "/") for p in live)
    in_cleanup = [p for p in live_rel if p.startswith("cleanup/")]
    print(f"LIVE={len(live)}")
    ok = True
    if len(live) != EXPECTED_LIVE:
        print(f"[FAIL] live count {len(live)} != expected {EXPECTED_LIVE}")
        for p in live_rel:
            print("  L", p)
        ok = False
    if in_cleanup:
        print("[FAIL] live modules resolve under cleanup/:")
        for p in in_cleanup:
            print("  X", p)
        ok = False
    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
