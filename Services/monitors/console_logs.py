"""Console-page log aggregation. Path-agnostic: the caller injects the log
directory and the list of log filenames, so this is testable with tmp dirs."""
from __future__ import annotations
from pathlib import Path


def tail(log_dir, log_files, lines: int, module: str = "") -> list:
    log_dir = Path(log_dir)
    module = (module or "").lower()
    all_lines: list = []
    for fname in log_files:
        if module and module not in fname.lower():
            continue
        lp = log_dir / fname
        if not lp.exists():
            continue
        stem = lp.stem
        with lp.open("r", encoding="utf-8", errors="replace") as f:
            chunk = f.readlines()[-200:]
        all_lines.extend(f"[{stem}] {l.rstrip()}" for l in chunk if l.strip())
    return all_lines[-lines:]


def clear(log_dir, log_files, module: str = "") -> int:
    log_dir = Path(log_dir)
    module = (module or "").lower()
    cleared = 0
    for fname in log_files:
        if module and module not in fname.lower():
            continue
        lp = log_dir / fname
        if lp.exists():
            lp.write_text("", encoding="utf-8")
            cleared += 1
    return cleared
