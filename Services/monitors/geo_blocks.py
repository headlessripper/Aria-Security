"""Geo-block persistence — read/write the country-block map as JSON.
Pure I/O helper; no Flask. Atomic write so a crash can't corrupt the file."""
from __future__ import annotations
import json
import os
from pathlib import Path


def load(path) -> dict:
    p = Path(path)
    try:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def save(path, data: dict) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + f".{os.getpid()}.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, p)
