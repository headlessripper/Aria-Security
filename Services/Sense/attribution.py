"""Attribute journaled filesystem activity to a newly-installed application.

Pure logic: given the filesystem journal (what got created, and when) and the
registry record of an app that just appeared, decide which paths that installer
is responsible for. Kept free of I/O so it is directly unit-testable.

A journal entry belongs to an app when it was created within the install time
window AND it either lives under the app's install directory or its path carries
a recognisable token of the app's name or publisher.
"""
from __future__ import annotations

import os
import re
from typing import Iterable, List, Sequence, Tuple

# Tokens too generic to attribute an app by.
_STOPWORDS = {
    "the", "inc", "llc", "ltd", "corp", "corporation", "company", "software",
    "technologies", "technology", "systems", "app", "application", "program",
    "programs", "setup", "install", "installer", "update", "updater", "common",
    "files", "data", "local", "temp", "roaming", "microsoft", "windows",
}
_MIN_TOKEN = 4


def name_tokens(*names: str) -> List[str]:
    """Lower-cased, de-noised identifier tokens from an app/publisher name."""
    out: List[str] = []
    for n in names:
        for tok in re.split(r"[^a-z0-9]+", (n or "").lower()):
            if len(tok) >= _MIN_TOKEN and tok not in _STOPWORDS and tok not in out:
                out.append(tok)
    return out


def attribute(journal: Sequence[tuple], app_info: dict, installed_at: float,
              window_s: float = 900.0) -> Tuple[List[str], List[str]]:
    """Return (files, dirs) attributable to the app.

    journal: sequence of (path, timestamp, is_dir).
    app_info: {"name", "publisher", "install_location"}.
    installed_at: when the app was first seen in the registry.
    window_s: how far on either side of `installed_at` to consider (default 15m).
    """
    install_loc = (app_info.get("install_location") or "").strip()
    loc_norm = os.path.normcase(os.path.abspath(install_loc)) if install_loc else ""
    tokens = name_tokens(app_info.get("name", ""), app_info.get("publisher", ""))

    files: List[str] = []
    dirs: List[str] = []

    for entry in journal:
        try:
            path, ts, is_dir = entry[0], float(entry[1]), bool(entry[2])
        except Exception:
            continue
        if not path:
            continue
        # time window
        if abs(ts - installed_at) > window_s:
            continue

        p_norm = os.path.normcase(os.path.abspath(path))

        matched = False
        # under the app's own install directory
        if loc_norm and (p_norm == loc_norm or
                         p_norm.startswith(loc_norm.rstrip(os.sep) + os.sep)):
            matched = True
        # or the path carries a name/publisher token
        elif tokens and any(t in p_norm for t in tokens):
            matched = True

        if not matched:
            continue
        (dirs if is_dir else files).append(path)

    return sorted(set(files)), sorted(set(dirs))


def footprint_paths(files: Iterable[str], dirs: Iterable[str]) -> List[str]:
    """Flatten a footprint to the path list used for residual checks/deletion."""
    return sorted(set([p for p in files if p] + [p for p in dirs if p]))
