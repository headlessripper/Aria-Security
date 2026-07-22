import os
import sys


def base_path() -> str:
    """Root that repo-root-relative data paths resolve against.

    Running from source this is the repo root. Frozen with PyInstaller there is
    no repo root, so bundled data lives under sys._MEIPASS (onefile: the temp
    extraction dir; onedir: the exe's folder). Every data path in the app is a
    repo-root-relative string resolved through find_items(), so making this one
    function frozen-aware is what lets the whole app run from an exe.
    """
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return meipass
        return os.path.dirname(os.path.realpath(sys.executable))
    script_dir = os.path.dirname(os.path.realpath(__file__))   # .../Interface
    return os.path.dirname(script_dir)                         # repo root


def find_items(icon_name):
    """Resolve a repo-root-relative asset/data path, with sensible fallbacks.

    find_items.py lives in Interface/, so from source the repo root is its
    parent directory. Paths passed in are repo-root-relative
    (e.g. "Interface/Icons/Icon-48.png").
    """
    if not icon_name:
        return None
    if os.path.isabs(icon_name):
        return icon_name if os.path.exists(icon_name) else None

    root = base_path()
    script_dir = os.path.dirname(os.path.realpath(__file__))
    candidates = [root, script_dir, os.getcwd()]
    if getattr(sys, "frozen", False):
        # onedir layouts keep data beside the exe (and under _internal/)
        exe_dir = os.path.dirname(os.path.realpath(sys.executable))
        candidates[1:1] = [exe_dir, os.path.join(exe_dir, "_internal")]

    for base in candidates:
        p = os.path.join(base, icon_name)
        if os.path.exists(p):
            return p
    return None
