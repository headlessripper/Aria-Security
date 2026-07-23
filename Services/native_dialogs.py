"""Native Windows file/folder pickers for the UI.

The UI runs in a WebView/browser, which cannot open a native picker and never
sees a real filesystem path. Since Aria's server and its window are the same
machine, the dialog is opened here and only the chosen path is handed back.

tkinter is used because it is stdlib and maps to the modern Windows common
dialogs. Each dialog runs on its own short-lived thread with its own Tk root
(Tk is not safe to reuse across threads) and is forced topmost so it surfaces
above the frameless app window.

Never raises: a cancelled dialog and a failed dialog are both reported, so a
picker can never take the app down.
"""
from __future__ import annotations

import os
import threading
from typing import Callable, Dict, Optional

# A dialog left open by the user shouldn't leak a thread forever, but it also
# must not be yanked away mid-selection; 10 minutes is a generous ceiling.
_DIALOG_TIMEOUT_S = 600

# Only one native dialog at a time — two modal pickers would fight for focus.
_dialog_lock = threading.Lock()


def _run_dialog(pick: Callable) -> Dict[str, object]:
    """Run `pick(filedialog, root)` on a dedicated thread with its own Tk root."""
    out: Dict[str, object] = {}

    def worker():
        root = None
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk()
            root.withdraw()                       # no empty Tk window
            root.attributes("-topmost", True)     # above the frameless app window
            root.update()
            out["path"] = pick(filedialog, root) or ""
        except Exception as e:                    # tkinter missing / no display
            out["error"] = str(e)
        finally:
            try:
                if root is not None:
                    root.destroy()
            except Exception:
                pass

    t = threading.Thread(target=worker, daemon=True, name="AriaPicker")
    t.start()
    t.join(_DIALOG_TIMEOUT_S)
    if t.is_alive():
        return {"error": "dialog timed out"}
    return out


def _normalize(path: object) -> str:
    """Tk returns '' on cancel and forward slashes on Windows."""
    if not path:
        return ""
    return os.path.normpath(str(path))


def pick_file(title: str = "Select a file", initial_dir: str = "") -> Dict[str, object]:
    """Open a native 'open file' dialog. Returns {"path": str} ("" if cancelled)."""
    def _pick(filedialog, root):
        kw = {"parent": root, "title": title}
        if initial_dir and os.path.isdir(initial_dir):
            kw["initialdir"] = initial_dir
        return filedialog.askopenfilename(**kw)

    with _dialog_lock:
        res = _run_dialog(_pick)
    if "error" in res:
        return {"path": "", "error": res["error"]}
    return {"path": _normalize(res.get("path"))}


def pick_folder(title: str = "Select a folder", initial_dir: str = "") -> Dict[str, object]:
    """Open a native folder picker. Returns {"path": str} ("" if cancelled)."""
    def _pick(filedialog, root):
        kw = {"parent": root, "title": title, "mustexist": True}
        if initial_dir and os.path.isdir(initial_dir):
            kw["initialdir"] = initial_dir
        return filedialog.askdirectory(**kw)

    with _dialog_lock:
        res = _run_dialog(_pick)
    if "error" in res:
        return {"path": "", "error": res["error"]}
    return {"path": _normalize(res.get("path"))}


def pick(mode: str, title: str = "", initial_dir: str = "") -> Dict[str, object]:
    """Dispatch on mode: 'file' or 'folder'. Unknown mode -> error, never raises."""
    mode = (mode or "").lower().strip()
    if mode == "file":
        return pick_file(title or "Select a file", initial_dir)
    if mode == "folder":
        return pick_folder(title or "Select a folder", initial_dir)
    return {"path": "", "error": f"unknown picker mode: {mode!r}"}
