import os


def find_menu(icon_name):
    """Resolve a repo-root-relative menu/icon path, with sensible fallbacks.

    find_menu.py lives in Interface/, so the repo root is its parent directory.
    Paths passed in are repo-root-relative (e.g. "Interface/Menu/Icon-48.png").
    """
    if not icon_name:
        return None
    if os.path.isabs(icon_name):
        return icon_name if os.path.exists(icon_name) else None
    script_dir = os.path.dirname(os.path.realpath(__file__))   # .../Interface
    repo_root = os.path.dirname(script_dir)                    # repo root
    for base in (repo_root, script_dir, os.getcwd()):
        p = os.path.join(base, icon_name)
        if os.path.exists(p):
            return p
    return None
