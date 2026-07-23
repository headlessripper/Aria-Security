# PyInstaller spec — Aria Security (user-mode build, no kernel driver).
#
# Build:  .venv\Scripts\python.exe -m PyInstaller packaging\aria.spec --noconfirm
# Output: dist\AriaSecurity\AriaSecurity.exe   (onedir: faster start, easier to sign)
#
# Everything in the app addresses its data as repo-root-relative strings resolved
# through Interface.find_items.find_items(), which is frozen-aware — so the data
# below only has to land at the bundle root under the same relative layout.

import os
from PyInstaller.utils.hooks import collect_dynamic_libs, collect_submodules

ROOT = os.path.abspath(os.getcwd())


def tree(rel):
    """(source, dest) pair keeping the repo-relative layout inside the bundle."""
    return (os.path.join(ROOT, rel), rel)


datas = [
    tree("Engine/Model"),        # pe_detector.onnx + features.json (real EMBER model)
    tree("Engine/Rules"),        # YARA rules + behavioral_rules.json
    tree("Engine/Signatures"),   # hash DBs + fuzzy
    tree("Engine/Whitelist"),
    tree("Config"),              # Config.json
    tree("templates"),           # the SPA
    tree("static"),              # vendored socket.io + fonts
    tree("Interface/Icons"),     # tray / notification icons
    tree("Argus"),               # soul.md / mind.md persona
]

# Native payloads PyInstaller's default analysis tends to miss.
binaries = []
for pkg in ("onnxruntime", "lightgbm", "lief", "yara", "llama_cpp"):
    try:
        binaries += collect_dynamic_libs(pkg)
    except Exception:
        pass

hiddenimports = [
    # Flask-SocketIO picks its async driver at runtime.
    "engineio.async_drivers.threading",
    "socketio", "engineio", "flask_socketio",
    # Native / lazily-imported engine deps.
    "onnxruntime", "lightgbm", "lief", "yara", "sklearn.ensemble",
    # Filesystem journal (SentinelSense) + notifications + native dialogs.
    "watchdog.observers", "watchdog.observers.winapi", "winotify",
    "tkinter", "tkinter.filedialog",
    "win32timezone",            # pywin32 pulls this in lazily
]
for pkg in ("Services", "Engine", "Interface", "Actions", "Argus", "Config"):
    try:
        hiddenimports += collect_submodules(pkg)
    except Exception:
        pass

excludes = [
    # Only ever used by the guarded Qt-context block and the dead
    # Interface/Pages/UsbAllowlistPage.py — the brain has its own _Signal class.
    # Dropping it saves well over 100 MB.
    "PySide6", "PyQt5", "PyQt6", "shiboken6",
    # Dev/analysis-only.
    "matplotlib", "notebook", "IPython", "pytest", "pandas",
]

a = Analysis(
    ["../SentinelUI_Flask.py"],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="AriaSecurity",
    console=False,              # windowed: the UI is the SPA
    disable_windowed_traceback=False,
    icon=os.path.join(ROOT, "Interface", "Icons", "Icon-100.ico"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,                  # UPX-packed AV binaries trip other scanners
    name="AriaSecurity",
)
