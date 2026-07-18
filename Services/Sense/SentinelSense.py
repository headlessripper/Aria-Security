#!/usr/bin/env python3
"""
Sentinel Sense (Core + GUI)

- Runs a background monitor loop (install/uninstall tracker + artifact mapper).
- When an app is uninstalled and leftovers are detected, shows a GUI main window.
- The main window stays hidden otherwise and only appears when leftovers are found.

Files:
- ~/.SentinelSense/sense_map.json
- ~/.SentinelSense/sense_events.json
"""

import os
import sys
import time
import json
import shutil
import hashlib
import traceback
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional

import winreg

# ── Qt is OPTIONAL ────────────────────────────────────────────────────────────
# The core monitor loop (install/uninstall tracking + residual detection) has no
# GUI dependency. Qt is only needed for the standalone leftovers window. Making it
# optional lets the main engine import + run the core without a QApplication.
try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel,
        QListWidget, QListWidgetItem, QPushButton, QHBoxLayout,
        QTabWidget, QMessageBox,
    )
    from PySide6.QtCore import Qt, QTimer, QObject
    from PySide6.QtGui import QIcon
    _QT_AVAILABLE = True
except Exception:
    _QT_AVAILABLE = False
    # Minimal stand-ins so the module still imports in headless mode. The GUI
    # classes (MainWindow/SenseGuiApp) are defined but never instantiated when
    # Qt is unavailable — only the core monitor loop + controller are used.
    class _QtStub:  # type: ignore
        def __init__(self, *a, **k): pass
        def __getattr__(self, _n): return lambda *a, **k: None
    QObject = QMainWindow = QApplication = QWidget = _QtStub  # type: ignore
    QVBoxLayout = QLabel = QListWidget = QListWidgetItem = _QtStub  # type: ignore
    QPushButton = QHBoxLayout = QTabWidget = QMessageBox = _QtStub  # type: ignore
    QTimer = QIcon = _QtStub  # type: ignore
    class Qt:  # type: ignore
        ItemIsUserCheckable = Unchecked = Checked = 0

# ── Config / helpers: support BOTH standalone (bare names) and packaged imports ─
try:
    from Sys_Config import APP_NAME
except Exception:
    try:
        from Config.Sys_Config import APP_NAME
    except Exception:
        APP_NAME = "Aria Security"

try:
    from find_menu import find_menu
except Exception:
    try:
        from Interface.find_menu import find_menu
    except Exception:
        def find_menu(p):  # type: ignore
            return p

try:
    from write_to_log import write_to_log
except Exception:
    try:
        from Interface.write_to_log import write_to_log
    except Exception:
        def write_to_log(msg, path):  # type: ignore
            try:
                print(f"[Sense] {msg}")
            except Exception:
                pass

try:
    from winotify import Notification, audio
except Exception:
    Notification = None  # type: ignore
    audio = None         # type: ignore

SYSTEM_ICON_PATH = "Interface/Menu/Icon-48.png"

# =========================
# PATHS / CONFIG
# =========================

HOME_DIR = Path.home() / ".AriaSecurity" / ".SentinelSense"
HOME_DIR.mkdir(parents=True, exist_ok=True)

SENSE_MAP_FILE = HOME_DIR / "sense_map.json"
EVENT_QUEUE_FILE = HOME_DIR / "sense_events.json"
LOG_FILE_CORE = HOME_DIR / "sense_core.log"
LOG_FILE_GUI = HOME_DIR / "sense_gui.log"

SCAN_INTERVAL = 30  # seconds

UNINSTALL_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
]

USER_APP_DIRS = [
    os.environ.get("ProgramFiles", r"C:\Program Files"),
    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    os.environ.get("LOCALAPPDATA", r"C:\Users\Default\AppData\Local"),
    os.environ.get("APPDATA", r"C:\Users\Default\AppData\Roaming"),
    os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
]

SYSTEM_PUBLISHERS = {
    "microsoft corporation",
    "microsoft",
    "intel corporation",
    "advanced micro devices, inc.",
}

APP_ICON_PATH = find_menu(SYSTEM_ICON_PATH)

# =========================
# UTILITIES
# =========================

def log_core(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [CORE] {msg}"
    write_to_log(f"{line}", 'logs/Sense.log')
    LOG_FILE_CORE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE_CORE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def log_gui(msg: str):
    from time import strftime
    ts = strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [GUI] {msg}"
    write_to_log(f"{line}", 'logs/Sense.log')
    LOG_FILE_GUI.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE_GUI, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _safe_toast(title: str, msg: str):
    """Show a Windows toast if winotify is available; no-op otherwise."""
    if Notification is None:
        return
    try:
        toast = Notification(
            app_id=APP_NAME, title=title, msg=msg,
            icon=find_menu(SYSTEM_ICON_PATH), duration="short",
        )
        if audio is not None:
            toast.set_audio(audio.Default, loop=True)
        toast.show()
    except Exception:
        pass


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode(errors="ignore")).hexdigest()


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log_core(f"Failed to load JSON from {path}: {e}")
        return default


def save_json(path: Path, data: Any):
    try:
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception as e:
        log_core(f"Failed to save JSON to {path}: {e}")

# =========================
# SENSE MAP + EVENTS
# =========================

def load_sense_map() -> Dict[str, Any]:
    data = load_json(SENSE_MAP_FILE, {"apps": {}})
    if "apps" not in data or not isinstance(data["apps"], dict):
        data["apps"] = {}
    return data


def save_sense_map(data: Dict[str, Any]):
    save_json(SENSE_MAP_FILE, data)


def push_event(event: Dict[str, Any]):
    events = load_json(EVENT_QUEUE_FILE, [])
    events.append(event)
    save_json(EVENT_QUEUE_FILE, events)


def remove_handled_event(event_to_remove: Dict[str, Any]):
    events = load_json(EVENT_QUEUE_FILE, [])
    filtered = []
    for e in events:
        if (
            e.get("type") == event_to_remove.get("type")
            and e.get("app_id") == event_to_remove.get("app_id")
            and e.get("timestamp") == event_to_remove.get("timestamp")
        ):
            continue
        filtered.append(e)
    save_json(EVENT_QUEUE_FILE, filtered)

# =========================
# CORE: APP ENUM + ARTIFACTS
# =========================

def _read_reg_value(key, name: str) -> Optional[str]:
    try:
        val, _ = winreg.QueryValueEx(key, name)
        if isinstance(val, str):
            return val
    except OSError:
        return None
    return None


def _is_user_app(display_name: Optional[str], publisher: Optional[str],
                 install_location: Optional[str]) -> bool:
    if not display_name:
        return False

    dn = display_name.strip()
    if not dn:
        return False

    if publisher and publisher.strip().lower() in SYSTEM_PUBLISHERS:
        return False

    if not install_location:
        return True

    il = install_location.strip()
    if not il:
        return True

    il_norm = os.path.normpath(il).lower()
    for base in USER_APP_DIRS:
        if not base:
            continue
        base_norm = os.path.normpath(base).lower()
        if il_norm.startswith(base_norm):
            return True

    return False


def snapshot_installed_apps() -> Dict[str, Dict[str, Any]]:
    apps: Dict[str, Dict[str, Any]] = {}

    for hive, path in UNINSTALL_KEYS:
        if hive == winreg.HKEY_CURRENT_USER:
            hive_label = "HKCU"
        else:
            hive_label = "HKLM"

        try:
            root = winreg.OpenKey(hive, path)
        except OSError:
            continue

        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(root, i)
                i += 1
            except OSError:
                break

            full_subkey_path = path + "\\" + subkey_name
            try:
                subkey = winreg.OpenKey(hive, full_subkey_path)
            except OSError:
                continue

            try:
                display_name = _read_reg_value(subkey, "DisplayName")
                display_version = _read_reg_value(subkey, "DisplayVersion")
                publisher = _read_reg_value(subkey, "Publisher")
                install_location = _read_reg_value(subkey, "InstallLocation")
                uninstall_string = _read_reg_value(subkey, "UninstallString")
            finally:
                winreg.CloseKey(subkey)

            if not _is_user_app(display_name, publisher, install_location):
                continue

            name = display_name or subkey_name
            app_id_source = f"{hive_label}\\{full_subkey_path}::{name}::{publisher or ''}"
            app_id = sha256(app_id_source)

            apps[app_id] = {
                "id": app_id,
                "name": name,
                "uninstall_key": f"{hive_label}\\{full_subkey_path}",
                "install_location": install_location or "",
                "display_version": display_version or "",
                "publisher": publisher or "",
                "uninstall_string": uninstall_string or "",
                "hive": hive_label,
                "subkey": full_subkey_path,
            }

        winreg.CloseKey(root)

    return apps


def _safe_walk(root: Path) -> List[Path]:
    paths: List[Path] = []
    if not root.exists() or not root.is_dir():
        return paths
    try:
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            if len(Path(dirpath).parts) > 15:
                dirnames[:] = []
                continue
            dp = Path(dirpath)
            paths.append(dp)
            for fn in filenames:
                paths.append(dp / fn)
    except Exception as e:
        log_core(f"safe_walk error on {root}: {e}")
    return paths


def snapshot_app_artifacts(app_info: Dict[str, Any]) -> Dict[str, List[str]]:
    files: List[str] = []
    folders: List[str] = []
    reg_keys: List[str] = []
    tasks: List[str] = []
    services: List[str] = []

    app_name = app_info.get("name", "").strip()
    app_name_low = app_name.lower()

    install_location = app_info.get("install_location", "").strip()
    if install_location:
        root = Path(install_location)
        if root.exists():
            all_paths = _safe_walk(root)
            for p in all_paths:
                p_str = str(p)
                if p.is_dir():
                    folders.append(p_str)
                else:
                    files.append(p_str)

    extra_roots = [
        Path(os.environ.get("LOCALAPPDATA", "")),
        Path(os.environ.get("APPDATA", "")),
        Path(os.environ.get("PROGRAMDATA", "")),
    ]

    for base in extra_roots:
        if not base.exists():
            continue
        try:
            for child in base.iterdir():
                if app_name_low and app_name_low in child.name.lower():
                    for p in _safe_walk(child):
                        p_str = str(p)
                        if p.is_dir():
                            folders.append(p_str)
                        else:
                            files.append(p_str)
        except Exception as e:
            log_core(f"Error scanning extra root {base}: {e}")

    def _scan_software_root(hive, hive_label):
        base_paths = [
            r"Software",
            r"Software\Microsoft",
        ]
        for base in base_paths:
            try:
                root = winreg.OpenKey(hive, base)
            except OSError:
                continue

            j = 0
            while True:
                try:
                    subname = winreg.EnumKey(root, j)
                    j += 1
                except OSError:
                    break
                if app_name_low and app_name_low not in subname.lower():
                    continue
                reg_keys.append(f"{hive_label}\\{base}\\{subname}")
            winreg.CloseKey(root)

    try:
        _scan_software_root(winreg.HKEY_CURRENT_USER, "HKCU")
    except Exception as e:
        log_core(f"Registry scan HKCU\\Software error: {e}")
    try:
        _scan_software_root(winreg.HKEY_LOCAL_MACHINE, "HKLM")
    except Exception as e:
        log_core(f"Registry scan HKLM\\Software error: {e}")

    files = sorted(set(files))
    folders = sorted(set(folders))
    reg_keys = sorted(set(reg_keys))

    return {
        "files": files,
        "folders": folders,
        "registry": reg_keys,
        "tasks": tasks,
        "services": services,
    }


def _path_exists(path_str: str) -> bool:
    try:
        return Path(path_str).exists()
    except Exception:
        return False


def _registry_key_exists(key_str: str) -> bool:
    parts = key_str.split("\\", 1)
    if len(parts) != 2:
        return False
    hive_label, subkey = parts
    if hive_label.upper() == "HKCU":
        hive = winreg.HKEY_CURRENT_USER
    elif hive_label.upper() == "HKLM":
        hive = winreg.HKEY_LOCAL_MACHINE
    else:
        return False
    try:
        handle = winreg.OpenKey(hive, subkey)
        winreg.CloseKey(handle)
        return True
    except OSError:
        return False


def find_residuals(app_entry: Dict[str, Any]) -> Dict[str, List[str]]:
    all_files: List[str] = []
    all_folders: List[str] = []
    all_reg: List[str] = []
    all_tasks: List[str] = []
    all_services: List[str] = []

    for session in app_entry.get("install_sessions", []):
        all_files.extend(session.get("files", []))
        all_folders.extend(session.get("folders", []))
        all_reg.extend(session.get("registry", []))
        all_tasks.extend(session.get("tasks", []))
        all_services.extend(session.get("services", []))

    ignored = set(app_entry.get("ignored_items", []))

    residual_files = sorted(
        {p for p in all_files if p not in ignored and _path_exists(p)}
    )
    residual_folders = sorted(
        {p for p in all_folders if p not in ignored and _path_exists(p)}
    )
    residual_reg = sorted(
        {k for k in all_reg if k not in ignored and _registry_key_exists(k)}
    )

    residual_tasks = sorted({t for t in all_tasks if t not in ignored})
    residual_services = sorted({s for s in all_services if s not in ignored})

    return {
        "files": residual_files,
        "folders": residual_folders,
        "registry": residual_reg,
        "tasks": residual_tasks,
        "services": residual_services,
    }

# =========================
# GUI: CLEANUP IMPLEMENTATION
# =========================

def delete_registry_key_tree(key_str: str) -> bool:
    parts = key_str.split("\\", 1)
    if len(parts) != 2:
        return False
    hive_label, subkey = parts
    if hive_label.upper() == "HKCU":
        hive = winreg.HKEY_CURRENT_USER
    elif hive_label.upper() == "HKLM":
        hive = winreg.HKEY_LOCAL_MACHINE
    else:
        return False

    try:
        def _delete_tree(h, sk):
            try:
                key = winreg.OpenKey(h, sk, 0, winreg.KEY_READ | winreg.KEY_WRITE)
            except OSError:
                return
            while True:
                try:
                    sub = winreg.EnumKey(key, 0)
                except OSError:
                    break
                _delete_tree(h, sk + "\\" + sub)
            winreg.CloseKey(key)
            try:
                winreg.DeleteKey(h, sk)
            except OSError:
                pass

        _delete_tree(hive, subkey)
        return True
    except Exception as e:
        log_gui(f"Failed to delete registry key {key_str}: {e}")
        return False


def cleanup_residuals(app_id: str, residuals: Dict[str, List[str]], update_ignored: bool = False):
    sense = load_sense_map()
    apps_db = sense.get("apps", {})
    app_entry = apps_db.get(app_id)
    if not app_entry:
        log_gui(f"cleanup_residuals: app_id {app_id} not found in sense_map")
        return

    ignored = set(app_entry.get("ignored_items", []))

    if update_ignored:
        for category in ("files", "folders", "registry", "tasks", "services"):
            for item in residuals.get(category, []):
                ignored.add(item)
        app_entry["ignored_items"] = sorted(ignored)
        apps_db[app_id] = app_entry
        sense["apps"] = apps_db
        save_sense_map(sense)
        return

    for f in residuals.get("files", []):
        try:
            p = Path(f)
            if p.is_file():
                log_gui(f"Deleting file: {f}")
                p.unlink(missing_ok=True)
        except Exception as e:
            log_gui(f"Failed to delete file {f}: {e}")

    folders = sorted(residuals.get("folders", []), key=lambda p: p.count(os.sep), reverse=True)
    for d in folders:
        try:
            p = Path(d)
            if p.exists() and p.is_dir():
                log_gui(f"Deleting folder (tree): {d}")
                shutil.rmtree(p, ignore_errors=True)
        except Exception as e:
            log_gui(f"Failed to delete folder {d}: {e}")

    for rk in residuals.get("registry", []):
        log_gui(f"Deleting registry key: {rk}")
        delete_registry_key_tree(rk)

    still_left = {
        "files": [],
        "folders": [],
        "registry": [],
        "tasks": residuals.get("tasks", []),
        "services": residuals.get("services", []),
    }
    for f in residuals.get("files", []):
        if Path(f).exists():
            still_left["files"].append(f)
    for d in residuals.get("folders", []):
        if Path(d).exists():
            still_left["folders"].append(d)

    for category in ("files", "folders", "registry", "tasks", "services"):
        for item in still_left.get(category, []):
            ignored.add(item)

    app_entry["ignored_items"] = sorted(ignored)
    apps_db[app_id] = app_entry
    sense["apps"] = apps_db
    save_sense_map(sense)

# =========================
# MAIN WINDOW (HIDDEN UNTIL NEEDED)
# =========================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel Sense")
        if APP_ICON_PATH and Path(APP_ICON_PATH).exists():
            self.setWindowIcon(QIcon(str(APP_ICON_PATH)))
            
        self.setFixedSize(600, 400)

        self.current_event: Dict[str, Any] = {}
        self.current_residuals: Dict[str, List[str]] = {}

        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        self.title_label = QLabel("")
        self.title_label.setStyleSheet("QLabel { font-size: 14px; }")
        layout.addWidget(self.title_label)

        self.sub_label = QLabel(
            "These files, folders, and registry entries were created by this application and "
            "still remain after uninstallation.\nYou can safely remove selected items or ignore this warning."
        )
        self.sub_label.setWordWrap(True)
        layout.addWidget(self.sub_label)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        self.lists: Dict[str, QListWidget] = {}
        for label, key in [
            ("Files", "files"),
            ("Folders", "folders"),
            ("Registry", "registry"),
            ("Tasks", "tasks"),
            ("Services", "services"),
        ]:
            lst = QListWidget()
            self.lists[key] = lst
            self.tabs.addTab(lst, label)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch(1)

        self.ignore_btn = QPushButton("Ignore")
        self.ignore_btn.clicked.connect(self.on_ignore)
        btn_layout.addWidget(self.ignore_btn)

        self.clean_selected_btn = QPushButton("Clean selected")
        self.clean_selected_btn.clicked.connect(self.on_clean_selected)
        btn_layout.addWidget(self.clean_selected_btn)

        self.clean_all_btn = QPushButton("Clean all")
        self.clean_all_btn.clicked.connect(self.on_clean_all)
        btn_layout.addWidget(self.clean_all_btn)

        layout.addLayout(btn_layout)
        
        # Styles
        self.setStyleSheet("""
        QWidget#Container {
            background-color: #2d2d2d;
            border-radius: 12px;
        }
        QFrame#Card {
            background-color: #2d2d2d;
            border: 1px solid #000000;
            border-radius: 12px;
        }
        QLabel#TitleLabel {
            font-size: 13px;
            font-weight: 600;
            color: #f9fafb;
        }
        QLabel#HeaderTitleLabel {
            font-size: 16px;
            font-weight: 600;
            color: #f9fafb;
        }
        QLabel#MutedLabel {
            color: #9ca3af;
            font-size: 11px;
        }
        QLabel {
            font-size: 13px;
            color: #e5e7eb;
        }
        QPushButton {
            background-color: #000000;
            color: #f9fafb;
            border-radius: 6px;
            padding: 6px 14px;
            border: transparent;
        }
        QPushButton:hover {
            background-color: #1d1d1d;
        }
        QPushButton:pressed {
            background-color: #ffffff;
            color: #000000;
        }
        QPushButton#CloseButton {
            background-color: transparent;
            border-radius: 4px;
            padding: 0;
            min-width: 0;
        }
        QPushButton#CloseButton:hover {
            background-color: #ef4444;
            color: #ffffff;
        }
        """)

        # Start hidden
        self.hide()
        

    def load_event(self, event: Dict[str, Any]):
        """Populate the window with a leftovers_detected event and show it."""
        self.current_event = event
        self.current_residuals = event.get("residuals", {})
        app_name = event.get("app_name", event.get("app_id", "Unknown app"))

        self.setWindowTitle(f"Sentinel Sense")
        self.title_label.setText(f"Leftover data detected for <b>{app_name}</b>.")

        # Clear and repopulate lists with checkboxes
        for key, lst in self.lists.items():
            lst.clear()
            for item_path in self.current_residuals.get(key, []):
                item = QListWidgetItem(item_path, lst)
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Unchecked)

        # Show main window now
        self.show()
        self.raise_()
        self.activateWindow()

    @property
    def app_id(self) -> str:
        return self.current_event.get("app_id", "")

    def _build_selected_residuals(self, all_or_selected: str) -> Dict[str, List[str]]:
        """Return residuals dict based on checkboxes."""
        if all_or_selected == "all":
            return self.current_residuals

        selected: Dict[str, List[str]] = {k: [] for k in ["files", "folders", "registry", "tasks", "services"]}
        for key, lst in self.lists.items():
            for i in range(lst.count()):
                item = lst.item(i)
                if item.checkState() == Qt.Checked:
                    selected[key].append(item.text())
        return selected

    def on_clean_all(self):
        if not self.app_id:
            return
        confirm = QMessageBox.question(
            self,
            "Confirm cleanup",
            "This will delete all listed files, folders, and registry keys.\n"
            "Are you sure you want to continue?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        residuals_to_clean = self._build_selected_residuals("all")
        try:
            cleanup_residuals(self.app_id, residuals_to_clean, update_ignored=False)
        except Exception:
            log_gui("Error during cleanup (all):\n" + traceback.format_exc())
            QMessageBox.critical(
                self,
                "Cleanup error",
                "An error occurred while cleaning leftovers.\nCheck logs for details.",
            )

        remove_handled_event(self.current_event)
        self.current_event = {}
        self.current_residuals = {}
        self.hide()

    def on_clean_selected(self):
        if not self.app_id:
            return
        residuals_to_clean = self._build_selected_residuals("selected")
        if not any(residuals_to_clean.values()):
            return

        confirm = QMessageBox.question(
            self,
            "Confirm cleanup",
            "This will delete the selected files, folders, and registry keys.\n"
            "Are you sure you want to continue?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        try:
            cleanup_residuals(self.app_id, residuals_to_clean, update_ignored=False)
        except Exception:
            log_gui("Error during cleanup (selected):\n" + traceback.format_exc())
            QMessageBox.critical(
                self,
                "Cleanup error",
                "An error occurred while cleaning leftovers.\nCheck logs for details.",
            )

        remove_handled_event(self.current_event)
        self.current_event = {}
        self.current_residuals = {}
        self.hide()

    def on_ignore(self):
        if not self.app_id:
            return
        try:
            cleanup_residuals(self.app_id, self.current_residuals, update_ignored=True)
        except Exception:
            log_gui("Error updating ignored items:\n" + traceback.format_exc())
            QMessageBox.critical(
                self,
                "Ignore error",
                "An error occurred while updating ignore list.\nCheck logs for details.",
            )

        remove_handled_event(self.current_event)
        self.current_event = {}
        self.current_residuals = {}
        self.hide()

# =========================
# GUI APP (HIDDEN UNTIL EVENT)
# =========================

class SenseGuiApp(QApplication):
    def __init__(self, argv):
        super().__init__(argv)
        self.setApplicationName("Sentinel Sense")
        if APP_ICON_PATH and Path(APP_ICON_PATH).exists():
            self.setWindowIcon(QIcon(str(APP_ICON_PATH)))

        # Keep app alive even if window hidden
        self.setQuitOnLastWindowClosed(False)

        # Create main window but keep hidden until leftovers detected
        self.main_window = MainWindow()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_events)
        self.timer.start(5000)  # every 5s

        self.check_events()

    def check_events(self):
        events = load_json(EVENT_QUEUE_FILE, [])
        if not events:
            return

        for event in events:
            if event.get("type") != "leftovers_detected":
                continue
            # Load event into main window and show it
            self.main_window.load_event(event)
            # Handle only one per tick
            break

# =========================
# CORE MONITOR LOOP (THREAD)
# =========================

def monitor_loop():
    log_core("Starting Sentinel Sense Core monitor")

    sense = load_sense_map()
    apps_db: Dict[str, Any] = sense.get("apps", {})
    if not isinstance(apps_db, dict):
        apps_db = {}
        sense["apps"] = apps_db

    prev_apps = snapshot_installed_apps()
    log_core(f"Initial detected user apps: {len(prev_apps)}")

    for app_id, info in prev_apps.items():
        if app_id not in apps_db:
            apps_db[app_id] = {
                "id": app_id,
                "name": info.get("name", app_id),
                "uninstall_key": info.get("uninstall_key", ""),
                "install_sessions": [],
                "ignored_items": [],
            }
    save_sense_map(sense)

    while True:
        time.sleep(SCAN_INTERVAL)

        current_apps = snapshot_installed_apps()

        # Newly installed apps
        new_ids = set(current_apps) - set(prev_apps)
        if new_ids:
            log_core(f"Detected {len(new_ids)} new app(s)")
        for app_id in new_ids:
            info = current_apps[app_id]
            log_core(f"[INSTALL] {info.get('name')} ({app_id[:8]}...)")
            _safe_toast("Sentinel Sense", f"New app installed: {info.get('name')}")

            artifacts = snapshot_app_artifacts(info)

            entry = apps_db.get(app_id, {
                "id": app_id,
                "name": info.get("name", app_id),
                "uninstall_key": info.get("uninstall_key", ""),
                "install_sessions": [],
                "ignored_items": [],
            })
            entry["install_sessions"].append({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                **artifacts,
            })
            apps_db[app_id] = entry

            sense["apps"] = apps_db
            save_sense_map(sense)

        # Uninstalled apps
        removed_ids = set(prev_apps) - set(current_apps)
        if removed_ids:
            log_core(f"Detected {len(removed_ids)} removed app(s)")
        for app_id in removed_ids:
            app_entry = apps_db.get(app_id)
            if not app_entry:
                continue

            app_name = app_entry.get("name", app_id)
            log_core(f"[UNINSTALL] {app_name} ({app_id[:8]}...)")
            _safe_toast("Sentinel Sense", f"Uninstalled app: {app_name}")

            residuals = find_residuals(app_entry)
            any_residual = any(residuals.values())
            if any_residual:
                log_core(f"Leftovers detected for {app_name}")
                _safe_toast("Sentinel Sense", f"Leftovers detected for {app_name}")
                event = {
                    "type": "leftovers_detected",
                    "app_id": app_id,
                    "app_name": app_name,
                    "residuals": residuals,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
                push_event(event)
            else:
                log_core(f"No leftovers detected for {app_name}")

        prev_apps = current_apps


def start_core_in_thread():
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
    return t

# =========================
# ENTRYPOINT
# =========================

class SentinelSenseController(QObject):
    """Controller to start/stop Sentinel Sense core loop from outside (e.g. SentinelService_v2)."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._core_thread = None
        self._running = False

    def start(self):
        if self._running:
            return
        self._running = True
        self._core_thread = threading.Thread(target=monitor_loop, daemon=True)
        self._core_thread.start()
        log_core("Sentinel Sense controller: started core thread")

    def stop(self):
        # monitor_loop currently runs forever; to support clean stop you need a global flag.
        # For now, we just log; implementing a stoppable loop would require refactoring.
        log_core("Sentinel Sense controller: stop requested (not yet implemented)")
        # Example future extension:
        # global CORE_SHOULD_STOP
        # CORE_SHOULD_STOP = True
        # then join thread here if needed


def Sentinel_Sense_main():
    # Start background core
    start_core_in_thread()

    # Start hidden GUI which only shows the main window when leftovers are found
    app = SenseGuiApp(sys.argv)
    sys.exit(app.exec())

if __name__ == "__main__":
    Sentinel_Sense_main()