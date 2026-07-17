#!/usr/bin/env python3
"""
Sentinel Sense GUI
PySide6 frontend for leftover detection and cleanup.

- Polls sense_events.json for "leftovers_detected" events.
- For each event, shows a dialog with files/folders/registry/tasks/services.
- Allows user to Clean or Ignore.
- On Clean, deletes artifacts and updates sense_map.json.
- On Ignore, marks items as ignored in sense_map.json so future runs won't nag.
"""

import os
import sys
import json
import shutil
import traceback
from pathlib import Path
from typing import Dict, Any, List

from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QVBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QHBoxLayout,
    QTabWidget,
    QMessageBox,
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QIcon
import winreg

# =========================
# PATHS (keep in sync with sense_core.py)
# =========================

HOME_DIR = Path.home() / ".SentinelSense"
SENSE_MAP_FILE = HOME_DIR / "sense_map.json"
EVENT_QUEUE_FILE = HOME_DIR / "sense_events.json"
LOG_FILE = HOME_DIR / "sense_gui.log"

# Optional icon path (adjust or remove)
APP_ICON_PATH = None  # e.g. Path("path/to/icon.ico")


# =========================
# UTILITIES
# =========================

def log(msg: str):
    from time import strftime
    ts = strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log(f"Failed to load JSON from {path}: {e}")
        return default


def save_json(path: Path, data: Any):
    try:
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception as e:
        log(f"Failed to save JSON to {path}: {e}")


# =========================
# REGISTRY UTIL
# =========================

def delete_registry_key_tree(key_str: str) -> bool:
    """
    Delete registry key subtree.
    key_str format: "HKCU\\Software\\Vendor\\App"
    Returns True on success.
    """
    parts = key_str.split("\\", 1)
    if len(parts) != 2:
        return False
    hive_label, subkey = parts
    hive = None
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
            # Delete subkeys first
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
        log(f"Failed to delete registry key {key_str}: {e}")
        return False


# =========================
# CLEANUP IMPLEMENTATION
# =========================

def cleanup_residuals(app_id: str, residuals: Dict[str, List[str]], update_ignored: bool = False):
    """
    Perform cleanup or ignore items:
      - If update_ignored is False: delete files/folders/registry keys.
      - If update_ignored is True: just add items to ignored_items in sense_map.json.
    """
    sense = load_json(SENSE_MAP_FILE, {"apps": {}})
    apps_db = sense.get("apps", {})
    app_entry = apps_db.get(app_id)
    if not app_entry:
        log(f"cleanup_residuals: app_id {app_id} not found in sense_map")
        return

    ignored = set(app_entry.get("ignored_items", []))

    if update_ignored:
        # Add all residual items to ignored list
        for category in ("files", "folders", "registry", "tasks", "services"):
            for item in residuals.get(category, []):
                ignored.add(item)
        app_entry["ignored_items"] = sorted(ignored)
        apps_db[app_id] = app_entry
        sense["apps"] = apps_db
        save_json(SENSE_MAP_FILE, sense)
        return

    # Actual cleanup
    for f in residuals.get("files", []):
        try:
            if Path(f).is_file():
                log(f"Deleting file: {f}")
                Path(f).unlink(missing_ok=True)
        except Exception as e:
            log(f"Failed to delete file {f}: {e}")

    # Delete folders from deepest to shallowest
    folders = sorted(residuals.get("folders", []), key=lambda p: p.count(os.sep), reverse=True)
    for d in folders:
        try:
            p = Path(d)
            if p.exists() and p.is_dir():
                log(f"Deleting folder (tree): {d}")
                shutil.rmtree(p, ignore_errors=True)
        except Exception as e:
            log(f"Failed to delete folder {d}: {e}")

    # Registry keys
    for rk in residuals.get("registry", []):
        log(f"Deleting registry key: {rk}")
        delete_registry_key_tree(rk)

    # Tasks/services cleanup could be implemented here later

    # After cleanup, re-check and add any still-existing items to ignored to avoid loops
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
    # For registry we can just assume if delete failed, leave it; we won't re-scan here

    for category in ("files", "folders", "registry", "tasks", "services"):
        for item in still_left.get(category, []):
            ignored.add(item)

    app_entry["ignored_items"] = sorted(ignored)
    apps_db[app_id] = app_entry
    sense["apps"] = apps_db
    save_json(SENSE_MAP_FILE, sense)


def remove_handled_event(event_to_remove: Dict[str, Any]):
    events = load_json(EVENT_QUEUE_FILE, [])
    # Remove by matching app_id + timestamp + type
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
# GUI DIALOG
# =========================

class LeftoverDialog(QDialog):
    def __init__(self, event: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.event = event
        self.app_id = event.get("app_id")
        self.app_name = event.get("app_name", self.app_id)
        self.residuals = event.get("residuals", {})

        self.setWindowTitle(f"Leftover files detected – {self.app_name}")
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.resize(700, 450)

        if APP_ICON_PATH and Path(APP_ICON_PATH).exists():
            self.setWindowIcon(QIcon(str(APP_ICON_PATH)))

        layout = QVBoxLayout()
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        title = QLabel(f"Leftover data detected for <b>{self.app_name}</b>.")
        title.setStyleSheet("QLabel { font-size: 14px; }")
        layout.addWidget(title)

        sub = QLabel(
            "These files, folders, and registry entries were created by this application and "
            "still remain after uninstallation.\nYou can safely remove them or ignore this warning."
        )
        sub.setWordWrap(True)
        layout.addWidget(sub)

        tabs = QTabWidget()
        self.lists: Dict[str, QListWidget] = {}

        for label, key in [
            ("Files", "files"),
            ("Folders", "folders"),
            ("Registry", "registry"),
            ("Tasks", "tasks"),
            ("Services", "services"),
        ]:
            lst = QListWidget()
            lst.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
            for item in self.residuals.get(key, []):
                QListWidgetItem(item, lst)
            tabs.addTab(lst, label)
            self.lists[key] = lst

        layout.addWidget(tabs)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch(1)

        self.ignore_btn = QPushButton("Ignore")
        self.ignore_btn.clicked.connect(self.on_ignore)
        btn_layout.addWidget(self.ignore_btn)

        self.clean_btn = QPushButton("Clean")
        self.clean_btn.clicked.connect(self.on_clean)
        btn_layout.addWidget(self.clean_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def on_clean(self):
        confirm = QMessageBox.question(
            self,
            "Confirm cleanup",
            "This will delete the listed files, folders, and registry keys.\n"
            "Are you sure you want to continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        try:
            cleanup_residuals(self.app_id, self.residuals, update_ignored=False)
        except Exception:
            log("Error during cleanup:\n" + traceback.format_exc())
            QMessageBox.critical(
                self,
                "Cleanup error",
                "An error occurred while cleaning leftovers.\nCheck logs for details.",
            )

        remove_handled_event(self.event)
        self.accept()

    def on_ignore(self):
        try:
            cleanup_residuals(self.app_id, self.residuals, update_ignored=True)
        except Exception:
            log("Error updating ignored items:\n" + traceback.format_exc())
            QMessageBox.critical(
                self,
                "Ignore error",
                "An error occurred while updating ignore list.\nCheck logs for details.",
            )

        remove_handled_event(self.event)
        self.accept()


# =========================
# MAIN APP LOOP
# =========================

class SenseGuiApp(QApplication):
    def __init__(self, argv):
        super().__init__(argv)
        # Optional: set application name/icon here
        self.setApplicationName("Sentinel Sense Cleaner")
        if APP_ICON_PATH and Path(APP_ICON_PATH).exists():
            self.setWindowIcon(QIcon(str(APP_ICON_PATH)))

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_events)
        self.timer.start(5000)  # check every 5 seconds

        # Immediately check once
        self.check_events()

    def check_events(self):
        events = load_json(EVENT_QUEUE_FILE, [])
        if not events:
            return

        # Process one event at a time (to keep UX simple)
        for event in events:
            if event.get("type") != "leftovers_detected":
                continue
            dlg = LeftoverDialog(event)
            dlg.exec()
            # After dialog, break; timer will pick up remaining events
            break


def main():
    app = SenseGuiApp(sys.argv)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
