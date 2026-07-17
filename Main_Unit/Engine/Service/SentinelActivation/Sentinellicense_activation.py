# Main_Unit/Service/Sentinellicense_activation.py

import json
from datetime import datetime
from pathlib import Path
import sys
from PySide6.QtWidgets import QDialog, QMessageBox
from PySide6.QtGui import QIcon

from Main_Unit.Engine.Service.SentinelActivation.Sentinellicense_downloader import CONFIG_FILE, ensure_license_config
from Main_Unit.Engine.Service.SentinelActivation.SentinellicenseUI import LicenseDialog
from Main_Unit.Engine.Service.SentinelActivation.Sentinelhwid_lock import ensure_hwid_bound
from Main_Unit.Engine.Service.SentinelActivation.activate_hwid import activate_hwid
from Main_Unit.find_items import find_items
from Main_Unit.Config.Sys_Config import SYSTEM_ICON_PATH, ALL_FEATURES

system_ico = find_items(SYSTEM_ICON_PATH)
ACTIVATED_LOCK_FILE = Path.home() / ".AriaSecurity" / "activated_lock.json"

# ------------------------
# Feature registry
# ------------------------
APP_FEATURES = ALL_FEATURES


def parse_expiry(expiry_str: str) -> datetime:
    return datetime.strptime(expiry_str, "%Y-%m-%d")


def load_license_config():
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def activate_with_key(key: str) -> bool:
    """Try to activate using the given license key."""
    config = load_license_config()
    info = config.get(key)

    if not info:
        return False

    # Check expiry
    try:
        expiry = parse_expiry(info["expiry"])
        if datetime.now() > expiry:
            return False
    except Exception:
        return False

    # Write activated_lock.json
    ACTIVATED_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    ACTIVATED_LOCK_FILE.write_text(
        json.dumps(
            {
                "activated": True,
                "license_key": key,
                "expiry_date": info["expiry"],
                "features": info.get("features", []),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return True


def is_activated_and_valid() -> bool:
    """Check if activated and not expired."""
    if not ACTIVATED_LOCK_FILE.exists():
        return False

    try:
        data = json.loads(ACTIVATED_LOCK_FILE.read_text(encoding="utf-8"))
        if not data.get("activated"):
            return False

        expiry_str = data["expiry_date"]
        expiry = parse_expiry(expiry_str)
        return datetime.now() <= expiry
    except Exception:
        return False


def show_expired_message(app):
    msg = QMessageBox()
    msg.setWindowIcon(QIcon(system_ico))
    msg.setWindowTitle("License Expired")
    msg.setText("Your license has expired. Please contact support.")
    msg.exec()
    sys.exit(1)


def show_device_lock_message(parent=None):
    msg = QMessageBox(parent)
    msg.setWindowTitle("Sentinel Anti-Tamper Device Lock")
    msg.setText(
        "This copy of Sentinel is either not activated on this device "
        "or has been moved from the original machine. \n\n"
        "Please contact developer at: Aria.inc@gmail.com to get new key."
    )
    msg.setIcon(QMessageBox.Icon.Critical)
    msg.setWindowIcon(QIcon(system_ico))
    msg.setStandardButtons(QMessageBox.StandardButton.Ok)
    msg.exec()


def ensure_activated_once(app):
    """
    On first run, show license dialog and activate.
    If already activated and valid, do nothing.
    If license_configuration.json exists, never show Network Error.
    """
    if is_activated_and_valid():
        return

    # Only try to download if config file is missing
    if not CONFIG_FILE.exists():
        if not ensure_license_config():
            msg = QMessageBox()
            msg.setWindowIcon(QIcon(system_ico))
            msg.setWindowTitle("Network Error")
            msg.setText("Cannot download license configuration. Check internet connection.")
            msg.exec()
            sys.exit(1)
            
    if not CONFIG_FILE.exists():
        if not ensure_license_config():
            msg = QMessageBox()
            msg.setWindowIcon(QIcon(system_ico))
            msg.setWindowTitle("Network Error")
            msg.setText("Cannot download license configuration. Check internet connection.")
            msg.exec()
            sys.exit(1)

    # Show license dialog
    dialog = LicenseDialog()
    if dialog.exec() != QDialog.DialogCode.Accepted:
        sys.exit(1)

    key = dialog.get_license_key()
    if not key:
        sys.exit(1)

    if not activate_with_key(key):
        msg = QMessageBox()
        msg.setWindowIcon(QIcon(system_ico))
        msg.setWindowTitle("Invalid License")
        msg.setText("The license key is invalid or expired.")
        msg.exec()
        sys.exit(1)

    # call function instead of subprocess
    activate_hwid()

    # Optional: HWID binding
    if not ensure_hwid_bound():
        show_device_lock_message()
        sys.exit(1)


# ------------------------
# Read active features
# ------------------------
def get_active_features() -> set[str]:
    """
    Return set of enabled feature flags from activated_lock.json.
    If not activated/invalid, returns empty set.
    """
    if not ACTIVATED_LOCK_FILE.exists():
        return set()

    try:
        data = json.loads(ACTIVATED_LOCK_FILE.read_text(encoding="utf-8"))
        if not data.get("activated"):
            return set()

        expiry = parse_expiry(data["expiry_date"])
        if datetime.now() > expiry:
            return set()

        features = data.get("features", [])
        if isinstance(features, list):
            return set(features)
        return set()
    except Exception:
        return set()
