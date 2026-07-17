#!/usr/bin/env python3
"""
Sentinel Sense Core
Headless install/uninstall monitor + artifact mapper + leftover detector.

Monitors:
- Uninstall registry keys (user + machine) to detect app install/uninstall
- Files/folders under install locations and AppData/ProgramData
- Related vendor/app registry keys

Stores knowledge base in:
- sense_map.json

Communicates with GUI via:
- sense_events.json (simple event queue)
"""

import os
import sys
import time
import json
import hashlib
import winreg
from pathlib import Path
from typing import Dict, Any, List, Optional

# =========================
# CONFIG
# =========================

HOME_DIR = Path.home() / ".SentinelSense"
HOME_DIR.mkdir(parents=True, exist_ok=True)

SENSE_MAP_FILE = HOME_DIR / "sense_map.json"
EVENT_QUEUE_FILE = HOME_DIR / "sense_events.json"
LOG_FILE = HOME_DIR / "sense_core.log"

SCAN_INTERVAL = 30  # seconds

# Uninstall registry roots
UNINSTALL_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
    # 64-bit view on 64-bit OS
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
]

# Only consider apps whose install location or files fall under these roots
USER_APP_DIRS = [
    os.environ.get("ProgramFiles", r"C:\Program Files"),
    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    os.environ.get("LOCALAPPDATA", r"C:\Users\Default\AppData\Local"),
    os.environ.get("APPDATA", r"C:\Users\Default\AppData\Roaming"),
    os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
]

# Publishers considered "system-ish" to ignore (extend as needed)
SYSTEM_PUBLISHERS = {
    "microsoft corporation",
    "microsoft",
    "intel corporation",
    "advanced micro devices, inc.",
}


# =========================
# UTILITIES
# =========================

def log(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode(errors="ignore")).hexdigest()


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
# SENSE MAP
# =========================

def load_sense_map() -> Dict[str, Any]:
    data = load_json(SENSE_MAP_FILE, {"apps": {}})
    if "apps" not in data:
        data["apps"] = {}
    return data


def save_sense_map(data: Dict[str, Any]):
    save_json(SENSE_MAP_FILE, data)


# =========================
# EVENT QUEUE (GUI IPC)
# =========================

def push_event(event: Dict[str, Any]):
    events = load_json(EVENT_QUEUE_FILE, [])
    events.append(event)
    save_json(EVENT_QUEUE_FILE, events)


# =========================
# UNINSTALL ENUMERATION
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

    # Ignore system publishers
    if publisher and publisher.strip().lower() in SYSTEM_PUBLISHERS:
        return False

    # If no install location, keep but mark as weak
    if not install_location:
        return True

    il = install_location.strip()
    if not il:
        return True

    # Check if install_location is under user-app directories
    il_norm = os.path.normpath(il).lower()
    for base in USER_APP_DIRS:
        if not base:
            continue
        base_norm = os.path.normpath(base).lower()
        if il_norm.startswith(base_norm):
            return True

    # If not under these locations, treat as non-user app
    return False


def snapshot_installed_apps() -> Dict[str, Dict[str, Any]]:
    """
    Returns mapping app_id -> app_info:
      {
        'name': str,
        'uninstall_key': 'HKLM\\...\\Uninstall\\{GUID}',
        'install_location': str or None,
        'display_version': str or None,
        'publisher': str or None,
        'hive': 'HKLM'/'HKCU',
        'subkey': 'Software\\...'
      }
    """
    apps: Dict[str, Dict[str, Any]] = {}

    for hive, path in UNINSTALL_KEYS:
        hive_label = "HKLM"
        if hive == winreg.HKEY_CURRENT_USER:
            hive_label = "HKCU"
        elif hive == winreg.HKEY_LOCAL_MACHINE:
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


# =========================
# ARTIFACT MAPPING
# =========================

def _safe_walk(root: Path) -> List[Path]:
    paths: List[Path] = []
    if not root.exists() or not root.is_dir():
        return paths
    try:
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            # Avoid insane depth in AppData
            if len(Path(dirpath).parts) > 15:
                dirnames[:] = []
                continue
            dp = Path(dirpath)
            paths.append(dp)
            for fn in filenames:
                paths.append(dp / fn)
    except Exception as e:
        log(f"safe_walk error on {root}: {e}")
    return paths


def snapshot_app_artifacts(app_info: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Map probable artifacts for this app.
    Strategy:
      - Start from install_location (if any) and walk that tree.
      - Also scan AppData and ProgramData for paths containing app name.
      - Registry: vendor/app keys under HKCU/HKLM\Software.
      - Tasks/services: left as future extension (empty lists).
    """
    files: List[str] = []
    folders: List[str] = []
    reg_keys: List[str] = []
    tasks: List[str] = []     # TODO: can integrate schtasks listing filtered by app name
    services: List[str] = []  # TODO: can integrate sc query filtered by app name

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

    # Heuristic: search user dirs for vendor/app name
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
                # simple name match
                if app_name_low and app_name_low in child.name.lower():
                    for p in _safe_walk(child):
                        p_str = str(p)
                        if p.is_dir():
                            folders.append(p_str)
                        else:
                            files.append(p_str)
        except Exception as e:
            log(f"Error scanning extra root {base}: {e}")

    # Registry keys: HKCU/HKLM\Software\[Vendor]\[Product] etc.
    # Very heuristic: search HKCU/HKLM\Software for keys containing app name.
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
        log(f"Registry scan HKCU\\Software error: {e}")
    try:
        _scan_software_root(winreg.HKEY_LOCAL_MACHINE, "HKLM")
    except Exception as e:
        log(f"Registry scan HKLM\\Software error: {e}")

    # De-dupe
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


# =========================
# RESIDUAL DETECTION
# =========================

def _path_exists(path_str: str) -> bool:
    try:
        return Path(path_str).exists()
    except Exception:
        return False


def _registry_key_exists(key_str: str) -> bool:
    # key_str format: "HKCU\Software\Vendor\App"
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
        handle = winreg.OpenKey(hive, subkey)
        winreg.CloseKey(handle)
        return True
    except OSError:
        return False


def find_residuals(app_entry: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    From sense_map entry, return artifacts that still exist on system.
    """
    # Merge artifacts from all install_sessions
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

    # Tasks/services existence checks can be added later
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
# MAIN MONITOR LOOP
# =========================

def monitor_loop():
    log("Starting Sentinal Sense Core monitor")

    sense = load_sense_map()
    apps_db: Dict[str, Any] = sense.get("apps", {})
    if not isinstance(apps_db, dict):
        apps_db = {}
        sense["apps"] = apps_db

    prev_apps = snapshot_installed_apps()
    log(f"Initial detected user apps: {len(prev_apps)}")

    # Initialize sense_map with any existing apps (no install_sessions yet)
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

        # Newly installed apps (by uninstall key presence)
        new_ids = set(current_apps) - set(prev_apps)
        if new_ids:
            log(f"Detected {len(new_ids)} new app(s)")
        for app_id in new_ids:
            info = current_apps[app_id]
            log(f"[INSTALL] {info.get('name')} ({app_id[:8]}...)")

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

        # Uninstalled apps (uninstall key removed)
        removed_ids = set(prev_apps) - set(current_apps)
        if removed_ids:
            log(f"Detected {len(removed_ids)} removed app(s)")
        for app_id in removed_ids:
            app_entry = apps_db.get(app_id)
            if not app_entry:
                continue

            app_name = app_entry.get("name", app_id)
            log(f"[UNINSTALL] {app_name} ({app_id[:8]}...)")

            residuals = find_residuals(app_entry)
            any_residual = any(residuals.values())
            if any_residual:
                log(f"Leftovers detected for {app_name}")
                event = {
                    "type": "leftovers_detected",
                    "app_id": app_id,
                    "app_name": app_name,
                    "residuals": residuals,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
                push_event(event)
            else:
                log(f"No leftovers detected for {app_name}")

        prev_apps = current_apps


# =========================
# ENTRYPOINT
# =========================

if __name__ == "__main__":
    try:
        monitor_loop()
    except KeyboardInterrupt:
        log("Sentinel Sense Core monitor stopped by user")
