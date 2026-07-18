"""
SentinelUI_Flask.py — AriaSecurity Flask + pywebview frontend.

Flask serves the SPA on 127.0.0.1:8765.
Socket.IO streams real-time brain events to the browser.
pywebview opens a native frameless window.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
import traceback
import winreg
from pathlib import Path
from typing import Optional

# ── Ensure project root on path ───────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ── Elevate on Windows ────────────────────────────────────────────────────────
# Set SENTINEL_NO_ELEVATE=1 (or pass --no-elevate) to skip the UAC relaunch —
# useful when already elevated, or for headless/browser testing via run_dev.py.
_SKIP_ELEVATE = (os.environ.get("SENTINEL_NO_ELEVATE") == "1"
                 or "--no-elevate" in sys.argv)
if not _SKIP_ELEVATE:
    try:
        import ctypes
        if os.name == "nt" and not ctypes.windll.shell32.IsUserAnAdmin():
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit(0)
    except Exception:
        pass

# ── Qt context (MUST be before SentinelService / Executioner) ─────────────────
try:
    from PySide6.QtWidgets import QApplication as _QApp
    if not _QApp.instance():
        _qt_app = _QApp(sys.argv[:1])
        _qt_app.setQuitOnLastWindowClosed(False)
except Exception as _qe:
    _qt_app = None

# ── Flask + SocketIO ──────────────────────────────────────────────────────────
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_socketio import SocketIO, emit

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "sentinel-secret-0x1f4a"
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*",
                    logger=False, engineio_logger=False)

# ── Backend imports ───────────────────────────────────────────────────────────
from Main_Unit.Engine.Service.SentinelBrain import get_brain, ThreatEvent

# Preload heavy service in daemon thread
_svc_module: dict = {}

def _preload_service():
    try:
        from Main_Unit.Engine.Service.SentinelService_v2 import SentinelService as _Svc
        _svc_module["cls"] = _Svc
    except Exception as exc:
        _svc_module["error"] = exc

threading.Thread(target=_preload_service, daemon=True, name="ServicePreload").start()

# ── Background service executables (removed) ──────────────────────────────────
# The legacy Plugin/SentinelServices/*.exe helpers were deleted. SentinelSense
# already runs in-process via SentinelService_v2 (SentinelSenseController), so the
# compiled SentinelSenseService.exe was redundant; SentinelTaskAgent.exe is retired.
# Any remaining background workers are started in-process by SentinelService_v2.

# Config
try:
    from Main_Unit.Config.Sys_Config import (
        VERSION, COMPILER_VERSION, BUILD_DATE, APP_NAME,
        BEHAVIORAL_RULES_PATH, APP_DESCRIPTION, DEVELOPER, CONFIG_PATH,
    )
except Exception:
    VERSION = COMPILER_VERSION = BUILD_DATE = APP_NAME = "—"
    BEHAVIORAL_RULES_PATH = ""
    APP_DESCRIPTION = "AI-powered antivirus and system defense platform."
    DEVELOPER = "Samuel Ikenna Great"
    CONFIG_PATH = "Main_Unit/Config.json"

# ── Settings shim ─────────────────────────────────────────────────────────────
_SETTINGS_PATH = Path.home() / ".AriaSecurity" / "settings.json"
_SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
_SETTINGS_LOCK = threading.Lock()

def _load_settings() -> dict:
    try:
        if _SETTINGS_PATH.exists():
            with _SETTINGS_PATH.open("r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def _save_settings(data: dict):
    try:
        with _SETTINGS_PATH.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def _load_config() -> dict:
    try:
        from Main_Unit.find_items import find_items
        p = find_items(CONFIG_PATH)
        if p and os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}

# ── App state ─────────────────────────────────────────────────────────────────
class _AppState:
    def __init__(self):
        self._lock = threading.Lock()
        self.monitoring   = False
        self._svc_instance: Optional[object] = None

    def get_service(self, timeout: float = 30.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if "cls" in _svc_module:
                if self._svc_instance is None:
                    self._svc_instance = _svc_module["cls"]()
                return self._svc_instance
            if "error" in _svc_module:
                raise RuntimeError(f"Service failed to load: {_svc_module['error']}")
            time.sleep(0.2)
        raise TimeoutError("Service not ready after 30 s")

    def snapshot(self) -> dict:
        brain = get_brain()
        events = [e.to_dict() for e in list(brain._threat_log)[-50:]]
        module_statuses = {
            name: status.running
            for name, status in brain._modules.items()
        }
        tc = {cat.name: cnt for cat, cnt in brain._category_counts.items()}
        return {
            "monitoring":       self.monitoring,
            "protection_level": brain._compute_protection_level() if hasattr(brain, '_compute_protection_level') else 0,
            "module_statuses":  module_statuses,
            "threat_counts":    tc,
            "blocked_count":    brain._blocked_count,
            "total_threats":    brain._total_threats,
            "recent_events":    events,
        }

_state = _AppState()

# ── Brain → Socket.IO bridge ──────────────────────────────────────────────────
def _on_brain_threat(event: ThreatEvent):
    try:
        socketio.emit("threat_event", event.to_dict())
    except Exception:
        pass

def _on_level_changed(level: int):
    try:
        socketio.emit("level_changed", {"level": level})
    except Exception:
        pass

def _on_module_changed(name: str, running: bool):
    try:
        socketio.emit("module_changed", {"name": name, "running": running})
    except Exception:
        pass

brain = get_brain()
brain.signals.threat_detected.connect(_on_brain_threat)
brain.signals.protection_level_changed.connect(_on_level_changed)
brain.signals.module_status_changed.connect(_on_module_changed)

# State pusher — emits full snapshot every 2 s
def _state_pusher():
    while True:
        try:
            snap = _state.snapshot()
            socketio.emit("state_update", snap)
        except Exception:
            pass
        time.sleep(2)

threading.Thread(target=_state_pusher, daemon=True, name="StatePusher").start()

# ── Scan history / Scheduler helpers ─────────────────────────────────────────
import Main_Unit.Engine.Service.SentinelScanHistory as _sh
import Main_Unit.Engine.Service.SentinelScheduler   as _sched

# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html",
                           version=VERSION,
                           compiler_version=COMPILER_VERSION,
                           build_date=BUILD_DATE,
                           app_name=APP_NAME)

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)

@app.route("/favicon.ico")
def favicon():
    for cand in (_ROOT / "Icon" / "Sentinel.ico",
                 _ROOT / "Main_Unit" / "Service" / "Icon" / "Icon-100.png"):
        if cand.exists():
            mime = ("image/vnd.microsoft.icon" if cand.suffix == ".ico"
                    else "image/png")
            return send_from_directory(str(cand.parent), cand.name, mimetype=mime)
    return ("", 204)

# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM STATE
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/state")
def api_state():
    return jsonify(_state.snapshot())

# ══════════════════════════════════════════════════════════════════════════════
# PROTECTION TOGGLE
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/protection/toggle", methods=["POST"])
def api_protection_toggle():
    def _worker():
        try:
            svc = _state.get_service()
            if _state.monitoring:
                svc.stop_monitoring()
                _state.monitoring = False
                socketio.emit("protection_toggled", {"monitoring": False})
            else:
                svc.start_monitoring()
                _state.monitoring = True
                socketio.emit("protection_toggled", {"monitoring": True})
        except Exception as exc:
            socketio.emit("error_event", {"message": str(exc)})
    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"status": "starting"})

# ══════════════════════════════════════════════════════════════════════════════
# FILE SCAN
# ══════════════════════════════════════════════════════════════════════════════

_scan_lock    = threading.Lock()
_scan_results: list = []
_scan_running = {"active": False}

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.json or {}
    path = data.get("path", "")
    if not path:
        return jsonify({"error": "no path"}), 400
    if _scan_running["active"]:
        return jsonify({"error": "scan already running"}), 409

    _scan_running["active"] = True
    _scan_results.clear()

    def _do_scan():
        try:
            svc = _state.get_service()
            p = Path(path)
            files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()] if p.is_dir() else []
            total = len(files)
            socketio.emit("scan_progress", {"status": "started", "total": total, "done": 0})
            for i, fp in enumerate(files):
                try:
                    result = svc.scan_file(str(fp))
                    if result:
                        _scan_results.append({"file": str(fp), **result})
                        _sh.record(str(fp), result)
                except Exception:
                    pass
                if (i + 1) % 10 == 0 or (i + 1) == total:
                    socketio.emit("scan_progress", {"status": "running", "total": total, "done": i + 1})
        except Exception as exc:
            socketio.emit("scan_progress", {"status": "error", "message": str(exc)})
        finally:
            _scan_running["active"] = False
            socketio.emit("scan_progress", {"status": "done", "results": _scan_results[:200]})

    threading.Thread(target=_do_scan, daemon=True).start()
    return jsonify({"status": "started"})

@app.route("/api/scan/results")
def api_scan_results():
    return jsonify({"running": _scan_running["active"], "results": _scan_results[:200]})

# ══════════════════════════════════════════════════════════════════════════════
# SCAN HISTORY
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/scan_history")
def api_scan_history():
    limit  = int(request.args.get("limit", 200))
    vf     = request.args.get("verdict", None)
    search = request.args.get("search", None)
    return jsonify(_sh.query(limit=limit, verdict_filter=vf, search=search))

@app.route("/api/scan_history/stats")
def api_scan_history_stats():
    return jsonify(_sh.stats())

@app.route("/api/scan_history", methods=["DELETE"])
def api_scan_history_clear():
    _sh.clear()
    return jsonify({"status": "cleared"})

# ══════════════════════════════════════════════════════════════════════════════
# SCHEDULED SCANS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/scheduled_scans")
def api_scheduled_scans_get():
    return jsonify(_sched.load_schedules())

@app.route("/api/scheduled_scans", methods=["POST"])
def api_scheduled_scans_add():
    d = request.json or {}
    sid = _sched.add_schedule(
        label=d.get("label", d.get("scan_path", "?")),
        scan_path=d.get("scan_path", ""),
        interval_hours=float(d.get("interval_hours", 24)),
    )
    return jsonify({"id": sid})

@app.route("/api/scheduled_scans/<sid>", methods=["DELETE"])
def api_scheduled_scans_del(sid):
    _sched.remove_schedule(sid)
    return jsonify({"status": "removed"})

@app.route("/api/scheduled_scans/<sid>/toggle", methods=["POST"])
def api_scheduled_scans_toggle(sid):
    d = request.json or {}
    _sched.toggle_schedule(sid, bool(d.get("enabled", True)))
    return jsonify({"status": "ok"})

# ══════════════════════════════════════════════════════════════════════════════
# WHITELIST  (3 buckets: files/dirs, IPs, hashes)
# ══════════════════════════════════════════════════════════════════════════════

def _wl():
    from Main_Unit.Engine.Service.SentinelWhitelist import get_whitelist
    return get_whitelist()

@app.route("/api/whitelist")
def api_whitelist_get():
    try:
        wl = _wl()
        return jsonify({
            "files":  wl.list_files(),
            "ips":    wl.list_ips(),
            "hashes": wl.list_hashes(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/whitelist/file", methods=["POST"])
def api_whitelist_add_file():
    path = (request.json or {}).get("path", "").strip()
    if not path:
        return jsonify({"error": "no path"}), 400
    try:
        _wl().add_file(path)
        return jsonify({"status": "added"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/whitelist/dir", methods=["POST"])
def api_whitelist_add_dir():
    path = (request.json or {}).get("path", "").strip()
    if not path:
        return jsonify({"error": "no path"}), 400
    try:
        _wl().add_dir(path)
        return jsonify({"status": "added"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/whitelist/ip", methods=["POST"])
def api_whitelist_add_ip():
    ip = (request.json or {}).get("ip", "").strip()
    if not ip:
        return jsonify({"error": "no ip"}), 400
    try:
        _wl().add_ip(ip)
        return jsonify({"status": "added"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/whitelist/hash", methods=["POST"])
def api_whitelist_add_hash():
    h = (request.json or {}).get("hash", "").strip()
    if not h:
        return jsonify({"error": "no hash"}), 400
    try:
        _wl().add_hash(h)
        return jsonify({"status": "added"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/whitelist/remove", methods=["POST"])
def api_whitelist_remove():
    val = (request.json or {}).get("value", "").strip()
    if not val:
        return jsonify({"error": "no value"}), 400
    try:
        ok = _wl().remove_entry(val)
        return jsonify({"status": "removed" if ok else "not_found"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
# FIREWALL RULES
# ══════════════════════════════════════════════════════════════════════════════

def _fw_list_sentinel_rules() -> list[str]:
    """Return rule names that start with Sentinel_ or PSDS_ from netsh."""
    try:
        r = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
            capture_output=True, text=True, timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        names = []
        for line in r.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Rule Name:"):
                name = stripped.split(":", 1)[1].strip()
                if name.startswith("Sentinel_") or name.startswith("PSDS_"):
                    names.append(name)
        return names
    except Exception:
        return []

@app.route("/api/firewall_rules")
def api_firewall_rules_get():
    try:
        names = _fw_list_sentinel_rules()
        rules = [{"name": n,
                  "type": "Sentinel" if n.startswith("Sentinel") else "PSDS"}
                 for n in names]
        return jsonify(rules)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/firewall_rules/block", methods=["POST"])
def api_firewall_rules_block():
    ip = (request.json or {}).get("ip", "").strip()
    if not ip:
        return jsonify({"error": "no ip"}), 400
    flags = subprocess.CREATE_NO_WINDOW
    errors = []
    for suffix, direction in [("", "in"), ("_OUT", "out")]:
        r = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=Sentinel_BLOCK_{ip}{suffix}",
             f"dir={direction}", "action=block",
             f"remoteip={ip}", "enable=yes", "profile=any"],
            capture_output=True, text=True, timeout=10, creationflags=flags
        )
        if r.returncode != 0:
            errors.append(r.stderr.strip() or r.stdout.strip())
    if errors:
        return jsonify({"status": "partial", "ip": ip, "errors": errors})
    return jsonify({"status": "blocked", "ip": ip})

@app.route("/api/firewall_rules/unblock", methods=["POST"])
def api_firewall_rules_unblock():
    ip = (request.json or {}).get("ip", "").strip()
    if not ip:
        return jsonify({"error": "no ip"}), 400
    flags    = subprocess.CREATE_NO_WINDOW
    deleted  = 0
    # Remove every variant: inbound, outbound, Sentinel and PSDS prefixes
    for name in [f"Sentinel_BLOCK_{ip}", f"Sentinel_BLOCK_{ip}_OUT",
                 f"PSDS_BLOCK_{ip}",     f"PSDS_BLOCK_{ip}_OUT"]:
        r = subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
            capture_output=True, text=True, timeout=10, creationflags=flags
        )
        if r.returncode == 0 and "deleted" in r.stdout.lower():
            deleted += 1
    return jsonify({"status": "unblocked", "ip": ip, "rules_deleted": deleted})

def _fw_clear_prefix(prefix: str) -> tuple[int, list]:
    """Enumerate and delete all rules whose name starts with prefix."""
    flags   = subprocess.CREATE_NO_WINDOW
    names   = [n for n in _fw_list_sentinel_rules() if n.startswith(prefix)]
    deleted = 0
    errors  = []
    for name in names:
        r = subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
            capture_output=True, text=True, timeout=8, creationflags=flags
        )
        if r.returncode == 0:
            deleted += 1
        else:
            errors.append(name)
    return deleted, errors

@app.route("/api/firewall/clear_sentinel", methods=["POST"])
def api_firewall_clear_sentinel():
    try:
        deleted, errors = _fw_clear_prefix("Sentinel_")
        return jsonify({"status": "cleared", "deleted": deleted, "errors": errors})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/firewall/clear_psds", methods=["POST"])
def api_firewall_clear_psds():
    try:
        deleted, errors = _fw_clear_prefix("PSDS_")
        return jsonify({"status": "cleared", "deleted": deleted, "errors": errors})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
# USB ALLOWLIST  (trusted devices)
# ══════════════════════════════════════════════════════════════════════════════

_USB_ALLOW_PATH = Path.home() / ".AriaSecurity" / "usb_allowlist.json"

def _usb_load() -> list:
    try:
        if _USB_ALLOW_PATH.exists():
            return json.loads(_USB_ALLOW_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []

def _usb_save(lst: list):
    _USB_ALLOW_PATH.parent.mkdir(parents=True, exist_ok=True)
    _USB_ALLOW_PATH.write_text(json.dumps(lst, indent=2), encoding="utf-8")

@app.route("/api/usb_allowlist")
def api_usb_allowlist_get():
    return jsonify(_usb_load())

@app.route("/api/usb_allowlist", methods=["POST"])
def api_usb_allowlist_add():
    d = request.json or {}
    lst = _usb_load()
    lst.append({
        "id":     d.get("id", str(time.time())),
        "label":  d.get("label", "Unknown"),
        "serial": d.get("serial", ""),
        "added":  time.strftime("%Y-%m-%d %H:%M"),
    })
    _usb_save(lst)
    return jsonify({"status": "added"})

@app.route("/api/usb_allowlist/<iid>", methods=["DELETE"])
def api_usb_allowlist_del(iid):
    lst = [e for e in _usb_load() if e.get("id") != iid]
    _usb_save(lst)
    return jsonify({"status": "removed"})

@app.route("/api/usb_devices")
def api_usb_devices():
    drives = []
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                letter = chr(ord("A") + i) + ":"
                if ctypes.windll.kernel32.GetDriveTypeW(letter + "\\") == 2:
                    label_buf = ctypes.create_unicode_buffer(261)
                    ctypes.windll.kernel32.GetVolumeInformationW(
                        letter + "\\", label_buf, 261, None, None, None, None, 0
                    )
                    drives.append({"drive": letter, "label": label_buf.value or "USB Drive", "id": letter})
    except Exception:
        pass
    return jsonify(drives)

# ══════════════════════════════════════════════════════════════════════════════
# USB ACCESS CONTROL (registry-based storage enable/disable)
# ══════════════════════════════════════════════════════════════════════════════

def _read_usbstor_state() -> Optional[bool]:
    """Returns True if USB storage enabled, False if disabled, None on error."""
    try:
        import winreg as _wr
        with _wr.OpenKey(
            _wr.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\USBSTOR"
        ) as k:
            val, _ = _wr.QueryValueEx(k, "Start")
            return val == 3   # 3=enabled, 4=disabled
    except Exception:
        return None

@app.route("/api/usb_control/status")
def api_usb_control_status():
    state = _read_usbstor_state()
    return jsonify({"enabled": state, "unknown": state is None})

@app.route("/api/usb_control/toggle", methods=["POST"])
def api_usb_control_toggle():
    d = request.json or {}
    enable = bool(d.get("enable", True))
    reg_val = "3" if enable else "4"
    try:
        subprocess.run(
            ["reg", "add",
             r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR",
             "/v", "Start", "/t", "REG_DWORD", "/d", reg_val, "/f"],
            capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW
        )
        action = "Enable" if enable else "Disable"
        ps_cmd = (
            "Get-PnpDevice -Class USB | "
            "Where-Object { $_.InstanceId -like 'USBSTOR\\*' } | "
        ) + ("Enable-PnpDevice -Confirm:$false" if enable else "Disable-PnpDevice -Confirm:$false")
        subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW
        )
        return jsonify({"status": "ok", "enabled": enable})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
# USB GUARD  (block-until-scanned state + smart port locker)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/usb_guard/state")
def api_usb_guard_state():
    """Per-drive guard state: scanning / threat / clean_pending / trusted."""
    try:
        from Main_Unit.Engine.Service.SentinelUSBGuard import get_state, port_locker_status
        return jsonify({
            "drives":      get_state(),
            "port_locked": port_locker_status() is False,  # False = USBSTOR disabled
            "port_status": port_locker_status(),
        })
    except Exception as e:
        return jsonify({"drives": {}, "error": str(e)})

@app.route("/api/usb_guard/trust", methods=["POST"])
def api_usb_guard_trust():
    """Lift the access ban on a drive AND add it to the trusted allowlist."""
    letter = (request.json or {}).get("letter", "").strip()
    if not letter:
        return jsonify({"error": "no letter"}), 400
    try:
        from Main_Unit.Engine.Service.SentinelUSBGuard import get_guard, USBGuard
        guard = get_guard() or USBGuard(None, None)
        return jsonify(guard.trust_and_unlock(letter))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/usb_guard/unlock", methods=["POST"])
def api_usb_guard_unlock():
    """Lift the access ban WITHOUT trusting (one-time access)."""
    letter = (request.json or {}).get("letter", "").strip()
    if not letter:
        return jsonify({"error": "no letter"}), 400
    try:
        from Main_Unit.Engine.Service.SentinelUSBGuard import get_guard, USBGuard
        guard = get_guard() or USBGuard(None, None)
        return jsonify(guard.unlock(letter))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/usb_guard/port_locker", methods=["POST"])
def api_usb_guard_port_locker():
    """Smart port locker: globally enable/disable all USB mass-storage."""
    enabled = bool((request.json or {}).get("enabled", True))
    try:
        from Main_Unit.Engine.Service.SentinelUSBGuard import set_port_locker
        return jsonify(set_port_locker(enabled))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
# AUTO-QUARANTINE TOGGLE  (controls SentinelExecutor auto-response)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/auto_quarantine")
def api_auto_quarantine_get():
    s = _load_settings()
    return jsonify({"enabled": bool(s.get("auto_quarantine", True))})

@app.route("/api/auto_quarantine", methods=["POST"])
def api_auto_quarantine_set():
    enabled = bool((request.json or {}).get("enabled", True))
    s = _load_settings()
    s["auto_quarantine"] = enabled
    _save_settings(s)
    return jsonify({"status": "ok", "enabled": enabled})

# ══════════════════════════════════════════════════════════════════════════════
# SECURE VAULT  (module-level functions)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/vault")
def api_vault_get():
    try:
        import Main_Unit.Engine.Service.SentinelSecureVault as _sv
        files = _sv.list_files()
        # Normalise for display
        out = []
        for f in files:
            out.append({
                "vault_id":  f.get("vault_id", "?"),
                "name":      f.get("orig_name", "?"),
                "orig_path": f.get("orig_path", ""),
                "size":      f.get("size", 0),
                "added":     f.get("added", 0),
            })
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/vault/add", methods=["POST"])
def api_vault_add():
    d = request.json or {}
    file_path = d.get("file_path", "").strip()
    password  = d.get("password", "")
    if not file_path:
        return jsonify({"error": "no file_path"}), 400
    try:
        import Main_Unit.Engine.Service.SentinelSecureVault as _sv
        vault_id = _sv.add(file_path, password)
        return jsonify({"status": "added", "vault_id": vault_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/vault/extract", methods=["POST"])
def api_vault_extract():
    d        = request.json or {}
    vault_id = d.get("vault_id", "").strip()
    dest     = d.get("dest", "").strip() or str(Path.home() / "Downloads")
    password = d.get("password", "")
    if not vault_id:
        return jsonify({"error": "no vault_id"}), 400
    try:
        import Main_Unit.Engine.Service.SentinelSecureVault as _sv
        # signature: extract(vault_id, dst_dir, password)
        path = _sv.extract(vault_id, dest, password)
        return jsonify({"status": "extracted", "path": path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/vault/<vault_id>", methods=["DELETE"])
def api_vault_delete(vault_id):
    try:
        import Main_Unit.Engine.Service.SentinelSecureVault as _sv
        _sv.delete(vault_id)
        return jsonify({"status": "deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
# QUARANTINE  — pure Python, zero Qt / qtawesome dependency
# ══════════════════════════════════════════════════════════════════════════════

_QUAR_ROOT = Path.home() / ".AriaSecurity" / ".SentinelQuarantine"
_QUAR_META = _QUAR_ROOT / "quarantine_metadata.json"
_QUAR_ROOT.mkdir(parents=True, exist_ok=True)

def _quar_load_meta() -> dict:
    """Read quarantine_metadata.json — returns {} on any error."""
    try:
        if _QUAR_META.exists():
            return json.loads(_QUAR_META.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}

def _quar_save_meta(meta: dict) -> None:
    try:
        _QUAR_META.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

def _quar_find(qid: str) -> tuple:
    """Return (full_qdir_str, data_dict) or (None, None)."""
    meta = _quar_load_meta()
    for full_qdir, data in meta.items():
        if Path(full_qdir).name == qid:
            return full_qdir, data
    return None, None

@app.route("/api/quarantine")
def api_quarantine_list():
    try:
        meta   = _quar_load_meta()
        result = []
        for full_qdir, data in meta.items():
            qdir     = Path(full_qdir)
            qid      = qdir.name
            basename = data.get("basename", "?")
            enc_path = qdir / basename
            key_path = _QUAR_ROOT / f"{qid}.key"
            # skip stale metadata entries whose directory is gone
            if not qdir.exists():
                continue
            sz = enc_path.stat().st_size if enc_path.exists() else 0
            result.append({
                "id":        qid,
                "full_path": str(qdir),
                "basename":  basename,
                "orig_path": data.get("orig_path", ""),
                "size":      sz,
                "has_key":   key_path.exists(),
            })
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/quarantine/<qid>/restore", methods=["POST"])
def api_quarantine_restore(qid):
    import shutil as _sh
    dest_override = (request.json or {}).get("dest", "").strip()

    full_qdir, data = _quar_find(qid)
    if not full_qdir:
        return jsonify({"error": "Quarantine entry not found"}), 404

    qdir     = Path(full_qdir)
    basename = data.get("basename", "?")
    enc_path = qdir / basename
    key_path = _QUAR_ROOT / f"{qid}.key"

    if not enc_path.exists():
        return jsonify({"error": f"Quarantined file missing: {enc_path}"}), 500

    try:
        if dest_override:
            out = Path(dest_override) / basename
        else:
            orig = data.get("orig_path", "")
            out  = Path(orig) if orig else Path.home() / "Downloads" / basename

        out.parent.mkdir(parents=True, exist_ok=True)

        if key_path.exists():
            # Fernet-encrypted quarantine
            from cryptography.fernet import Fernet
            fernet = Fernet(key_path.read_bytes())
            out.write_bytes(fernet.decrypt(enc_path.read_bytes()))
        else:
            # No encryption key — file was stored as-is (or key was lost)
            _sh.copy2(str(enc_path), str(out))

        # Cleanup
        _sh.rmtree(str(qdir), ignore_errors=True)
        if key_path.exists():
            key_path.unlink(missing_ok=True)
        meta = _quar_load_meta()
        meta.pop(full_qdir, None)
        _quar_save_meta(meta)

        return jsonify({"status": "restored", "path": str(out),
                        "note": "" if key_path.exists() else
                        "No .key file found — file restored as-is (may be unencrypted copy)"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/quarantine/<qid>", methods=["DELETE"])
def api_quarantine_delete(qid):
    import shutil as _sh

    full_qdir, _ = _quar_find(qid)
    # also accept a direct directory that exists even without metadata
    if not full_qdir:
        candidate = _QUAR_ROOT / qid
        if candidate.exists():
            full_qdir = str(candidate)
        else:
            return jsonify({"error": "not found"}), 404

    qdir     = Path(full_qdir)
    key_path = _QUAR_ROOT / f"{qid}.key"
    _sh.rmtree(str(qdir), ignore_errors=True)
    if key_path.exists():
        key_path.unlink(missing_ok=True)
    meta = _quar_load_meta()
    meta.pop(full_qdir, None)
    meta.pop(str(qdir), None)
    _quar_save_meta(meta)
    return jsonify({"status": "deleted"})

# ══════════════════════════════════════════════════════════════════════════════
# CONSOLE / SYSTEM LOG
# ══════════════════════════════════════════════════════════════════════════════

_LOG_DIR   = _ROOT / "logs"
_LOG_FILES = [
    "Sentinel.log", "AVBrain.log", "NetPro.log", "Ransom.log",
    "Behavioral.log", "ExploitPro.log", "psds.log",
    "ThreatIntel.log", "ModelUpdater.log", "Sense.log",
]

@app.route("/api/console/logs")
def api_console_logs():
    n      = int(request.args.get("lines", 400))
    module = request.args.get("module", "").lower()
    try:
        all_lines: list[str] = []
        for fname in _LOG_FILES:
            if module and module not in fname.lower():
                continue
            lp = _LOG_DIR / fname
            if not lp.exists():
                continue
            stem = lp.stem
            with lp.open("r", encoding="utf-8", errors="replace") as f:
                chunk = f.readlines()[-200:]
            all_lines.extend(f"[{stem}] {l.rstrip()}" for l in chunk if l.strip())
        return jsonify({"lines": all_lines[-n:]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/console/clear", methods=["POST"])
def api_console_clear():
    module = (request.json or {}).get("module", "").lower()
    cleared = 0
    try:
        for fname in _LOG_FILES:
            if module and module not in fname.lower():
                continue
            lp = _LOG_DIR / fname
            if lp.exists():
                lp.write_text("", encoding="utf-8")
                cleared += 1
        return jsonify({"status": "cleared", "files": cleared})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
# BEHAVIORAL RULES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/behavioral_rules")
def api_behavioral_rules_get():
    try:
        p = Path(str(BEHAVIORAL_RULES_PATH)) if BEHAVIORAL_RULES_PATH else None
        if p and p.exists():
            return app.response_class(p.read_text(encoding="utf-8"), mimetype="text/plain")
        return app.response_class("", mimetype="text/plain")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/behavioral_rules", methods=["POST"])
def api_behavioral_rules_save():
    text = (request.json or {}).get("content", request.get_data(as_text=True))
    try:
        p = Path(str(BEHAVIORAL_RULES_PATH)) if BEHAVIORAL_RULES_PATH else None
        if p:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        return jsonify({"status": "saved"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
# YARA RULES
# ══════════════════════════════════════════════════════════════════════════════

_YARA_USER_PATH = Path.home() / ".AriaSecurity" / "yara_rules"
_YARA_PROJ_DIRS = [
    _ROOT / "Main_Unit" / "Engine" / "Rules",
    _ROOT / "Main_Unit" / "Engine" / "Rules" / "Main_Sys_Rules",
]

@app.route("/api/yara_rules")
def api_yara_rules_get():
    files = []
    seen  = set()
    for d in _YARA_PROJ_DIRS:
        if not d.exists():
            continue
        for ext in ("*.yar", "*.yara", "*.rule", "*.rules"):
            for f in d.glob(ext):
                if f.name not in seen:
                    seen.add(f.name)
                    files.append({"name": f.name, "source": "built-in", "size": f.stat().st_size})
    _YARA_USER_PATH.mkdir(parents=True, exist_ok=True)
    for ext in ("*.yar", "*.yara"):
        for f in _YARA_USER_PATH.glob(ext):
            if f.name not in seen:
                seen.add(f.name)
                files.append({"name": f.name, "source": "imported", "size": f.stat().st_size})
    return jsonify(files)

@app.route("/api/yara_rules/import", methods=["POST"])
def api_yara_rules_import():
    src = Path((request.json or {}).get("source_path", ""))
    try:
        if not src.exists():
            return jsonify({"error": "file not found"}), 404
        _YARA_USER_PATH.mkdir(parents=True, exist_ok=True)
        import shutil
        shutil.copy2(str(src), str(_YARA_USER_PATH / src.name))
        return jsonify({"status": "imported", "name": src.name})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
# VIRUSTOTAL
# ══════════════════════════════════════════════════════════════════════════════

_VT_KEY_PATH = Path.home() / ".AriaSecurity" / "vt_key.json"

def _vt_key() -> str:
    try:
        if _VT_KEY_PATH.exists():
            return json.loads(_VT_KEY_PATH.read_text())["key"]
    except Exception:
        pass
    # Also check Config.json
    try:
        cfg = _load_config()
        return cfg.get("virustotal_api_key", "")
    except Exception:
        return ""

@app.route("/api/virustotal/key", methods=["POST"])
def api_vt_set_key():
    key = (request.json or {}).get("key", "")
    _VT_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    _VT_KEY_PATH.write_text(json.dumps({"key": key}))
    return jsonify({"status": "saved"})

@app.route("/api/virustotal/<query_type>/<path:query>")
def api_vt_query(query_type, query):
    import urllib.request
    key = _vt_key()
    if not key:
        return jsonify({"error": "No VT API key configured"}), 400
    endpoints = {
        "hash":   f"https://www.virustotal.com/api/v3/files/{query}",
        "ip":     f"https://www.virustotal.com/api/v3/ip_addresses/{query}",
        "url":    f"https://www.virustotal.com/api/v3/urls/{query}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{query}",
    }
    url = endpoints.get(query_type)
    if not url:
        return jsonify({"error": "unknown type"}), 400
    try:
        req = urllib.request.Request(url, headers={"x-apikey": key})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
# ABUSEIPDB
# ══════════════════════════════════════════════════════════════════════════════

_ABUSE_KEY_PATH = Path.home() / ".AriaSecurity" / "abuseipdb_key.json"

def _abuse_key() -> str:
    try:
        if _ABUSE_KEY_PATH.exists():
            return json.loads(_ABUSE_KEY_PATH.read_text())["key"]
    except Exception:
        pass
    try:
        cfg = _load_config()
        return cfg.get("abuseipdb_api_key", "")
    except Exception:
        return ""

@app.route("/api/abuseipdb/key", methods=["POST"])
def api_abuse_set_key():
    key = (request.json or {}).get("key", "")
    _ABUSE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    _ABUSE_KEY_PATH.write_text(json.dumps({"key": key}))
    return jsonify({"status": "saved"})

@app.route("/api/abuseipdb/lookup", methods=["POST"])
def api_abuse_lookup():
    ip = (request.json or {}).get("ip", "").strip()
    if not ip:
        return jsonify({"error": "no ip"}), 400
    key = _abuse_key()
    if not key:
        return jsonify({"error": "No AbuseIPDB API key configured"}), 400
    try:
        from Main_Unit.Engine.Service.SentinelThreatIntelligence import lookup_ip_abuseipdb
        data = lookup_ip_abuseipdb(ip, key)
        if not data:
            return jsonify({"error": "No data returned"}), 404
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
# SANDBOX
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/sandbox/detonate", methods=["POST"])
def api_sandbox_detonate():
    file_path = (request.json or {}).get("file_path", "").strip()
    if not file_path or not os.path.isfile(file_path):
        return jsonify({"error": "File not found or invalid path"}), 400

    result_holder = {}

    def _do():
        try:
            from Main_Unit.Engine.Service.SentinelSandbox import detonate
            rep = detonate(file_path)
            result_holder["report"] = {
                "verdict":     rep.verdict,
                "mode":        rep.mode,
                "new_procs":   len(rep.new_processes) if hasattr(rep, "new_processes") else 0,
                "new_files":   len(rep.new_files) if hasattr(rep, "new_files") else 0,
                "indicators":  (rep.suspicious_indicators[:5]
                                if hasattr(rep, "suspicious_indicators") else []),
                "sha256":      getattr(rep, "sha256", ""),
            }
        except Exception as e:
            result_holder["error"] = str(e)

    t = threading.Thread(target=_do, daemon=True)
    t.start()
    t.join(timeout=90)
    if "error" in result_holder:
        return jsonify({"error": result_holder["error"]}), 500
    if "report" not in result_holder:
        return jsonify({"error": "Sandbox timed out"}), 504
    return jsonify(result_holder["report"])

# ══════════════════════════════════════════════════════════════════════════════
# MEMORY SCANNER
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/memory")
def api_memory_get():
    try:
        import psutil
        vm   = psutil.virtual_memory()
        proc = psutil.Process()
        top_procs = []
        for p in psutil.process_iter(["pid", "name", "memory_info"]):
            try:
                mi = p.info.get("memory_info")
                if mi:
                    top_procs.append({"pid": p.info["pid"], "name": p.info.get("name","?"),
                                      "mb": round(mi.rss / 1048576, 1)})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        top_procs.sort(key=lambda x: x["mb"], reverse=True)
        return jsonify({
            "total":       vm.total,
            "used":        vm.used,
            "free":        vm.free,
            "percent":     vm.percent,
            "sentinel_mb": round(proc.memory_info().rss / 1048576, 1),
            "top_procs":   top_procs[:20],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

_mem_scan_running = {"active": False}

@app.route("/api/memory/scan", methods=["POST"])
def api_memory_scan():
    if _mem_scan_running["active"]:
        return jsonify({"error": "scan already running"}), 409
    _mem_scan_running["active"] = True

    def _do():
        import psutil
        results = []
        checked = 0
        try:
            if "cls" not in _svc_module:
                socketio.emit("memory_scan_done", {"error": "Service not loaded yet", "results": []})
                return
            svc = _state._svc_instance
            if svc is None:
                svc = _svc_module["cls"]()
                _state._svc_instance = svc
            scanner = getattr(getattr(svc, "worker", None), "scanner", None)
            if scanner is None:
                socketio.emit("memory_scan_done", {"error": "Scanner unavailable", "results": []})
                return
            procs = list(psutil.process_iter(["pid", "name", "exe"]))
            total = len(procs)
            socketio.emit("memory_scan_progress", {"checked": 0, "total": total, "status": "scanning"})
            for proc in procs:
                try:
                    exe = proc.info.get("exe") or ""
                    if not exe or not os.path.exists(exe):
                        checked += 1
                        continue
                    result = scanner.scan_file(exe)
                    verdict = (result or {}).get("verdict", "CLEAN")
                    if verdict in ("MALWARE", "SUSPICIOUS"):
                        results.append({
                            "pid": proc.info["pid"], "name": proc.info.get("name","?"),
                            "exe": exe, "verdict": verdict,
                            "reasons": (result or {}).get("reasons", [])[:3],
                        })
                        from Main_Unit.Engine.Service.SentinelBrain import ThreatCategory, ThreatSeverity
                        get_brain().emit_event(ThreatEvent(
                            category=ThreatCategory.MALWARE, severity=ThreatSeverity.CRITICAL,
                            title=f"Memory threat: {proc.info.get('name','?')} (PID {proc.info['pid']})",
                            detail=f"{verdict} — {exe}", source_module="MemoryScanner",
                            file_path=exe, pid=proc.info["pid"],
                        ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception:
                    pass
                checked += 1
                if checked % 25 == 0:
                    socketio.emit("memory_scan_progress", {"checked": checked, "total": total, "status": "scanning"})
        except Exception as exc:
            socketio.emit("memory_scan_done", {"error": str(exc), "results": results})
            return
        finally:
            _mem_scan_running["active"] = False
        socketio.emit("memory_scan_done", {"results": results, "checked": checked, "threats": len(results), "status": "done"})

    threading.Thread(target=_do, daemon=True, name="MemScan").start()
    return jsonify({"status": "started"})

@app.route("/api/memory/clean", methods=["POST"])
def api_memory_clean():
    """
    Trim working sets of all accessible processes via SetProcessWorkingSetSize.
    SetProcessWorkingSetSize(h, SIZE_MAX, SIZE_MAX) forces the kernel to trim
    the working set to the minimum allowed for that process.
    """
    import psutil
    import ctypes
    import ctypes.wintypes

    kernel32 = ctypes.windll.kernel32

    # Declare argtypes so ctypes passes the right-sized values
    kernel32.OpenProcess.argtypes          = [ctypes.wintypes.DWORD,
                                               ctypes.wintypes.BOOL,
                                               ctypes.wintypes.DWORD]
    kernel32.OpenProcess.restype           = ctypes.wintypes.HANDLE
    kernel32.SetProcessWorkingSetSize.argtypes = [ctypes.wintypes.HANDLE,
                                                    ctypes.c_size_t,
                                                    ctypes.c_size_t]
    kernel32.SetProcessWorkingSetSize.restype  = ctypes.wintypes.BOOL
    kernel32.CloseHandle.argtypes          = [ctypes.wintypes.HANDLE]
    kernel32.CloseHandle.restype           = ctypes.wintypes.BOOL

    PROCESS_SET_QUOTA         = 0x0100
    PROCESS_QUERY_INFORMATION = 0x0400
    ACCESS = PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION
    SIZE_MAX = ctypes.c_size_t(-1).value  # (size_t)(-1) = trim to minimum

    cleaned = 0
    failed  = 0

    # Trim our own process first (always succeeds)
    kernel32.SetProcessWorkingSetSize(
        kernel32.GetCurrentProcess(), SIZE_MAX, SIZE_MAX
    )

    for proc in psutil.process_iter(["pid"]):
        try:
            pid = proc.info["pid"]
            if pid == 0:
                continue
            h = kernel32.OpenProcess(ACCESS, False, pid)
            if h:
                kernel32.SetProcessWorkingSetSize(h, SIZE_MAX, SIZE_MAX)
                kernel32.CloseHandle(h)
                cleaned += 1
            else:
                failed += 1
        except Exception:
            failed += 1

    return jsonify({"status": "cleaned", "processes": cleaned, "skipped": failed})

# ══════════════════════════════════════════════════════════════════════════════
# PROCESS THREATS (risk scoring)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/process_threats")
def api_process_threats():
    import psutil
    rows = []
    try:
        for proc in psutil.process_iter(["pid", "name", "exe", "ppid"]):
            try:
                info = proc.info
                score = 0
                name  = (info.get("name") or "").lower()
                exe   = info.get("exe") or ""
                if any(x in name for x in ["cryptominer","miner","payload","injector","keylog"]):
                    score += 50
                if info.get("ppid") in [0, 4] and "system" not in name:
                    score += 15
                if exe and not os.path.exists(exe):
                    score += 25
                if "temp" in exe.lower() or "appdata\\local\\temp" in exe.lower():
                    score += 20
                if name.endswith(".exe") and len(name) <= 5:
                    score += 10
                rows.append({"pid": info["pid"], "name": info.get("name","?"),
                             "path": exe, "score": min(score, 100)})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        rows.sort(key=lambda x: x["score"], reverse=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify(rows[:200])

# ══════════════════════════════════════════════════════════════════════════════
# TASK MANAGER (full process list)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/tasks")
def api_tasks():
    import psutil
    rows = []
    try:
        for proc in psutil.process_iter(["pid","name","exe","status","cpu_percent","memory_info"]):
            try:
                mi = proc.info.get("memory_info")
                rows.append({
                    "pid":    proc.info["pid"],
                    "name":   proc.info.get("name","?"),
                    "status": proc.info.get("status","?"),
                    "cpu":    round(proc.info.get("cpu_percent") or 0, 1),
                    "mb":     round(mi.rss / 1048576, 1) if mi else 0,
                    "path":   proc.info.get("exe") or "",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    rows.sort(key=lambda x: x["mb"], reverse=True)
    return jsonify(rows[:300])

@app.route("/api/tasks/<int:pid>/kill", methods=["POST"])
def api_task_kill(pid):
    import psutil
    try:
        p = psutil.Process(pid)
        p.terminate()
        return jsonify({"status": "terminated", "pid": pid})
    except psutil.NoSuchProcess:
        return jsonify({"error": "process not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
# NETWORK MONITOR
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/network/events")
def api_network_events():
    brain = get_brain()
    events = [e.to_dict() for e in brain._threat_log if e.category.name == "NETWORK"]
    return jsonify(events[-100:])

@app.route("/api/network/connections")
def api_network_connections():
    import psutil
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            try:
                proc_name = ""
                if c.pid:
                    try:
                        proc_name = psutil.Process(c.pid).name()
                    except Exception:
                        pass
                conns.append({
                    "pid":     c.pid,
                    "proc":    proc_name,
                    "laddr":   f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—",
                    "raddr":   f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "—",
                    "status":  c.status,
                    "family":  "TCP" if c.type == 1 else "UDP",
                })
            except Exception:
                pass
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify(conns[:200])

# ══════════════════════════════════════════════════════════════════════════════
# GEO BLOCKS
# ══════════════════════════════════════════════════════════════════════════════

_GEO_PATH = Path.home() / ".AriaSecurity" / "geo_blocks.json"

@app.route("/api/geo_blocks")
def api_geo_blocks_get():
    try:
        if _GEO_PATH.exists():
            return jsonify(json.loads(_GEO_PATH.read_text(encoding="utf-8")))
        return jsonify({})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/geo_blocks", methods=["POST"])
def api_geo_blocks_set():
    d = request.json or {}
    try:
        _GEO_PATH.parent.mkdir(parents=True, exist_ok=True)
        _GEO_PATH.write_text(json.dumps(d, indent=2), encoding="utf-8")
        return jsonify({"status": "saved"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
# THREAT INTEL
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/threat_intel/stats")
def api_ti_stats():
    brain = get_brain()
    tc = {cat.name: cnt for cat, cnt in brain._category_counts.items()}
    return jsonify({
        "total":      brain._total_threats,
        "malware":    tc.get("MALWARE", 0),
        "network":    tc.get("NETWORK", 0),
        "behavioral": tc.get("BEHAVIORAL", 0),
        "events":     [e.to_dict() for e in list(brain._threat_log)[-100:]],
    })

# ══════════════════════════════════════════════════════════════════════════════
# STORAGE
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/storage")
def api_storage():
    import psutil
    disks = []
    try:
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
                    "device":     part.device,
                    "mountpoint": part.mountpoint,
                    "fstype":     part.fstype,
                    "total":      usage.total,
                    "used":       usage.used,
                    "free":       usage.free,
                    "percent":    usage.percent,
                })
            except (PermissionError, OSError):
                pass
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify(disks)

# ══════════════════════════════════════════════════════════════════════════════
# SERVICE CONTROL
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/service/status")
def api_service_status():
    startup = "manual"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\AriaSecurity") as k:
            val, _ = winreg.QueryValueEx(k, "Start")
            startup = {2: "automatic", 3: "manual", 4: "disabled"}.get(val, "manual")
    except Exception:
        pass
    return jsonify({"startup": startup, "running": _state.monitoring,
                    "version": VERSION, "build": BUILD_DATE})

@app.route("/api/service/startup", methods=["POST"])
def api_service_set_startup():
    mode = (request.json or {}).get("mode", "manual")
    try:
        subprocess.run(["sc", "config", "AriaSecurity", f"start={mode}"],
                       capture_output=True, check=False)
        return jsonify({"status": "set", "mode": mode})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/service/<action>", methods=["POST"])
def api_service_action(action):
    actions = {
        "start":   ["sc", "start", "AriaSecurity"],
        "stop":    ["sc", "stop",  "AriaSecurity"],
        "restart": ["sc", "stop",  "AriaSecurity"],
    }
    cmd = actions.get(action)
    if not cmd:
        return jsonify({"error": "unknown action"}), 400
    try:
        subprocess.run(cmd, capture_output=True, check=False)
        if action == "restart":
            time.sleep(2)
            subprocess.run(["sc", "start", "AriaSecurity"], capture_output=True, check=False)
        return jsonify({"status": action})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
# PLUGINS
# ══════════════════════════════════════════════════════════════════════════════

# Real, installable Python packages that unlock optional Sentinel capabilities.
# `module` is the import name used to detect whether the package is installed.
_PLUGIN_CATALOG = [
    {"pkg": "yara-python",      "module": "yara",        "name": "YARA Engine",       "desc": "Signature-based malware scanning with YARA rules"},
    {"pkg": "llama-cpp-python", "module": "llama_cpp",   "name": "AVBrain LLM",        "desc": "Local AI reasoning engine (Argus copilot)"},
    {"pkg": "scikit-learn",     "module": "sklearn",     "name": "Anomaly Detection", "desc": "Isolation-Forest behavioural anomaly scoring"},
    {"pkg": "onnxruntime",      "module": "onnxruntime", "name": "ONNX Runtime",      "desc": "Neural-net file classifier inference"},
    {"pkg": "cryptography",     "module": "cryptography","name": "Secure Vault",      "desc": "Fernet encryption for the secure vault"},
    {"pkg": "wmi",              "module": "wmi",         "name": "WMI Bridge",        "desc": "Live USB/disk hardware event monitoring"},
    {"pkg": "folium",           "module": "folium",      "name": "Connection Map",    "desc": "Geographic map of live network connections"},
    {"pkg": "schedule",         "module": "schedule",    "name": "Scan Scheduler",    "desc": "Recurring scheduled directory scans"},
    {"pkg": "requests",         "module": "requests",    "name": "Threat Intel Feeds","desc": "VirusTotal / AbuseIPDB cloud lookups"},
]

def _module_installed(module_name: str) -> bool:
    import importlib.util
    try:
        return importlib.util.find_spec(module_name) is not None
    except Exception:
        return False

def _load_plugins() -> list:
    return [{
        "name":      p["name"],
        "pkg":       p["pkg"],
        "module":    p["module"],
        "desc":      p["desc"],
        "installed": _module_installed(p["module"]),
    } for p in _PLUGIN_CATALOG]

@app.route("/api/plugins")
def api_plugins_get():
    return jsonify(_load_plugins())

@app.route("/api/plugins/<path:pkg>/install", methods=["POST"])
def api_plugins_install(pkg):
    entry = next((p for p in _PLUGIN_CATALOG if p["pkg"] == pkg), None)
    if not entry:
        return jsonify({"error": f"Unknown plugin: {pkg}"}), 400

    def _install():
        try:
            socketio.emit("install_progress", {"pkg": pkg, "status": "installing"})
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--upgrade", pkg],
                capture_output=True, text=True, timeout=600,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            ok = (result.returncode == 0) and _module_installed(entry["module"])
            socketio.emit("install_progress", {
                "pkg": pkg, "status": "done", "success": ok,
                "error": "" if ok else (result.stderr or result.stdout)[-400:],
            })
        except Exception as exc:
            socketio.emit("install_progress", {"pkg": pkg, "status": "error", "error": str(exc)})
    threading.Thread(target=_install, daemon=True).start()
    return jsonify({"status": "started"})

# ══════════════════════════════════════════════════════════════════════════════
# AVBRAIN MODEL  (download the GGUF that powers Argus, then hot-load it)
# ══════════════════════════════════════════════════════════════════════════════

_AVB_MODEL_URL = (
    "https://huggingface.co/bartowski/Phi-3.5-mini-instruct-GGUF"
    "/resolve/main/Phi-3.5-mini-instruct-Q4_K_M.gguf"
)
_AVB_MODEL_DIR  = Path.home() / ".AriaSecurity" / "avbrain"
_AVB_MODEL_FILE = _AVB_MODEL_DIR / "Phi-3.5-mini-instruct-Q4_K_M.gguf"
_AVB_DOWNLOAD   = {"active": False}

@app.route("/api/avbrain/model/status")
def api_avbrain_model_status():
    exists = _AVB_MODEL_FILE.exists()
    llm_ok = False
    try:
        from Main_Unit.Engine.Service.AVBrain import get_avbrain
        llm_ok = get_avbrain().is_llm_available()
    except Exception:
        pass
    return jsonify({
        "model_present": exists,
        "size":          _AVB_MODEL_FILE.stat().st_size if exists else 0,
        "llm_available": llm_ok,
        "downloading":   _AVB_DOWNLOAD["active"],
    })

@app.route("/api/avbrain/model/download", methods=["POST"])
def api_avbrain_model_download():
    if _AVB_DOWNLOAD["active"]:
        return jsonify({"status": "already_downloading"})
    if _AVB_MODEL_FILE.exists():
        threading.Thread(target=_avbrain_reload, daemon=True).start()
        return jsonify({"status": "already_present"})

    _AVB_DOWNLOAD["active"] = True

    def _worker():
        try:
            import requests as _rq
            _AVB_MODEL_DIR.mkdir(parents=True, exist_ok=True)
            tmp = _AVB_MODEL_FILE.with_suffix(".part")
            socketio.emit("avbrain_model_progress", {"status": "connecting", "pct": 0})
            with _rq.get(_AVB_MODEL_URL, stream=True, timeout=60) as r:
                r.raise_for_status()
                total = int(r.headers.get("content-length") or 0)
                done, last = 0, 0.0
                with open(tmp, "wb") as f:
                    for chunk in r.iter_content(chunk_size=1024 * 1024):
                        if not chunk:
                            continue
                        f.write(chunk)
                        done += len(chunk)
                        now = time.time()
                        if now - last > 0.5:
                            last = now
                            pct = int(done * 100 / total) if total else 0
                            socketio.emit("avbrain_model_progress", {
                                "status": "downloading", "pct": pct,
                                "mb": round(done / 1048576, 1),
                                "total_mb": round(total / 1048576, 1) if total else 0,
                            })
            tmp.replace(_AVB_MODEL_FILE)
            socketio.emit("avbrain_model_progress", {"status": "loading", "pct": 100})
            loaded = _avbrain_reload()
            socketio.emit("avbrain_model_progress", {"status": "done", "pct": 100, "loaded": loaded})
        except Exception as exc:
            socketio.emit("avbrain_model_progress", {"status": "error", "error": str(exc)})
        finally:
            _AVB_DOWNLOAD["active"] = False

    threading.Thread(target=_worker, daemon=True, name="AVBrainModelDownload").start()
    return jsonify({"status": "started"})

def _avbrain_reload() -> bool:
    try:
        from Main_Unit.Engine.Service.AVBrain import get_avbrain
        return bool(get_avbrain().reload_model())
    except Exception as exc:
        print(f"[AVBrain] reload after download failed: {exc}")
        return False

# ══════════════════════════════════════════════════════════════════════════════
# YARA RULE EDITOR  (read / validate-and-save / delete user rules)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/yara_rules/content")
def api_yara_rule_content():
    name = request.args.get("name", "")
    if not name or "/" in name or "\\" in name or ".." in name:
        return jsonify({"error": "invalid name"}), 400
    for base in _YARA_PROJ_DIRS + [_YARA_USER_PATH]:
        fp = base / name
        if fp.exists():
            return jsonify({
                "name": name,
                "content": fp.read_text(encoding="utf-8", errors="replace"),
                "editable": base == _YARA_USER_PATH,
            })
    return jsonify({"error": "not found"}), 404

@app.route("/api/yara_rules/save", methods=["POST"])
def api_yara_rule_save():
    d       = request.json or {}
    name    = (d.get("name") or "").strip()
    content = d.get("content", "")
    if not name or "/" in name or "\\" in name or ".." in name:
        return jsonify({"error": "invalid name"}), 400
    if not name.lower().endswith((".yar", ".yara")):
        name += ".yar"
    # Validate by compiling if the yara module is available
    try:
        import yara
        try:
            yara.compile(source=content)
        except yara.Error as ye:
            return jsonify({"error": f"YARA compile error: {ye}"}), 400
    except ImportError:
        pass
    _YARA_USER_PATH.mkdir(parents=True, exist_ok=True)
    (_YARA_USER_PATH / name).write_text(content, encoding="utf-8")
    return jsonify({"status": "saved", "name": name})

@app.route("/api/yara_rules/<path:name>", methods=["DELETE"])
def api_yara_rule_delete(name):
    if "/" in name or "\\" in name or ".." in name:
        return jsonify({"error": "invalid name"}), 400
    fp = _YARA_USER_PATH / name
    if fp.exists():
        fp.unlink()
        return jsonify({"status": "deleted"})
    return jsonify({"error": "not found or built-in (read-only)"}), 404

# ══════════════════════════════════════════════════════════════════════════════
# Argus (AI Copilot)
# ══════════════════════════════════════════════════════════════════════════════

_ARIA_HISTORY: list = []

@app.route("/api/aria/chat", methods=["POST"])
def api_aria_chat():
    msg = (request.json or {}).get("message", "")
    if not msg:
        return jsonify({"error": "empty message"}), 400
    _ARIA_HISTORY.append({"role": "user", "content": msg})

    def _respond():
        reply = None
        # Primary: AVBrain's Argus copilot, backed by the downloaded GGUF model.
        try:
            from Main_Unit.Engine.Service.AVBrain import get_avbrain
            av = get_avbrain()
            if av.is_llm_available():
                reply = av.chat(msg)
        except Exception as exc:
            print(f"[Argus] AVBrain chat unavailable: {exc}")
        # Fallback: deterministic status summary when no model is loaded.
        if not reply:
            snap  = _state.snapshot()
            tc    = snap["threat_counts"]
            total = sum(tc.values())
            reply = (
                f"AriaSecurity is {'active' if snap['monitoring'] else 'inactive'}. "
                f"Protection level: {snap['protection_level']}%. "
                f"Total threats detected: {total}. "
                "AI model not loaded — open AI Copilot and click "
                "“Download Model” to enable full Argus reasoning."
            )
        _ARIA_HISTORY.append({"role": "assistant", "content": reply})
        socketio.emit("aria_reply", {"reply": reply})

    threading.Thread(target=_respond, daemon=True).start()
    return jsonify({"status": "processing"})

@app.route("/api/aria/history")
def api_aria_history():
    return jsonify(_ARIA_HISTORY[-40:])

# ══════════════════════════════════════════════════════════════════════════════
# SETTINGS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/settings")
def api_settings_get():
    return jsonify(_load_settings())

@app.route("/api/settings", methods=["POST"])
def api_settings_save():
    _save_settings(request.json or {})
    return jsonify({"status": "saved"})

# ══════════════════════════════════════════════════════════════════════════════
# ABOUT
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/about")
def api_about():
    import platform
    return jsonify({
        "app_name":         APP_NAME,
        "version":          VERSION,
        "compiler_version": COMPILER_VERSION,
        "build_date":       BUILD_DATE,
        "developer":        DEVELOPER,
        "description":      APP_DESCRIPTION.strip() if APP_DESCRIPTION else "",
        "os":               f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python":           platform.python_version(),
    })

# ══════════════════════════════════════════════════════════════════════════════
# TOOLS — ping / traceroute
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/tools/ping", methods=["POST"])
def api_tools_ping():
    host = (request.json or {}).get("host", "").strip()
    if not host:
        return jsonify({"error": "no host"}), 400
    try:
        r = subprocess.run(
            ["ping", "-n", "4", host],
            capture_output=True, text=True, timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return jsonify({"output": r.stdout or r.stderr, "returncode": r.returncode})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/tools/traceroute", methods=["POST"])
def api_tools_traceroute():
    host = (request.json or {}).get("host", "").strip()
    if not host:
        return jsonify({"error": "no host"}), 400
    try:
        r = subprocess.run(
            ["tracert", "-d", "-h", "20", host],
            capture_output=True, text=True, timeout=60,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return jsonify({"output": r.stdout or r.stderr, "returncode": r.returncode})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
# NET SCOPE  (per-NIC bandwidth snapshot)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/net_scope")
def api_net_scope():
    import psutil
    try:
        ifaces = psutil.net_io_counters(pernic=True, nowrap=True)
        out = {}
        for name, s in ifaces.items():
            out[name] = {
                "bytes_sent":    s.bytes_sent,
                "bytes_recv":    s.bytes_recv,
                "packets_sent":  s.packets_sent,
                "packets_recv":  s.packets_recv,
                "dropin":        getattr(s, "dropin",  0),
                "dropout":       getattr(s, "dropout", 0),
            }
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ══════════════════════════════════════════════════════════════════════════════
# SCHEDULER RUNNER
# ══════════════════════════════════════════════════════════════════════════════

def _on_scan_due(sid: str, scan_path: str):
    def _do():
        try:
            svc = _state.get_service()
            p = Path(scan_path)
            files = [p] if p.is_file() else list(p.rglob("*")) if p.is_dir() else []
            for fp in files:
                try:
                    result = svc.scan_file(str(fp))
                    if result:
                        _sh.record(str(fp), result)
                except Exception:
                    pass
        except Exception:
            pass
    threading.Thread(target=_do, daemon=True).start()
    socketio.emit("scan_started", {"scheduled_id": sid, "path": scan_path})

_scheduler = _sched.SchedulerThread(on_scan_due=_on_scan_due)
_scheduler.start()

# ══════════════════════════════════════════════════════════════════════════════
# SOCKET.IO HANDLERS
# ══════════════════════════════════════════════════════════════════════════════

@socketio.on("connect")
def on_connect():
    emit("state_update", _state.snapshot())

@socketio.on("ping_pong")
def on_ping(data):
    emit("pong", {"ts": time.time()})

# ══════════════════════════════════════════════════════════════════════════════
# PYWEBVIEW LAUNCHER
# ══════════════════════════════════════════════════════════════════════════════

_PORT = 8765

def _start_flask():
    socketio.run(app, host="127.0.0.1", port=_PORT, debug=False,
                 use_reloader=False, allow_unsafe_werkzeug=True)

def main():
    import webview
    flask_thread = threading.Thread(target=_start_flask, daemon=True, name="FlaskServer")
    flask_thread.start()
    time.sleep(0.8)
    window = webview.create_window(
        title    = "AriaSecurity",
        url      = f"http://127.0.0.1:{_PORT}/",
        width    = 1240,
        height   = 760,
        resizable= True,
        frameless= False,
        min_size = (960, 620),
    )
    webview.start(debug=True)

if __name__ == "__main__":
    main()
