# SentinelService_v2.py — Qt-free rewrite (NiceGUI compatible)
# All QThread / QObject / QSettings replaced with threading.Thread / JSON.

import os
import json
import threading
import time
from pathlib import Path
from typing import Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import winreg
from concurrent.futures import ThreadPoolExecutor

from Services.SentinelBrain import get_brain, ThreatEvent, ThreatCategory, ThreatSeverity

# Headless, Qt-free executor: terminates running threats, auto-quarantines, and
# emits brain events. The old Qt `Executioner` needs a running QApplication event
# loop (which never runs under Flask/service), so threats queued into it were
# never processed — that was the "Task N added to queue" dead-end bug.
try:
    from Actions.SentinelExecutor import get_executor as _get_executor
except KeyboardInterrupt:
    raise
except Exception:
    _get_executor = None  # type: ignore

try:
    from Engine.Compiler.SentinelCompiler_v5 import VirusScanner
except KeyboardInterrupt:
    raise
except Exception:
    VirusScanner = None  # type: ignore

try:
    from Services.Protection.SentinelNetProtectionNG2 import NetworkProtection
except KeyboardInterrupt:
    raise
except Exception:
    NetworkProtection = None  # type: ignore

try:
    from Services.Protection.Sentinelpsds import PSDS
except KeyboardInterrupt:
    raise
except Exception:
    PSDS = None  # type: ignore

try:
    from Services.Protection.SentinelRansomProtection import RansomProtection
except KeyboardInterrupt:
    raise
except Exception:
    RansomProtection = None  # type: ignore

try:
    from Services.Protection.SentinelExploitProtection import ExploitProtection
except KeyboardInterrupt:
    raise
except Exception:
    ExploitProtection = None  # type: ignore

try:
    from Services.SentinelBehavioralEngine import BehavioralEngine
except KeyboardInterrupt:
    raise
except Exception:
    BehavioralEngine = None  # type: ignore

try:
    from Services.SentinelThreatIntelligence import ThreatIntelligence
except KeyboardInterrupt:
    raise
except Exception:
    ThreatIntelligence = None  # type: ignore

try:
    from Services.AVBrain import get_avbrain
except KeyboardInterrupt:
    raise
except Exception:
    get_avbrain = None  # type: ignore

try:
    from winotify import Notification, audio
    _WINOTIFY = True
except Exception:
    Notification = audio = None  # type: ignore
    _WINOTIFY = False

try:
    from Config.Sys_Config import SYSTEM_ICON_PATH
except Exception:
    SYSTEM_ICON_PATH = ""

try:
    from Config.Sys_Config import watch_dirs as _RANSOM_WATCH_DIRS
except Exception:
    _RANSOM_WATCH_DIRS = []

try:
    from Interface.find_items import find_items as find_icon
except Exception:
    find_icon = None  # type: ignore

import warnings
warnings.filterwarnings("ignore", message="`sklearn.utils.parallel.delayed should be used with `sklearn.utils.parallel.Parallel`")
warnings.filterwarnings("ignore", category=ResourceWarning)

# ---------------------------------------------------------------------------
# Settings shim — replaces QSettings with a simple JSON file
# ---------------------------------------------------------------------------

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


def _save_settings(data: dict) -> None:
    try:
        with _SETTINGS_PATH.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


class _Settings:
    """Minimal QSettings-compatible shim backed by a JSON file."""
    def __init__(self):
        with _SETTINGS_LOCK:
            self._data = _load_settings()

    def value(self, key: str, default=None):
        with _SETTINGS_LOCK:
            return self._data.get(key, default)

    def setValue(self, key: str, val) -> None:
        with _SETTINGS_LOCK:
            self._data[key] = val
            _save_settings(self._data)

    def sync(self) -> None:
        pass  # writes happen on every setValue


# ---------------------------------------------------------------------------
# USB Drive Monitor
# ---------------------------------------------------------------------------

class USBDriveMonitor:
    """
    Monitors for newly inserted USB drives and auto-scans them.
    Replaces QObject — uses _Signal callbacks from SentinelBrain.
    """
    _USB_SCAN_EXTS = {
        '.exe', '.dll', '.sys', '.scr', '.ocx',
        '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
        '.msi', '.com', '.pif', '.lnk', '.hta',
    }
    _MAX_FILES = 5000

    def __init__(self, scanner, executor):
        self.scanner = scanner
        self.executor = executor
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._known_drives: set = set()
        # Callbacks: connect(fn) / emit(*args)
        from Services.SentinelBrain import _Signal
        self.usb_scanning      = _Signal()   # (drive, name)
        self.usb_scan_complete = _Signal()   # (drive, name, threat_count)
        self.usb_inserted      = _Signal()   # (drive, name)
        self.usb_threat_found  = _Signal()   # (drive, threat_count)

    def start(self):
        if self._running:
            return
        self._running = True
        self._known_drives = self._get_removable_drives()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="USBMonitor")
        self._thread.start()

    def stop(self):
        self._running = False

    @staticmethod
    def _get_removable_drives() -> set:
        import ctypes as _ct
        drives = set()
        bitmask = _ct.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                letter = chr(ord('A') + i) + ":"
                if _ct.windll.kernel32.GetDriveTypeW(letter + "\\") == 2:
                    drives.add(letter)
        return drives

    def _monitor_loop(self):
        try:
            import wmi as _wmi
            c = _wmi.WMI()
            watcher = c.Win32_VolumeChangeEvent.watch_for(EventType=2)
            from Interface.write_to_log import write_to_log
            write_to_log("[USB] WMI drive arrival watcher active", "logs/SystemSentinel.log")
            while self._running:
                try:
                    watcher(timeout_ms=2000)
                    current = self._get_removable_drives()
                    new = current - self._known_drives
                    self._known_drives = current
                    for drive in new:
                        name = self._get_volume_name(drive)
                        self.usb_scanning.emit(drive, name)
                        threading.Thread(target=self._scan_usb, args=(drive, name), daemon=True).start()
                except Exception:
                    pass
        except Exception as e:
            print(f"USB WMI unavailable ({e}), switching to polling")
            self._poll_loop()

    def _poll_loop(self):
        while self._running:
            try:
                current = self._get_removable_drives()
                new = current - self._known_drives
                self._known_drives = current
                for drive in new:
                    name = self._get_volume_name(drive)
                    self.usb_scanning.emit(drive, name)
                    threading.Thread(target=self._scan_usb, args=(drive, name), daemon=True).start()
            except Exception:
                pass
            time.sleep(3)

    @staticmethod
    def _get_volume_name(drive_letter: str) -> str:
        try:
            import ctypes as _ct
            buf = _ct.create_unicode_buffer(256)
            _ct.windll.kernel32.GetVolumeInformationW(drive_letter + "\\", buf, 256, None, None, None, None, 0)
            return buf.value or "USB Drive"
        except Exception:
            return "USB Drive"

    @staticmethod
    def _get_usb_instance_id(drive_letter: str) -> str:
        try:
            ps = (
                "$dl = '" + drive_letter + "'; "
                "$disk = Get-WmiObject -Query \"SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'\" | "
                "ForEach-Object { "
                "  $d = $_; "
                "  $parts = Get-WmiObject -Query \"ASSOCIATORS OF {Win32_DiskDrive.DeviceID='$($d.DeviceID)'} "
                "    WHERE AssocClass=Win32_DiskDriveToDiskPartition\"; "
                "  foreach ($p in $parts) { "
                "    $lds = Get-WmiObject -Query \"ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($p.DeviceID)'} "
                "      WHERE AssocClass=Win32_LogicalDiskToPartition\"; "
                "    foreach ($ld in $lds) { if ($ld.DeviceID -eq $dl) { $d.PNPDeviceID } } "
                "  } "
                "}; $disk | Select-Object -First 1"
            )
            import subprocess as _sp
            r = _sp.run(["powershell", "-NonInteractive", "-NoProfile", "-Command", ps],
                        capture_output=True, text=True, timeout=12)
            return r.stdout.strip()
        except Exception:
            return ""

    def _scan_usb(self, drive_letter: str, device_name: str = "USB Drive"):
        from Interface.write_to_log import write_to_log
        drive_path = drive_letter + "\\"
        if not os.path.isdir(drive_path):
            self.usb_scan_complete.emit(drive_letter, device_name, 0)
            return

        instance_id = ""
        try:
            instance_id = self._get_usb_instance_id(drive_letter)
        except Exception:
            pass

        # ── Block-until-scanned guard: lock the drive, scan, hold for user trust ──
        # When the USB Guard is active it OWNS the response (lock → scan →
        # quarantine → await trust). Fall back to the legacy inline scan only if
        # the guard isn't wired up.
        try:
            from Services.SentinelUSBGuard import get_guard
            guard = get_guard()
            if guard is not None:
                self.usb_scanning.emit(drive_letter, device_name)
                guard.handle_insertion(drive_letter, device_name, instance_id)
                self.usb_scan_complete.emit(drive_letter, device_name, 0)
                return
        except Exception as e:
            write_to_log(f"[USB] guard unavailable, using inline scan: {e}",
                         "logs/SystemSentinel.log")

        try:
            from Interface.Pages.UsbAllowlistPage import is_usb_allowed
            if instance_id and is_usb_allowed(instance_id):
                write_to_log(f"[USB] {drive_letter} is in allowlist — scan skipped", "logs/SystemSentinel.log")
                self.usb_inserted.emit(drive_letter, device_name)
                self.usb_scan_complete.emit(drive_letter, device_name, 0)
                return
        except Exception:
            pass

        write_to_log(f"[USB] Auto-scanning {drive_path}", "logs/SystemSentinel.log")
        files = []
        try:
            for root, _, fnames in os.walk(drive_path):
                for fname in fnames:
                    if Path(fname).suffix.lower() in self._USB_SCAN_EXTS:
                        files.append(os.path.join(root, fname))
                    if len(files) >= self._MAX_FILES:
                        break
                if len(files) >= self._MAX_FILES:
                    break
        except PermissionError:
            pass

        detections = []
        for fpath in files:
            try:
                result = self.scanner.scan_file(fpath)
                verdict = result.get("verdict", "CLEAN")
                if verdict in ("MALWARE", "SUSPICIOUS"):
                    detections.append(fpath)
                    reasons = result.get("reasons", [])
                    write_to_log(f"[USB] THREAT: {fpath} — {verdict}", "logs/SystemSentinel.log")
                    try:
                        brain = get_brain()
                        sev = ThreatSeverity.CRITICAL if verdict == "MALWARE" else ThreatSeverity.HIGH
                        brain.emit_event(ThreatEvent(
                            category=ThreatCategory.USB, severity=sev,
                            title=f"USB threat on {drive_letter}: {os.path.basename(fpath)}",
                            detail=f"{verdict} — {', '.join(reasons[:3])}",
                            source_module="USBMonitor", file_path=fpath,
                        ))
                    except Exception:
                        pass
            except Exception:
                pass

        threat_count = len(detections)
        self.usb_threat_found.emit(drive_letter, threat_count)
        if threat_count == 0:
            self.usb_inserted.emit(drive_letter, device_name)
        self.usb_scan_complete.emit(drive_letter, device_name, threat_count)


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------

def get_user_directories():
    home = os.path.expanduser("~")
    dirs = {
        "Desktop":   os.path.join(home, "Desktop"),
        "Documents": os.path.join(home, "Documents"),
        "Pictures":  os.path.join(home, "Pictures"),
        "Videos":    os.path.join(home, "Videos"),
        "Music":     os.path.join(home, "Music"),
    }
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                  r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
        dirs["Downloads"], _ = winreg.QueryValueEx(reg_key, "{374DE290-123F-4565-9164-39C4925E467B}")
        winreg.CloseKey(reg_key)
    except FileNotFoundError:
        dirs["Downloads"] = os.path.join(home, "Downloads")
    return [d for d in dirs.values() if os.path.exists(d)]


def is_user_file(event):
    src_path = event.src_path.lower()
    system_paths = [
        'windows', 'program files', 'programdata', 'appdata\\local\\temp',
        'appdata\\roaming\\microsoft', '$recycle.bin', 'system volume information',
        '__pycache__', '.venv', 'venv', 'node_modules', '.git',
    ]
    if any(p in src_path for p in system_paths):
        return False
    temp_exts = {'.tmp', '.temp', '.log', '~', '.bak', '.old', '.chk', '.sys', '.pyc', '.pyo'}
    if Path(src_path).suffix.lower() in temp_exts:
        return False
    if Path(src_path).name.lower() in {'thumbs.db', 'desktop.ini', 'autorun.inf'}:
        return False
    return True


# ---------------------------------------------------------------------------
# Anomaly filesystem handler
# ---------------------------------------------------------------------------

class AnomalyHandler(FileSystemEventHandler):
    def __init__(self, settings: _Settings, scanner, executor):
        super().__init__()
        self.settings = settings
        self.scanner = scanner
        self.executor = executor
        from Services.SentinelBrain import _Signal
        self.anomaly_detected = _Signal()  # (dir_path,)

    def on_any_event(self, event):
        if event.is_directory or not is_user_file(event):
            return
        dir_path = os.path.dirname(event.src_path)
        user_dirs = get_user_directories()
        if not any(dir_path.lower().startswith(d.lower()) for d in user_dirs):
            return
        self._log_anomaly(dir_path)
        self.anomaly_detected.emit(dir_path)

    def _log_anomaly(self, dir_path: str):
        try:
            anomaly_list = self.settings.value("anomaly_directory", [])
            if not isinstance(anomaly_list, list):
                anomaly_list = []
            if not any(item.get("file", "") == dir_path for item in anomaly_list):
                anomaly_list.append({"file": dir_path})
                self.settings.setValue("anomaly_directory", anomaly_list)
        except Exception as e:
            print(f"Error updating anomaly list: {e}")


# ---------------------------------------------------------------------------
# Per-module thread wrappers (threading.Thread, no Qt dependency)
# ---------------------------------------------------------------------------

class _ModuleThread:
    """Base: start/stop pattern for all protection module threads."""
    def __init__(self, name: str):
        self._name = name
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name=self._name)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self._do_stop()
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self):
        raise NotImplementedError

    def _do_stop(self):
        pass

    def isRunning(self) -> bool:
        return bool(self._thread and self._thread.is_alive())


class _ServiceHolder:
    """Thin uniform adapter around a new-style BaseService (RansomProtection /
    ExploitProtection / BehavioralEngine).

    BaseService already manages its own worker thread AND self-reports its
    module status to the brain via `set_module_running`, so this holder must
    NOT spawn a second thread or duplicate the brain wiring — it simply exposes
    the same `start()`/`stop()`/`isRunning()` surface the orchestrator uses for
    the legacy `_ModuleThread` wrappers. If the service failed to construct
    (import fell through to None), it degrades to a no-op.
    """

    def __init__(self, service):
        self._svc = service
        self._name = getattr(service, "name", "service") if service else "service"

    def start(self):
        if self._svc is None:
            return
        try:
            self._svc.start()
        except Exception as e:
            print(f"[{self._name}] start error: {e}")

    def stop(self):
        if self._svc is None:
            return
        try:
            self._svc.stop()
        except Exception:
            pass

    def isRunning(self) -> bool:
        if self._svc is None:
            return False
        try:
            return bool(self._svc.is_running())
        except Exception:
            return False


class _UsbThread(_ModuleThread):
    def __init__(self, usb_monitor: USBDriveMonitor):
        super().__init__("USBMonitor")
        self._monitor = usb_monitor

    def _run(self):
        try:
            self._monitor.start()
            get_brain().set_module_running("USBMonitor", True)
        except Exception as e:
            print(f"[USBMonitor] start error: {e}")
            return
        self._stop_event.wait()

    def _do_stop(self):
        try:
            self._monitor.stop()
        except Exception:
            pass
        try:
            get_brain().set_module_running("USBMonitor", False)
        except Exception:
            pass


class _SenseThread(_ModuleThread):
    """
    Runs the Sentinel Sense core monitor (install/uninstall tracking + leftover
    detection) inside the main engine — no separate process, no Qt GUI. The
    headless core loop is started via SentinelSenseController.
    """
    def __init__(self):
        super().__init__("SentinelSense")
        self._controller = None

    def _run(self):
        try:
            from Services.Sense.SentinelSense import SentinelSenseController
            self._controller = SentinelSenseController()
            self._controller.start()
            get_brain().set_module_running("SentinelSense", True)
        except Exception as e:
            print(f"[SentinelSense] start error: {e}")
            return
        self._stop_event.wait()

    def _do_stop(self):
        try:
            if self._controller:
                self._controller.stop()
        except Exception:
            pass
        try:
            get_brain().set_module_running("SentinelSense", False)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# File-scan worker (runs in its own daemon thread)
# ---------------------------------------------------------------------------

class SentinelWorker:
    """File-scan coordinator — watchdog + periodic scanning."""

    def __init__(self, scanner, net_service, executor):
        self.settings      = _Settings()
        self.scanner       = scanner
        self.net_service   = net_service
        self.executor      = executor
        self.observer: Optional[Observer] = None
        self.running       = False
        self.scan_cancelled = False
        self.scan_executor = ThreadPoolExecutor(max_workers=2)
        self._scan_thread: Optional[threading.Thread] = None

        from Services.SentinelBrain import _Signal
        self.display_status_changed = _Signal()  # (str,)
        self.status_changed         = _Signal()  # (str,)
        self.scanning_complete      = _Signal()  # (int,)
        # USB signals forwarded from USBDriveMonitor for backward-compat
        self.usb_scanning           = _Signal()  # (drive, name)
        self.usb_scan_complete      = _Signal()  # (drive, name, count)

    def start_monitoring(self):
        self.status_changed.emit("Sentinel Protection: Starting...")
        self.running = True

        brain = get_brain()
        brain.register_module("FileScanner")
        brain.set_module_running("FileScanner", True)
        brain.signals.status_line_changed.connect(
            lambda line: self.display_status_changed.emit(line)
        )

        event_handler = AnomalyHandler(self.settings, self.scanner, self.executor)
        event_handler.anomaly_detected.connect(self._on_anomaly)
        self.observer = Observer()
        for directory in get_user_directories():
            if os.path.exists(directory):
                self.observer.schedule(event_handler, path=directory, recursive=True)
        self.observer.start()

        # Start periodic scan loop in background thread
        self._scan_thread = threading.Thread(target=self._scan_loop, daemon=True, name="FileScanLoop")
        self._scan_thread.start()

        self.status_changed.emit("Sentinel Protection: Enabled")
        try:
            toast = Notification(app_id="Aria Security", title="Protection Engine",
                                 msg="Active", icon=find_icon(SYSTEM_ICON_PATH), duration="short")
            toast.show()
        except Exception:
            pass

    def _scan_loop(self):
        time.sleep(0.1)
        while self.running:
            self._run_scan_cycle()
            time.sleep(5)

    def _run_scan_cycle(self):
        if not self.running:
            return
        self.scan_cancelled = False
        try:
            anomalies = self.settings.value("anomaly_directory", [])
            if not anomalies:
                self.status_changed.emit("Idle")
                return
            anomaly = anomalies[0]
            dir_path = anomaly["file"]
            running_flag = [self.running]
            cancel_flag  = [self.scan_cancelled]
            if os.path.exists(dir_path):
                self.status_changed.emit(f"Scanning: {os.path.basename(dir_path)}")
                self.scan_executor.submit(self._async_scan_directory, dir_path, running_flag, cancel_flag)
            self.status_changed.emit("Idle")
            anomalies = self.settings.value("anomaly_directory", [])
            if isinstance(anomalies, list) and anomalies:
                anomalies.pop(0)
                self.settings.setValue("anomaly_directory", anomalies)
        except Exception as e:
            print(f"Scan error: {e}")
            self.status_changed.emit("Idle - Error")

    def _async_scan_directory(self, dir_path, running_flag, cancel_flag):
        try:
            scan_count, detections = self.scanner.scan_directory(
                dir_path, executor=self.executor,
                running_flag=running_flag, cancel_flag=cancel_flag,
            )
            self.scanning_complete.emit(len(detections))
            if detections:
                brain = get_brain()
                for threat_path in detections:
                    brain.emit_event(ThreatEvent(
                        category=ThreatCategory.MALWARE, severity=ThreatSeverity.HIGH,
                        title="Malware detected",
                        detail=f"Threat found during directory scan: {threat_path}",
                        source_module="FileScanner", file_path=str(threat_path),
                    ))
        except Exception as e:
            print(f"Async scan error: {e}")
            self.scanning_complete.emit(0)

    def _on_anomaly(self, dir_path: str):
        print(f"ANOMALY: {dir_path}")

    def stop_monitoring(self):
        self.running = False
        self.scan_cancelled = True
        try:
            get_brain().set_module_running("FileScanner", False)
        except Exception:
            pass
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(0.5)
            except Exception:
                pass
            self.observer = None
        self.status_changed.emit("Sentinel Protection: Disabled")
        try:
            toast = Notification(app_id="Aria Security", title="Protection Engine",
                                 msg="Stopped safely", icon=find_icon(SYSTEM_ICON_PATH), duration="short")
            toast.show()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Service façade
# ---------------------------------------------------------------------------

class SentinelService:
    """Primary service façade consumed by the UI layer."""

    def __init__(self):
        self._brain = get_brain()

        _scanner      = VirusScanner(max_workers=4) if VirusScanner else None
        _executor     = _get_executor() if _get_executor else None
        # New-style BaseService protection services. Each manages its own worker
        # thread and reports its own module status to the brain, so they're used
        # directly (behind a thin _ServiceHolder), NOT wrapped in a _ModuleThread.
        # ThreatIntelligence is constructed (and started) BEFORE NetworkProtection
        # so the shared intel store is live when NetworkProtection consumes it via
        # get_intel_store().
        _intel_svc    = ThreatIntelligence() if ThreatIntelligence else None
        _net_svc      = NetworkProtection() if NetworkProtection else None
        _psds_svc     = PSDS() if PSDS else None
        _ransom_svc   = RansomProtection(config={"watch_dirs": list(_RANSOM_WATCH_DIRS)}) if RansomProtection else None
        _exploit_svc  = ExploitProtection() if ExploitProtection else None
        _behav_svc    = BehavioralEngine() if BehavioralEngine else None
        _usb_mon      = USBDriveMonitor(_scanner, _executor)

        # Wire the block-until-scanned USB Guard with the live scanner + executor.
        try:
            from Services.SentinelUSBGuard import init_guard
            init_guard(_scanner, _executor)
        except Exception as e:
            print(f"[USBGuard] init failed: {e}")

        for name in [
            "FileScanner", "NetProtection", "RansomProtection",
            "ExploitProtection", "BehavioralEngine", "ThreatIntelligence",
            "USBMonitor", "PSDS", "SentinelSense",
        ]:
            self._brain.register_module(name)

        self._intel_thread   = _ServiceHolder(_intel_svc)
        self._net_thread     = _ServiceHolder(_net_svc)
        self._psds_thread    = _ServiceHolder(_psds_svc)
        self._ransom_thread  = _ServiceHolder(_ransom_svc)
        self._exploit_thread = _ServiceHolder(_exploit_svc)
        self._behav_thread   = _ServiceHolder(_behav_svc)
        self._usb_thread     = _UsbThread(_usb_mon)
        self._sense_thread   = _SenseThread()

        # ThreatIntelligence starts first so the shared intel store is populated
        # before NetworkProtection begins consuming it.
        self._module_threads = [
            self._intel_thread, self._net_thread, self._psds_thread,
            self._ransom_thread, self._exploit_thread, self._behav_thread,
            self._usb_thread, self._sense_thread,
        ]

        self.worker = SentinelWorker(_scanner, _net_svc, _executor)

        # Forward USB signals from monitor → worker for backward-compat
        _usb_mon.usb_scanning.connect(lambda d, n: self.worker.usb_scanning.emit(d, n))
        _usb_mon.usb_scan_complete.connect(lambda d, n, c: self.worker.usb_scan_complete.emit(d, n, c))

        # Worker callbacks
        self.worker.status_changed.connect(self._on_status_changed)
        self.worker.display_status_changed.connect(self._on_display_status_changed)
        self.worker.scanning_complete.connect(self._on_scan_complete)

    @property
    def brain(self):
        return self._brain

    def start_monitoring(self):
        for t in self._module_threads:
            if not t.isRunning():
                t.start()
        threading.Thread(target=self.worker.start_monitoring, daemon=True, name="SentinelWorker").start()
        try:
            get_avbrain().start()
        except Exception as e:
            print(f"[AVBrain] start error: {e}")

    def stop_monitoring(self):
        try:
            get_avbrain().stop()
        except Exception:
            pass
        for t in self._module_threads:
            t.stop()
        self.worker.stop_monitoring()

    def start_directory_scan(self, path: str):
        if self.worker.running:
            try:
                anomalies = self.worker.settings.value("anomaly_directory", []) or []
                anomalies.append({"file": path})
                self.worker.settings.setValue("anomaly_directory", anomalies)
            except Exception:
                pass

    def get_threat_summary(self) -> dict:
        return {
            "total_threats": self._brain.get_total_threats(),
            "blocked_ips":   self._brain.get_blocked_count(),
            "counts":        self._brain.get_threat_counts(),
            "protection":    self._brain._compute_protection_level(),
            "recent":        [e.to_dict() for e in self._brain.get_recent_events(10)],
            "modules":       [
                {"name": m.name, "running": m.running, "events": m.event_count}
                for m in self._brain.get_module_statuses()
            ],
        }

    # ── Internal callbacks ─────────────────────────────────────────────────────

    def _on_status_changed(self, status: str):
        pass  # NiceGUI UI polls brain directly; no Qt parent to update

    def _on_display_status_changed(self, status: str):
        pass

    def _on_scan_complete(self, threats: int):
        print(f"Scan complete: {threats} threats neutralized")
