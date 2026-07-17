# SentinelWindowsService.py
# Runs all AriaSecurity protection modules as a Windows background service.
# Survives user logout, session lock, and reboot (if set to auto-start).
#
# Installation:
#   python SentinelWindowsService.py install
#   python SentinelWindowsService.py start
#   python SentinelWindowsService.py stop
#   python SentinelWindowsService.py remove
#
# Requires: pip install pywin32
# Must be run as Administrator for install/remove/start/stop.

import sys
import os
import time
import threading
import traceback
import logging

# Ensure the project root is on sys.path when running as a service
_SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_SERVICE_DIR, "..", "..", "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    import win32service
    import win32serviceutil
    import win32event
    import servicemanager
    import win32api
    _WIN32_AVAILABLE = True
except ImportError:
    _WIN32_AVAILABLE = False

from Main_Unit.Service.write_to_log import write_to_log

SERVICE_LOG = "logs/SentinelService.log"

def _log(msg: str, level: str = "INFO"):
    write_to_log(f"[{level}] {msg}", SERVICE_LOG)


# ---------------------------------------------------------------------------
# Core protection runner (independent of Qt — service has no UI)
# ---------------------------------------------------------------------------

class SentinelProtectionCore(threading.Thread):
    """
    Runs the non-Qt protection modules in a background thread:
      - PSDS (kernel SYN blocking)
      - Network protection (NIDS)
      - Exploit protection (WMI)
      - Ransomware protection (file watcher)

    The Qt UI (SentinelService_v2.py) connects separately when the user opens the GUI.
    """

    def __init__(self):
        super().__init__(daemon=True, name="SentinelCore")
        self.running = False
        self._net_service = None
        self._ransom_ctrl = None
        self._exploit_ctrl = None

    def run(self):
        self.running = True
        _log("SentinelProtectionCore starting...")

        # Import here to avoid loading PySide6 inside the service process
        try:
            from Main_Unit.Engine.Service.SentinelServices.Sentinelpsds import start as psds_start
            psds_start()
            _log("PSDS (port-scan defense) started")
        except Exception:
            _log(f"PSDS start failed:\n{traceback.format_exc()}", "WARN")

        try:
            from Main_Unit.Engine.Service.SentinelServices.SentinelNetProtectionNG2 import SentinelAgentService
            self._net_service = SentinelAgentService(interval=1.5)
            self._net_service.start_monitoring()
            _log("Network protection (NIDS) started")
        except Exception:
            _log(f"NIDS start failed:\n{traceback.format_exc()}", "WARN")

        try:
            from Main_Unit.Engine.Service.SentinelServices.SentinelExploitProtection import ExploitProtectionController
            self._exploit_ctrl = ExploitProtectionController(log_file=SERVICE_LOG)
            self._exploit_ctrl.start()
            _log("Exploit protection started")
        except Exception:
            _log(f"Exploit protection start failed:\n{traceback.format_exc()}", "WARN")

        try:
            from Main_Unit.Engine.Service.SentinelServices.SentinelRansomProtection import RansomProtectionController
            self._ransom_ctrl = RansomProtectionController(enable_isolation=True)
            self._ransom_ctrl.start()
            _log("Ransomware protection started")
        except Exception:
            _log(f"Ransomware protection start failed:\n{traceback.format_exc()}", "WARN")

        _log("SentinelProtectionCore fully running")

        # Keep thread alive — modules are daemon threads themselves
        while self.running:
            time.sleep(5)

        self._shutdown()

    def _shutdown(self):
        _log("SentinelProtectionCore shutting down...")

        try:
            from Main_Unit.Engine.Service.SentinelServices.Sentinelpsds import stop as psds_stop
            psds_stop()
        except Exception:
            pass

        if self._net_service:
            try:
                self._net_service.stop_monitoring()
            except Exception:
                pass

        if self._exploit_ctrl:
            try:
                self._exploit_ctrl.stop()
            except Exception:
                pass

        if self._ransom_ctrl:
            try:
                self._ransom_ctrl.stop()
            except Exception:
                pass

        _log("SentinelProtectionCore stopped")

    def stop(self):
        self.running = False


# ---------------------------------------------------------------------------
# Windows Service class
# ---------------------------------------------------------------------------

if _WIN32_AVAILABLE:
    class AriaSecurityService(win32serviceutil.ServiceFramework):
        _svc_name_ = "AriaSecurity"
        _svc_display_name_ = "Aria Security Protection Service"
        _svc_description_ = (
            "AI-powered antivirus, network intrusion detection, ransomware protection, "
            "and exploit defense. Part of the Aria Security security platform."
        )

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._core: SentinelProtectionCore = SentinelProtectionCore()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)
            self._core.stop()
            _log("Service stop requested")

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, '')
            )
            _log("Aria Security Service STARTING")

            self._core.start()

            # Wait for stop signal
            win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)

            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, '')
            )
            _log("Aria Security Service STOPPED")


# ---------------------------------------------------------------------------
# Service auto-start configuration helpers
# ---------------------------------------------------------------------------

def _run_sc(args: list) -> bool:
    """Run sc.exe command and return success."""
    try:
        result = subprocess.run(
            ['sc.exe'] + args,
            capture_output=True, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return result.returncode == 0
    except Exception:
        return False


def set_service_auto_start(service_name: str = "AriaSecurity") -> bool:
    """Configure service to start automatically with Windows."""
    import subprocess
    return _run_sc(['config', service_name, 'start=', 'auto'])


def set_service_recovery(service_name: str = "AriaSecurity") -> bool:
    """Configure service to restart automatically on failure."""
    import subprocess
    return _run_sc([
        'failure', service_name,
        'reset=', '60',
        'actions=', 'restart/5000/restart/5000/restart/10000'
    ])


# ---------------------------------------------------------------------------
# Standalone runner (for testing without installing as a service)
# ---------------------------------------------------------------------------

def run_standalone():
    """Run protection core in foreground without Windows service framework."""
    _log("Running standalone (not as Windows service)")
    core = SentinelProtectionCore()
    core.start()
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        _log("Keyboard interrupt — stopping")
        core.stop()
        core.join(timeout=10)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import subprocess

    if not _WIN32_AVAILABLE:
        print("pywin32 not installed. Running standalone mode.")
        run_standalone()
        sys.exit(0)

    if len(sys.argv) == 1:
        # No arguments — Windows service dispatcher
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(AriaSecurityService)
        servicemanager.StartServiceCtrlDispatcher()
    elif len(sys.argv) >= 2 and sys.argv[1] == 'standalone':
        run_standalone()
    else:
        win32serviceutil.HandleCommandLine(AriaSecurityService)
        # After install, configure auto-start and recovery
        if len(sys.argv) >= 2 and sys.argv[1] == 'install':
            set_service_auto_start()
            set_service_recovery()
            print("Service installed with auto-start and failure recovery.")
