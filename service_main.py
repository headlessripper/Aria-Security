"""Aria Security — Windows service entry point.

Runs the Aria backend headless (Flask + Socket.IO + all protection services) with
NO pywebview window. The UI is a separate process (the Flutter shell, or any
browser) that talks to http://127.0.0.1:8765.

Why a service: protection must run before login, survive the window being
closed, and be elevated once — as LocalSystem — instead of prompting for UAC on
every launch.

Usage (from an elevated shell):
    AriaService.exe install     # register + set auto-start
    AriaService.exe start
    AriaService.exe stop
    AriaService.exe remove
    AriaService.exe debug       # run in the console, Ctrl-C to stop

Running it with no arguments starts it in console mode too, which is handy for
checking a frozen build without touching the SCM.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

# The service must never try to elevate (it already runs as LocalSystem) and must
# never open a window. Set before importing the app.
os.environ.setdefault("SENTINEL_NO_ELEVATE", "1")
os.environ.setdefault("ARIA_RUN_AS_SERVICE", "1")

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

SERVICE_NAME = "AriaSecurity"
SERVICE_DISPLAY = "Aria Security"
SERVICE_DESCRIPTION = (
    "Aria Security protection engine. Serves the Aria UI on 127.0.0.1:8765 and "
    "runs real-time file, network, behavioural and device protection."
)


def _serve(stop_event: threading.Event | None = None) -> None:
    """Boot the backend and block until told to stop."""
    # Bring any desktop-run state into the machine-wide dir on first service run.
    try:
        from Config import paths
        moved = paths.migrate_legacy_data()
        if moved:
            print(f"[AriaService] migrated {len(moved)} item(s) into {paths.data_dir()}")
    except Exception as e:
        print(f"[AriaService] data migration skipped: {e}")

    import SentinelUI_Flask as app_mod

    t = threading.Thread(target=app_mod._start_flask, daemon=True,
                         name="AriaFlask")
    t.start()
    print(f"[AriaService] serving on http://127.0.0.1:{getattr(app_mod, '_PORT', 8765)}")

    if stop_event is None:
        # Console mode: run until interrupted.
        try:
            while t.is_alive():
                time.sleep(1)
        except KeyboardInterrupt:
            print("[AriaService] stopping")
        return

    while not stop_event.is_set():
        stop_event.wait(1)
    print("[AriaService] stop requested")


# ---------------------------------------------------------------------------
# Windows service wrapper (pywin32). Import is optional so the module still
# runs in console mode on a machine without pywin32.
# ---------------------------------------------------------------------------
try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class AriaService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            super().__init__(args)
            self._wait = win32event.CreateEvent(None, 0, 0, None)
            self._stop = threading.Event()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop.set()
            win32event.SetEvent(self._wait)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            try:
                _serve(self._stop)
            except Exception as e:
                servicemanager.LogErrorMsg(f"AriaSecurity service failed: {e}")
                raise

    _HAVE_PYWIN32 = True
except Exception:                                    # pragma: no cover
    AriaService = None                               # type: ignore
    _HAVE_PYWIN32 = False


def main() -> None:
    argv = sys.argv
    if len(argv) == 1:
        # No arguments. Frozen service exes are launched by the SCM with no
        # args, so hand off to the dispatcher when we can; otherwise run in
        # console mode (useful for testing a frozen build directly).
        if _HAVE_PYWIN32 and getattr(sys, "frozen", False):
            try:
                servicemanager.Initialize()
                servicemanager.PrepareToHostSingle(AriaService)
                servicemanager.StartServiceCtrlDispatcher()
                return
            except Exception:
                pass                                 # not started by the SCM
        _serve(None)
        return

    if not _HAVE_PYWIN32:
        print("pywin32 is required for install/start/stop/remove")
        sys.exit(2)
    win32serviceutil.HandleCommandLine(AriaService)


if __name__ == "__main__":
    main()
