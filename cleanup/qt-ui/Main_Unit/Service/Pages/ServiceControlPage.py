"""Service Control Page — install/uninstall startup, manage background service EXEs."""
from __future__ import annotations

import os
import sys
import subprocess
import winreg
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QMessageBox, QScrollArea,
)

CARD = "#161b22"; BORDER = "#21262d"; SURFACE = "#0d1117"
ACCENT = "#2f81f7"; GREEN = "#3fb950"; RED = "#f85149"; ORANGE = "#d29922"
TEXT = "#e6edf3"; TEXT_DIM = "#8b949e"; TEXT_MUTED = "#484f58"

_APP_NAME     = "AriaSecurity"
_RUN_KEY      = r"Software\Microsoft\Windows\CurrentVersion\Run"
_TASK_NAME    = "AriaSecurity_Startup"
_PLUGIN_DIRS  = [
    Path("./Plugin"),
    Path("./Plugin/SentinelServices"),
]

_SERVICES = [
    ("SentinelSenseService",    "SentinelSenseService.exe",    "Core threat detection engine"),
    ("SentinelTaskAgent",       "SentinelTaskAgent.exe",       "Background task & alert dispatcher"),
]


# ── helpers ───────────────────────────────────────────────────────────────────

def _find_exe(exe_name: str) -> Path | None:
    for d in _PLUGIN_DIRS:
        p = Path(d) / exe_name
        if p.exists():
            return p.resolve()
    return None


def _is_proc_running(exe_name: str) -> bool:
    try:
        import psutil
        target = exe_name.lower()
        for p in psutil.process_iter(["name"]):
            if (p.info.get("name") or "").lower() == target:
                return True
    except Exception:
        pass
    return False


def _kill_proc(exe_name: str):
    subprocess.run(
        ["taskkill", "/F", "/IM", exe_name],
        capture_output=True, timeout=10,
    )


def _startup_registered() -> bool:
    """Return True if Sentinel is in the HKCU Run key."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as k:
            winreg.QueryValueEx(k, _APP_NAME)
            return True
    except FileNotFoundError:
        return False


def _register_startup():
    """Add Sentinel to HKCU Run key so it starts with Windows.

    In compiled (frozen) mode sys.executable IS the built EXE — use it directly.
    In dev/source mode the EXE has not been built yet, so we look for a
    dist/AriaSecurity.exe next to the script; if it doesn't exist we raise
    a descriptive RuntimeError so the UI can surface it gracefully.
    """
    if getattr(sys, "frozen", False):
        # PyInstaller sets sys.frozen = True; sys.executable is the real EXE.
        cmd = f'"{sys.executable}"'
    else:
        # Source / development mode — try to find a pre-built EXE.
        script_dir = Path(sys.argv[0]).resolve().parent
        candidates = [
            script_dir / "AriaSecurity.exe",
            script_dir / "dist" / "AriaSecurity.exe",
            script_dir / "dist" / "AriaSecurity" / "AriaSecurity.exe",
        ]
        exe_path = next((p for p in candidates if p.exists()), None)
        if exe_path is None:
            raise RuntimeError(
                "AriaSecurity.exe was not found.\n\n"
                "Startup registration requires the compiled application.\n"
                "Build the project with PyInstaller first, then enable startup.\n\n"
                "(During development this feature is unavailable.)"
            )
        cmd = f'"{exe_path}"'
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY,
                        0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, _APP_NAME, 0, winreg.REG_SZ, cmd)


def _unregister_startup():
    """Remove Sentinel from HKCU Run key."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY,
                            0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, _APP_NAME)
    except FileNotFoundError:
        pass


def _sc_query(svc_name: str) -> str:
    """Return the Windows service STATE string, or '' if not installed."""
    try:
        r = subprocess.run(
            ["sc", "query", svc_name],
            capture_output=True, text=True, timeout=8,
        )
        for line in r.stdout.splitlines():
            if "STATE" in line:
                parts = line.split()
                if len(parts) >= 4:
                    return parts[3]   # RUNNING / STOPPED / etc.
        if "FAILED 1060" in r.stdout or "does not exist" in r.stdout:
            return ""
    except Exception:
        pass
    return ""


def _sc_install(svc_name: str, exe_path: str, description: str) -> bool:
    r = subprocess.run([
        "sc", "create", svc_name,
        f"binpath={exe_path}",
        "start=auto",
        "DisplayName=" + svc_name,
    ], capture_output=True, text=True, timeout=15)
    if r.returncode == 0:
        subprocess.run(["sc", "description", svc_name, description],
                       capture_output=True, timeout=8)
    return r.returncode == 0


def _sc_delete(svc_name: str) -> bool:
    subprocess.run(["sc", "stop", svc_name], capture_output=True, timeout=10)
    r = subprocess.run(["sc", "delete", svc_name],
                       capture_output=True, text=True, timeout=10)
    return r.returncode == 0


def _sc_start(svc_name: str) -> bool:
    r = subprocess.run(["sc", "start", svc_name],
                       capture_output=True, text=True, timeout=15)
    return r.returncode == 0


def _sc_stop(svc_name: str) -> bool:
    r = subprocess.run(["sc", "stop", svc_name],
                       capture_output=True, text=True, timeout=15)
    return r.returncode == 0


# ── worker ────────────────────────────────────────────────────────────────────

class _ActionWorker(QThread):
    done = Signal(bool, str)  # success, message

    def __init__(self, fn, *args):
        super().__init__()
        self._fn   = fn
        self._args = args

    def run(self):
        try:
            result = self._fn(*self._args)
            self.done.emit(bool(result), "")
        except Exception as e:
            self.done.emit(False, str(e))


# ── Service row widget ────────────────────────────────────────────────────────

class _ServiceRow(QFrame):
    """One card per service EXE — shows process status + start/stop/install/uninstall."""

    def __init__(self, display: str, exe_name: str, description: str, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self._exe_name   = exe_name
        self._svc_name   = display.replace(" ", "")  # Windows service name
        self._workers: list[_ActionWorker] = []

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        # Status dot
        self._dot = QLabel()
        self._dot.setFixedSize(10, 10)
        layout.addWidget(self._dot)

        # Info
        info = QVBoxLayout()
        info.setSpacing(2)
        name_lbl = QLabel(display)
        name_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self._desc_lbl = QLabel(description)
        self._desc_lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:10px;")
        self._status_lbl = QLabel("Checking…")
        self._status_lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:10px;")
        info.addWidget(name_lbl)
        info.addWidget(self._desc_lbl)
        info.addWidget(self._status_lbl)
        layout.addLayout(info, 1)

        # Buttons
        self._start_btn = self._mk_btn("Start", GREEN)
        self._stop_btn  = self._mk_btn("Stop",  RED)
        self._inst_btn  = self._mk_btn("Install Svc", ACCENT)
        self._uninst_btn= self._mk_btn("Remove Svc", ORANGE)

        self._start_btn.clicked.connect(self._on_start)
        self._stop_btn.clicked.connect(self._on_stop)
        self._inst_btn.clicked.connect(self._on_install)
        self._uninst_btn.clicked.connect(self._on_uninstall)

        for b in [self._start_btn, self._stop_btn, self._inst_btn, self._uninst_btn]:
            layout.addWidget(b)

        self.refresh()

    @staticmethod
    def _mk_btn(text: str, color: str) -> QPushButton:
        b = QPushButton(text)
        b.setFixedSize(90, 28)
        b.setStyleSheet(
            f"QPushButton{{background:{color}22;color:{color};border:1px solid {color}44;"
            f"border-radius:6px;font-size:11px;font-weight:600;}}"
            f"QPushButton:hover{{background:{color}44;}}"
            f"QPushButton:disabled{{background:#21262d;color:#484f58;border-color:#21262d;}}"
        )
        return b

    def refresh(self):
        running    = _is_proc_running(self._exe_name)
        svc_state  = _sc_query(self._svc_name)
        exe_exists = _find_exe(self._exe_name) is not None
        installed  = bool(svc_state)           # non-empty → service is registered

        # Dot colour
        dot_color = GREEN if running else (TEXT_MUTED if not exe_exists else RED)
        self._dot.setStyleSheet(
            f"background:{dot_color};border-radius:5px;"
            f"min-width:10px;max-width:10px;min-height:10px;max-height:10px;"
        )

        # Status text
        parts = []
        parts.append("Running" if running else "Stopped")
        if not exe_exists:
            parts.append("(exe not found)")
        if installed:
            parts.append(f"| WinSvc: {svc_state}")
        self._status_lbl.setText("  ".join(parts))

        self._start_btn.setEnabled(exe_exists and not running)
        self._stop_btn.setEnabled(running)
        self._inst_btn.setEnabled(exe_exists and not installed)
        self._uninst_btn.setEnabled(installed)

    # ── actions ──

    def _on_start(self):
        exe_path = _find_exe(self._exe_name)
        if not exe_path:
            return
        self._start_btn.setEnabled(False)
        try:
            os.startfile(str(exe_path))
        except Exception as e:
            QMessageBox.warning(self.window(), "Error", str(e))
        QTimer.singleShot(1500, self.refresh)

    def _on_stop(self):
        self._stop_btn.setEnabled(False)
        w = _ActionWorker(_kill_proc, self._exe_name)
        w.done.connect(lambda ok, _: (self.refresh(), self._workers.remove(w)))
        self._workers.append(w)
        w.start()

    def _on_install(self):
        exe_path = _find_exe(self._exe_name)
        if not exe_path:
            return
        reply = QMessageBox.question(
            self.window(), "Install Windows Service",
            f"Register '{self._svc_name}' as a Windows service?\n"
            f"Requires administrator privileges.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self._inst_btn.setEnabled(False)
        w = _ActionWorker(_sc_install, self._svc_name, str(exe_path),
                          self._desc_lbl.text())
        w.done.connect(lambda ok, msg: self._on_action_done(ok, msg, "Service installed." if ok else f"Failed: {msg}"))
        self._workers.append(w)
        w.start()

    def _on_uninstall(self):
        reply = QMessageBox.question(
            self.window(), "Remove Windows Service",
            f"Stop and remove '{self._svc_name}' from Windows services?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self._uninst_btn.setEnabled(False)
        w = _ActionWorker(_sc_delete, self._svc_name)
        w.done.connect(lambda ok, msg: self._on_action_done(ok, msg, "Service removed." if ok else f"Failed: {msg}"))
        self._workers.append(w)
        w.start()

    def _on_action_done(self, ok: bool, msg: str, display: str):
        self.refresh()
        if not ok and msg:
            QMessageBox.warning(self.window(), "Service Error", msg)


# ── Page ─────────────────────────────────────────────────────────────────────

class ServiceControlPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("Service Control")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        hdr.addWidget(title)
        hdr.addStretch()
        refresh_btn = QPushButton("Refresh All")
        refresh_btn.setStyleSheet(
            f"QPushButton{{background:{CARD};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:8px;padding:6px 14px;font-size:12px;}}"
            f"QPushButton:hover{{background:#1c2128;}}"
        )
        refresh_btn.clicked.connect(self._refresh_all)
        hdr.addWidget(refresh_btn)
        root.addLayout(hdr)

        # ── Windows Startup section ──────────────────────────────────────────
        startup_lbl = QLabel("WINDOWS STARTUP")
        startup_lbl.setStyleSheet(
            f"font-size:10px;font-weight:700;color:{TEXT_MUTED};"
            f"letter-spacing:1px;"
        )
        root.addWidget(startup_lbl)

        self._startup_card = QFrame()
        self._startup_card.setObjectName("Card")
        sc = QHBoxLayout(self._startup_card)
        sc.setContentsMargins(16, 14, 16, 14)
        sc.setSpacing(14)

        self._startup_dot = QLabel()
        self._startup_dot.setFixedSize(10, 10)
        sc.addWidget(self._startup_dot)

        st_info = QVBoxLayout()
        st_info.setSpacing(2)
        st_name = QLabel("AriaSecurity — Start with Windows")
        st_name.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self._startup_status = QLabel("")
        self._startup_status.setStyleSheet(f"color:{TEXT_DIM};font-size:10px;")
        st_info.addWidget(st_name)
        st_info.addWidget(self._startup_status)
        sc.addLayout(st_info, 1)

        self._install_startup_btn = QPushButton("Enable Startup")
        self._install_startup_btn.setFixedSize(120, 30)
        self._install_startup_btn.setStyleSheet(
            f"QPushButton{{background:{GREEN}22;color:{GREEN};border:1px solid {GREEN}44;"
            f"border-radius:6px;font-size:11px;font-weight:600;}}"
            f"QPushButton:hover{{background:{GREEN}44;}}"
        )
        self._install_startup_btn.clicked.connect(self._enable_startup)

        self._remove_startup_btn = QPushButton("Disable Startup")
        self._remove_startup_btn.setFixedSize(120, 30)
        self._remove_startup_btn.setStyleSheet(
            f"QPushButton{{background:{RED}1a;color:{RED};border:1px solid {RED}33;"
            f"border-radius:6px;font-size:11px;font-weight:600;}}"
            f"QPushButton:hover{{background:{RED}33;}}"
        )
        self._remove_startup_btn.clicked.connect(self._disable_startup)

        sc.addWidget(self._install_startup_btn)
        sc.addWidget(self._remove_startup_btn)
        root.addWidget(self._startup_card)

        # ── Background Services section ──────────────────────────────────────
        svc_lbl = QLabel("BACKGROUND SERVICE PROCESSES")
        svc_lbl.setStyleSheet(
            f"font-size:10px;font-weight:700;color:{TEXT_MUTED};"
            f"letter-spacing:1px;"
        )
        root.addWidget(svc_lbl)

        hint = QLabel(
            "Each service runs as a separate process. "
            "'Install Svc' registers it as a Windows Service (requires admin). "
            "Start/Stop controls the process directly."
        )
        hint.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        hint.setWordWrap(True)
        root.addWidget(hint)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        svc_widget = QWidget()
        svc_widget.setStyleSheet("background:transparent;")
        self._svc_layout = QVBoxLayout(svc_widget)
        self._svc_layout.setContentsMargins(0, 0, 0, 0)
        self._svc_layout.setSpacing(8)
        self._svc_layout.addStretch()
        scroll.setWidget(svc_widget)
        root.addWidget(scroll, 1)

        self._rows: list[_ServiceRow] = []
        self._build_rows()
        self._refresh_startup()

        # Auto-refresh every 5 s
        self._timer = QTimer(self)
        self._timer.setInterval(5000)
        self._timer.timeout.connect(self._refresh_all)
        self._timer.start()

    def _build_rows(self):
        while self._svc_layout.count() > 1:
            item = self._svc_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._rows.clear()
        for display, exe_name, desc in _SERVICES:
            row = _ServiceRow(display, exe_name, desc)
            self._svc_layout.insertWidget(self._svc_layout.count() - 1, row)
            self._rows.append(row)

    def _refresh_all(self):
        self._refresh_startup()
        for row in self._rows:
            row.refresh()

    def _refresh_startup(self):
        registered  = _startup_registered()
        is_frozen   = getattr(sys, "frozen", False)
        dot_color   = GREEN if registered else TEXT_MUTED
        self._startup_dot.setStyleSheet(
            f"background:{dot_color};border-radius:5px;"
            f"min-width:10px;max-width:10px;min-height:10px;max-height:10px;"
        )
        if registered:
            status = "Registered in HKCU\\Run — Sentinel launches when you log in."
        elif not is_frozen:
            status = "Dev mode — build the EXE first to enable startup registration."
        else:
            status = "Not registered — Sentinel must be started manually."
        self._startup_status.setText(status)
        # Enable "Enable Startup" only when compiled and not yet registered
        self._install_startup_btn.setEnabled(is_frozen and not registered)
        self._remove_startup_btn.setEnabled(registered)

    def _enable_startup(self):
        try:
            _register_startup()
            self._refresh_startup()
        except RuntimeError as e:
            QMessageBox.warning(self, "Startup Registration Unavailable", str(e))
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def _disable_startup(self):
        try:
            _unregister_startup()
            self._refresh_startup()
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))
