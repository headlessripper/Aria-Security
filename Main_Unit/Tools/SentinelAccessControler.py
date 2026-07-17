import ctypes
import subprocess
import time
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout,
    QPushButton, QMessageBox, QFrame, QHBoxLayout
)
from PySide6.QtGui import QFont, QIcon
from PySide6.QtCore import Qt, QThread, Signal, Slot

from Main_Unit.Config.Sys_Config import SYSTEM_ICON_PATH
from Main_Unit.find_items import find_items

system_ico = find_items(SYSTEM_ICON_PATH)


# ── Helpers ──────────────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _read_usbstor_start() -> int | None:
    """Return the USBSTOR Start DWORD (3=enabled, 4=disabled) or None on error."""
    try:
        result = subprocess.run(
            ["reg", "query",
             r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR",
             "/v", "Start"],
            capture_output=True, text=True, timeout=8,
        )
        for part in result.stdout.split():
            if part.startswith("0x") or part.isdigit():
                return int(part, 0)
    except Exception:
        pass
    return None


# ── Title bar ─────────────────────────────────────────────────────────────────

class TitleBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._mouse_pos = None
        self.setFixedHeight(32)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 4, 10, 4)
        layout.setSpacing(8)

        icon_lbl = QLabel()
        if system_ico:
            icon_lbl.setPixmap(QIcon(system_ico).pixmap(16, 16))

        title_lbl = QLabel("Sentinel USB Access Controller")
        title_lbl.setObjectName("TitleLabel")

        close_btn = QPushButton("✕")
        close_btn.setObjectName("TitleCloseBtn")
        close_btn.setFixedSize(22, 22)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.clicked.connect(lambda: self.window().close())

        layout.addWidget(icon_lbl)
        layout.addWidget(title_lbl)
        layout.addStretch()
        layout.addWidget(close_btn)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._mouse_pos = event.globalPosition().toPoint()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._mouse_pos is not None:
            delta = event.globalPosition().toPoint() - self._mouse_pos
            self.window().move(self.window().pos() + delta)
            self._mouse_pos = event.globalPosition().toPoint()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        self._mouse_pos = None
        super().mouseReleaseEvent(event)


# ── State reader thread ───────────────────────────────────────────────────────

class _StateReader(QThread):
    """Reads the USBSTOR registry value off the main thread and emits the result."""
    done = Signal(object)  # int | None

    def run(self):
        self.done.emit(_read_usbstor_start())


# ── Worker thread ─────────────────────────────────────────────────────────────

class USBWorker(QThread):
    """
    Runs USB access toggle entirely off the main thread.

    Safe approach — two steps:
      1. Registry: USBSTOR\\Start = 3 (enable) or 4 (disable)
         Prevents the driver from loading for NEW connections.
      2. PowerShell: target only USBSTOR\\* device instance IDs.
         These are exclusively USB-storage endpoints — never HID
         (keyboard / mouse / hub) devices, so the system stays responsive.
    """
    finished = Signal(bool, str)  # success, message

    def __init__(self, target_enable: bool):
        super().__init__()
        self.target_enable = target_enable

    def run(self):
        errors: list[str] = []

        # ── Step 1: USBSTOR driver start-type ────────────────────────────────
        reg_val = "3" if self.target_enable else "4"
        try:
            r = subprocess.run(
                ["reg", "add",
                 r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR",
                 "/v", "Start", "/t", "REG_DWORD", "/d", reg_val, "/f"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode != 0:
                errors.append(f"Registry write failed (code {r.returncode}): {r.stderr.strip()}")
        except subprocess.TimeoutExpired:
            errors.append("Registry write timed out")
        except Exception as e:
            errors.append(f"Registry error: {e}")

        if errors:
            self.finished.emit(False, "\n".join(errors))
            return

        # ── Step 2: Immediate effect on currently connected storage devices ──
        # PowerShell filter: instance ID starts with "USBSTOR\" — ONLY storage,
        # never keyboards, mice, hubs, or USB controllers.
        if self.target_enable:
            ps_cmd = (
                "Get-PnpDevice | "
                "Where-Object { $_.InstanceId -like 'USBSTOR\\*' } | "
                "Enable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue; "
                "& pnputil /scan-devices | Out-Null"
            )
        else:
            ps_cmd = (
                "Get-PnpDevice | "
                "Where-Object { $_.InstanceId -like 'USBSTOR\\*' "
                "               -and $_.Status -eq 'OK' } | "
                "Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue"
            )

        try:
            subprocess.run(
                ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=20,
            )
        except subprocess.TimeoutExpired:
            errors.append("Device control timed out — registry change applied, reboot to complete")
        except Exception as e:
            errors.append(f"Device control error: {e}")

        # Brief pause for Windows to complete the hardware handshake
        time.sleep(0.8)

        if errors:
            self.finished.emit(False, "\n".join(errors))
        else:
            self.finished.emit(True, "")


# ── Main UI ───────────────────────────────────────────────────────────────────

class USBControlApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        if system_ico:
            self.setWindowIcon(QIcon(system_ico))
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setMinimumWidth(460)

        self._worker: USBWorker | None = None
        # True=unlocked, False=locked, None=unknown/reading
        self._current_state: bool | None = None

        # ── Layout ──
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)

        container = QFrame()
        container.setObjectName("Container")
        cl = QVBoxLayout(container)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)

        cl.addWidget(TitleBar(self))

        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 16, 16, 16)
        card_layout.setSpacing(12)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("USB Port Access")
        title.setObjectName("HeaderTitleLabel")
        subtitle = QLabel("Lock or unlock USB storage ports system-wide.")
        subtitle.setObjectName("MutedLabel")
        hdr_txt = QVBoxLayout()
        hdr_txt.addWidget(title)
        hdr_txt.addWidget(subtitle)
        hdr.addLayout(hdr_txt)
        hdr.addStretch()
        card_layout.addLayout(hdr)

        # Admin warning banner (hidden when not needed)
        self._admin_banner = QLabel(
            "⚠  Run as Administrator for changes to take effect."
        )
        self._admin_banner.setObjectName("WarnLabel")
        self._admin_banner.setAlignment(Qt.AlignCenter)
        self._admin_banner.setVisible(not is_admin())
        card_layout.addWidget(self._admin_banner)

        # Status + button
        inner = QVBoxLayout()
        inner.setContentsMargins(30, 20, 30, 20)
        inner.setSpacing(20)

        self._status_lbl = QLabel("READING STATE…")
        self._status_lbl.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self._status_lbl.setAlignment(Qt.AlignCenter)
        inner.addWidget(self._status_lbl)

        self._toggle_btn = QPushButton("LOADING…")
        self._toggle_btn.setFixedHeight(52)
        self._toggle_btn.setCursor(Qt.PointingHandCursor)
        self._toggle_btn.setEnabled(False)
        self._toggle_btn.clicked.connect(self._on_toggle_clicked)
        inner.addWidget(self._toggle_btn)

        card_layout.addLayout(inner)

        # Footer
        footer = QHBoxLayout()
        footer.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        footer.addWidget(close_btn)
        card_layout.addLayout(footer)

        cl.addWidget(card)
        root.addWidget(container)

        self.setStyleSheet("""
            QWidget#Container {
                background-color: #1a1f2e;
                border-radius: 12px;
            }
            QFrame#Card {
                background-color: #1a1f2e;
                border: 1px solid #2d3448;
                border-radius: 12px;
            }
            QLabel#TitleLabel {
                font-size: 13px; font-weight: 600; color: #e6edf3;
            }
            QLabel#HeaderTitleLabel {
                font-size: 15px; font-weight: 700; color: #e6edf3;
            }
            QLabel#MutedLabel {
                color: #8b949e; font-size: 11px;
            }
            QLabel#WarnLabel {
                color: #d29922;
                background: #2a2310;
                border: 1px solid #d2992244;
                border-radius: 6px;
                padding: 6px;
                font-size: 11px;
            }
            QLabel {
                font-size: 13px; color: #e5e7eb;
            }
            QPushButton {
                background-color: #21262d;
                color: #e6edf3;
                border-radius: 6px;
                padding: 6px 14px;
                border: 1px solid #30363d;
                font-size: 12px;
            }
            QPushButton:hover { background-color: #30363d; }
            QPushButton:pressed { background-color: #2f81f7; color: white; }
            QPushButton:disabled { color: #484f58; background-color: #161b22; }
            QPushButton#TitleCloseBtn {
                background: transparent;
                border: none;
                color: #8b949e;
                font-size: 13px;
                padding: 0;
                border-radius: 4px;
            }
            QPushButton#TitleCloseBtn:hover { background: #f85149; color: white; }
        """)

        # Read registry off the main thread so startup is instant
        self._refresh_state()

    def _refresh_state(self):
        """Start a background registry read; result is delivered via Qt signal."""
        self._current_state = None
        self._toggle_btn.setEnabled(False)
        self._toggle_btn.setText("READING…")
        self._toggle_btn.setStyleSheet("")
        self._status_lbl.setText("READING STATE…")
        self._status_lbl.setStyleSheet("color:#8b949e;")

        reader = _StateReader(self)
        reader.done.connect(self._apply_state)
        reader.finished.connect(reader.deleteLater)
        reader.start()

    def _apply_state(self, reg_value):
        """Called on the main thread once the registry read completes."""
        if reg_value is None:
            self._current_state = None
            self._status_lbl.setText("STATE UNKNOWN")
            self._status_lbl.setStyleSheet("color:#8b949e;")
            self._toggle_btn.setText("RETRY")
            self._toggle_btn.setStyleSheet("")
            self._toggle_btn.setEnabled(True)
            return
        enabled = (reg_value == 3)
        self._current_state = enabled
        self._update_ui(enabled)

    def _update_ui(self, enabled: bool):
        if enabled:
            self._status_lbl.setText("PORTS: UNLOCKED")
            self._status_lbl.setStyleSheet("color: #3fb950; font-size:15px;")
            self._toggle_btn.setText("LOCK USB PORTS")
            self._toggle_btn.setStyleSheet(
                "QPushButton{background:#d29922;color:#000;border-radius:8px;"
                "font-weight:700;font-size:13px;border:none;}"
                "QPushButton:hover{background:#b8841e;}"
            )
        else:
            self._status_lbl.setText("PORTS: LOCKED")
            self._status_lbl.setStyleSheet("color: #f85149; font-size:15px;")
            self._toggle_btn.setText("UNLOCK USB PORTS")
            self._toggle_btn.setStyleSheet(
                "QPushButton{background:#3fb950;color:#000;border-radius:8px;"
                "font-weight:700;font-size:13px;border:none;}"
                "QPushButton:hover{background:#2ea043;}"
            )
        self._toggle_btn.setEnabled(is_admin())

    def _on_toggle_clicked(self):
        if self._worker and self._worker.isRunning():
            return

        # Unknown state: re-read instead of attempting a toggle
        if self._current_state is None:
            self._refresh_state()
            return

        locking = self._current_state  # True = currently unlocked → about to lock

        if locking:
            reply = QMessageBox.question(
                self, "Confirm Lock",
                "Locking USB ports will disconnect all USB storage devices.\n"
                "Make sure all USB drives are safely removed first.\n\n"
                "Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        self._toggle_btn.setEnabled(False)
        self._toggle_btn.setText("WORKING… PLEASE WAIT")
        self._toggle_btn.setStyleSheet("")
        self._status_lbl.setText("APPLYING…")
        self._status_lbl.setStyleSheet("color:#d29922;")

        target_enable = not locking
        self._worker = USBWorker(target_enable)
        self._worker.finished.connect(self._on_finished)
        self._worker.start()

    @Slot(bool, str)
    def _on_finished(self, success: bool, message: str):
        if not success:
            QMessageBox.critical(
                self, "Operation Failed",
                f"The USB access change could not be applied:\n\n{message}\n\n"
                "Ensure Sentinel is running as Administrator.",
            )
        self._refresh_state()
