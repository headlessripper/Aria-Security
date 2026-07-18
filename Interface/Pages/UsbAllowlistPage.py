"""USB Allowlist Page — whitelist specific USB devices by Hardware ID."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QFrame, QMessageBox, QInputDialog,
)

CARD = "#161b22"; BORDER = "#21262d"; SURFACE = "#0d1117"
ACCENT = "#2f81f7"; GREEN = "#3fb950"; RED = "#f85149"; ORANGE = "#d29922"
TEXT = "#e6edf3"; TEXT_DIM = "#8b949e"; TEXT_MUTED = "#484f58"

_ALLOWLIST_PATH = Path.home() / ".AriaSecurity" / "usb_allowlist.json"


def _load_allowlist() -> list[dict]:
    try:
        if _ALLOWLIST_PATH.exists():
            return json.loads(_ALLOWLIST_PATH.read_text())
    except Exception:
        pass
    return []


def _save_allowlist(entries: list[dict]):
    _ALLOWLIST_PATH.write_text(json.dumps(entries, indent=2))


def is_usb_allowed(hardware_id: str) -> bool:
    return any(e.get("hardware_id", "").lower() == hardware_id.lower() for e in _load_allowlist())


class _DetectWorker(QThread):
    """Enumerate currently connected USB storage devices via PowerShell."""
    done = Signal(list)

    def run(self):
        try:
            ps = (
                "Get-PnpDevice | "
                "Where-Object { $_.InstanceId -like 'USBSTOR\\*' } | "
                "Select-Object FriendlyName, InstanceId, Status | "
                "ConvertTo-Json -Compress"
            )
            r = subprocess.run(
                ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps],
                capture_output=True, text=True, timeout=15,
            )
            if r.stdout.strip():
                import json as _j
                data = _j.loads(r.stdout.strip())
                if isinstance(data, dict):
                    data = [data]
                self.done.emit(data)
            else:
                self.done.emit([])
        except Exception:
            self.done.emit([])


class UsbAllowlistPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        hdr = QHBoxLayout()
        title = QLabel("USB Device Allowlist")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        hdr.addWidget(title)
        hdr.addStretch()
        root.addLayout(hdr)

        hint = QLabel(
            "Devices listed here bypass the USB auto-scan prompt. "
            "Devices are matched by Hardware ID — plug in the device and click Detect to add it."
        )
        hint.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        hint.setWordWrap(True)
        root.addWidget(hint)

        cols = QHBoxLayout()
        cols.setSpacing(12)

        # Left: connected devices
        left = QFrame()
        left.setObjectName("Card")
        ll = QVBoxLayout(left)
        ll.setContentsMargins(12, 12, 12, 12)
        ll.setSpacing(8)
        ll.addWidget(self._sec("Connected USB Storage Devices"))
        self._detected_list = QListWidget()
        self._detected_list.setStyleSheet(self._lw_style())
        ll.addWidget(self._detected_list, 1)
        detect_btn = QPushButton("Detect Devices")
        detect_btn.setStyleSheet(
            f"QPushButton{{background:{ACCENT};color:white;border:none;"
            f"border-radius:8px;padding:6px 14px;font-size:12px;}}"
            f"QPushButton:hover{{background:#388bfd;}}"
        )
        detect_btn.clicked.connect(self._detect)
        add_btn = QPushButton("Add to Allowlist")
        add_btn.setStyleSheet(
            f"QPushButton{{background:{GREEN}22;color:{GREEN};border:1px solid {GREEN}44;"
            f"border-radius:8px;padding:6px 14px;font-size:12px;}}"
            f"QPushButton:hover{{background:{GREEN}44;}}"
        )
        add_btn.clicked.connect(self._add_from_detected)
        btn_r = QHBoxLayout()
        btn_r.addWidget(detect_btn)
        btn_r.addWidget(add_btn)
        ll.addLayout(btn_r)
        cols.addWidget(left, 1)

        # Right: allowlist
        right = QFrame()
        right.setObjectName("Card")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(12, 12, 12, 12)
        rl.setSpacing(8)
        rl.addWidget(self._sec("Trusted Devices"))
        self._allow_list = QListWidget()
        self._allow_list.setStyleSheet(self._lw_style())
        rl.addWidget(self._allow_list, 1)
        manual_btn = QPushButton("Add Manually")
        manual_btn.setStyleSheet(
            f"QPushButton{{background:{CARD};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:8px;padding:6px 14px;font-size:12px;}}"
            f"QPushButton:hover{{background:#1c2128;}}"
        )
        manual_btn.clicked.connect(self._add_manual)
        remove_btn = QPushButton("Remove")
        remove_btn.setStyleSheet(
            f"QPushButton{{background:{RED}1a;color:{RED};border:1px solid {RED}33;"
            f"border-radius:8px;padding:6px 14px;font-size:12px;}}"
            f"QPushButton:hover{{background:{RED}33;}}"
        )
        remove_btn.clicked.connect(self._remove_selected)
        rb = QHBoxLayout()
        rb.addWidget(manual_btn)
        rb.addWidget(remove_btn)
        rl.addLayout(rb)
        cols.addWidget(right, 1)

        root.addLayout(cols, 1)

        self._detected_devices: list[dict] = []
        self._worker: _DetectWorker | None = None
        QTimer.singleShot(200, self._refresh_allow)

    @staticmethod
    def _sec(text: str) -> QLabel:
        l = QLabel(text)
        l.setStyleSheet(f"font-size:11px;font-weight:600;color:{TEXT_DIM};")
        return l

    @staticmethod
    def _lw_style() -> str:
        return (
            f"QListWidget{{background:transparent;border:none;}}"
            f"QListWidget::item{{padding:8px 6px;border-bottom:1px solid {BORDER};color:{TEXT};}}"
            f"QListWidget::item:selected{{background:{ACCENT}22;}}"
        )

    def _detect(self):
        if self._worker and self._worker.isRunning():
            return
        self._detected_list.clear()
        self._detected_list.addItem("Detecting…")
        self._worker = _DetectWorker()
        self._worker.done.connect(self._on_detected)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.start()

    def _on_detected(self, devices: list[dict]):
        self._detected_devices = devices
        self._detected_list.clear()
        if not devices:
            self._detected_list.addItem("No USB storage devices found")
            return
        allowed_ids = {e.get("hardware_id", "").lower() for e in _load_allowlist()}
        for dev in devices:
            name = dev.get("FriendlyName") or dev.get("InstanceId", "Unknown")
            iid  = dev.get("InstanceId", "")
            already = " ✅" if iid.lower() in allowed_ids else ""
            item = QListWidgetItem(f"{name}{already}\n  {iid}")
            item.setData(Qt.ItemDataRole.UserRole, dev)
            self._detected_list.addItem(item)

    def _add_from_detected(self):
        item = self._detected_list.currentItem()
        if not item:
            return
        dev = item.data(Qt.ItemDataRole.UserRole)
        if not dev:
            return
        iid  = dev.get("InstanceId", "")
        name = dev.get("FriendlyName") or iid
        if not iid:
            return
        entries = _load_allowlist()
        if any(e.get("hardware_id", "").lower() == iid.lower() for e in entries):
            QMessageBox.information(self, "Already Trusted", f"{name} is already in the allowlist.")
            return
        entries.append({"label": name, "hardware_id": iid})
        _save_allowlist(entries)
        self._refresh_allow()

    def _add_manual(self):
        hw_id, ok = QInputDialog.getText(
            self, "Add Device", "Enter Hardware ID (e.g. USBSTOR\\DISK&…):"
        )
        if ok and hw_id.strip():
            entries = _load_allowlist()
            entries.append({"label": hw_id.strip(), "hardware_id": hw_id.strip()})
            _save_allowlist(entries)
            self._refresh_allow()

    def _remove_selected(self):
        item = self._allow_list.currentItem()
        if not item:
            return
        hw_id = item.data(Qt.ItemDataRole.UserRole)
        entries = [e for e in _load_allowlist() if e.get("hardware_id") != hw_id]
        _save_allowlist(entries)
        self._refresh_allow()

    def _refresh_allow(self):
        self._allow_list.clear()
        for entry in _load_allowlist():
            label = entry.get("label", entry.get("hardware_id", ""))
            hw_id = entry.get("hardware_id", "")
            item  = QListWidgetItem(f"{label}\n  {hw_id}")
            item.setData(Qt.ItemDataRole.UserRole, hw_id)
            self._allow_list.addItem(item)
