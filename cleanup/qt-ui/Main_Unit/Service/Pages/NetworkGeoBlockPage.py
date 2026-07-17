"""Network Geo-Block Page — block inbound/outbound traffic by country via Windows Firewall."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QColor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QFrame, QMessageBox,
    QProgressBar, QCheckBox,
)

CARD = "#161b22"; BORDER = "#21262d"; SURFACE = "#0d1117"
ACCENT = "#2f81f7"; GREEN = "#3fb950"; RED = "#f85149"; ORANGE = "#d29922"
TEXT = "#e6edf3"; TEXT_DIM = "#8b949e"; TEXT_MUTED = "#484f58"

_STATE_PATH = Path.home() / ".AriaSecurity" / "geo_blocks.json"

# Country name → ISO-2 code (subset of commonly blocked countries + user-relevant ones)
_COUNTRIES: list[tuple[str, str]] = [
    ("China",               "CN"),
    ("Russia",              "RU"),
    ("North Korea",         "KP"),
    ("Iran",                "IR"),
    ("Belarus",             "BY"),
    ("Syria",               "SY"),
    ("Cuba",                "CU"),
    ("Venezuela",           "VE"),
    ("Myanmar",             "MM"),
    ("Nigeria",             "NG"),
    ("Ukraine",             "UA"),
    ("Brazil",              "BR"),
    ("India",               "IN"),
    ("Vietnam",             "VN"),
    ("Pakistan",            "PK"),
    ("Romania",             "RO"),
    ("Turkey",              "TR"),
    ("Bangladesh",          "BD"),
    ("Indonesia",           "ID"),
    ("Algeria",             "DZ"),
]

# Minimal /16 prefix samples per country for demo (real deployments use full CIDR lists)
_SAMPLE_RANGES: dict[str, list[str]] = {
    "CN": ["1.0.1.0/24","1.0.2.0/23","1.0.8.0/21","1.0.32.0/19","1.1.0.0/24","1.2.0.0/16","14.0.0.0/16","27.0.0.0/16","36.0.0.0/16","49.0.0.0/16","58.0.0.0/16","59.0.0.0/16","60.0.0.0/16","61.0.0.0/16"],
    "RU": ["2.56.0.0/16","5.18.0.0/16","5.45.0.0/16","5.63.0.0/16","31.13.0.0/16","31.40.0.0/16","31.148.0.0/16","37.17.0.0/16","37.29.0.0/16","37.44.0.0/16","45.8.0.0/16","45.11.0.0/16","77.37.0.0/16","77.72.0.0/16","78.25.0.0/16","78.108.0.0/16","79.98.0.0/16","80.66.0.0/16","80.82.0.0/16","80.90.0.0/16","81.162.0.0/16","82.146.0.0/16","83.217.0.0/16","84.42.0.0/16","85.93.0.0/16","86.57.0.0/16","87.224.0.0/16","88.200.0.0/16","89.111.0.0/16","90.188.0.0/16","91.108.0.0/16","91.210.0.0/16","92.53.0.0/16","93.91.0.0/16","94.140.0.0/16","95.31.0.0/16","176.0.0.0/16","178.48.0.0/16","185.0.0.0/16","188.0.0.0/16","193.0.0.0/16","195.19.0.0/16","212.0.0.0/16","213.0.0.0/16","217.0.0.0/16"],
    "KP": ["175.45.176.0/22","210.52.109.0/24","77.94.35.0/24"],
    "IR": ["2.144.0.0/16","5.22.0.0/16","5.53.0.0/16","5.160.0.0/16","31.2.0.0/16","31.14.0.0/16","31.24.0.0/16","31.57.0.0/16","37.0.0.0/16","78.157.0.0/16","80.75.0.0/16","82.99.0.0/16","91.99.0.0/16","91.108.0.0/16","176.221.0.0/16","185.0.0.0/16","193.29.0.0/16","195.146.0.0/16","213.176.0.0/16"],
    "BY": ["5.100.0.0/16","37.17.0.0/16","46.56.0.0/16","80.94.0.0/16","81.163.0.0/16","82.209.0.0/16","83.97.0.0/16","84.22.0.0/16","85.90.0.0/16","86.57.0.0/16","88.200.0.0/16","93.84.0.0/16","178.120.0.0/16","185.0.0.0/16","193.0.0.0/16","194.0.0.0/16"],
    "SY": ["5.0.0.0/16","31.9.0.0/16","45.148.0.0/16","80.90.0.0/16","85.0.0.0/16","176.105.0.0/16","185.125.0.0/16","213.178.0.0/16"],
}
# Fill remaining countries with placeholder ranges (in production, use full CIDR DB)
for _cc in [c[1] for c in _COUNTRIES if c[1] not in _SAMPLE_RANGES]:
    _SAMPLE_RANGES[_cc] = []


def _load_state() -> dict[str, bool]:
    try:
        if _STATE_PATH.exists():
            return json.loads(_STATE_PATH.read_text())
    except Exception:
        pass
    return {}


def _save_state(state: dict[str, bool]):
    _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STATE_PATH.write_text(json.dumps(state, indent=2))


def _rule_name(iso2: str) -> str:
    return f"Sentinel_GeoBlock_{iso2}"


class _BlockWorker(QThread):
    progress  = Signal(int, int)
    log       = Signal(str)
    finished  = Signal()

    def __init__(self, iso2: str, country: str, enable: bool):
        super().__init__()
        self._iso2    = iso2
        self._country = country
        self._enable  = enable

    def run(self):
        ranges = _SAMPLE_RANGES.get(self._iso2, [])
        name   = _rule_name(self._iso2)

        if not self._enable:
            # Delete rule
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={name}",
            ], capture_output=True, timeout=15)
            self.log.emit(f"Removed block rule for {self._country}")
            self.finished.emit()
            return

        if not ranges:
            self.log.emit(f"No IP ranges available for {self._country} — rule skipped.")
            self.finished.emit()
            return

        # Delete any existing rule first
        subprocess.run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={name}",
        ], capture_output=True, timeout=10)

        # Build comma-separated range list (netsh accepts up to ~100 at once)
        chunks = [ranges[i:i+80] for i in range(0, len(ranges), 80)]
        total = len(chunks)
        for i, chunk in enumerate(chunks):
            ip_list = ",".join(chunk)
            chunk_name = f"{name}_{i}" if total > 1 else name
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={chunk_name}",
                "dir=in", "action=block",
                f"remoteip={ip_list}",
                "enable=yes",
            ], capture_output=True, timeout=30)
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={chunk_name}_out",
                "dir=out", "action=block",
                f"remoteip={ip_list}",
                "enable=yes",
            ], capture_output=True, timeout=30)
            self.progress.emit(i + 1, total)

        self.log.emit(f"Blocked {self._country} ({len(ranges)} CIDR ranges)")
        self.finished.emit()


class NetworkGeoBlockPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        hdr = QHBoxLayout()
        title = QLabel("Network Geo-Block")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        hdr.addWidget(title)
        hdr.addStretch()
        root.addLayout(hdr)

        hint = QLabel(
            "Block all inbound and outbound traffic to/from selected countries via Windows Firewall. "
            "Uses CIDR IP ranges. Requires administrator privileges. "
            "Note: IP-based geo-blocking is best-effort — VPNs and proxies bypass it."
        )
        hint.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        hint.setWordWrap(True)
        root.addWidget(hint)

        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setFixedHeight(14)
        self._progress.setVisible(False)
        self._progress.setStyleSheet(
            f"QProgressBar{{background:{SURFACE};border:1px solid {BORDER};"
            f"border-radius:4px;font-size:9px;}}"
            f"QProgressBar::chunk{{background:{ACCENT};border-radius:3px;}}"
        )
        root.addWidget(self._progress)

        self._status = QLabel("")
        self._status.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        root.addWidget(self._status)

        # Country list
        list_card = QFrame()
        list_card.setObjectName("Card")
        lc = QVBoxLayout(list_card)
        lc.setContentsMargins(12, 12, 12, 12)
        lc.setSpacing(4)

        sec = QLabel("Countries")
        sec.setStyleSheet(f"font-size:11px;font-weight:600;color:{TEXT_DIM};")
        lc.addWidget(sec)

        self._list = QListWidget()
        self._list.setStyleSheet(
            f"QListWidget{{background:transparent;border:none;}}"
            f"QListWidget::item{{padding:6px 4px;border-bottom:1px solid {BORDER};color:{TEXT};}}"
            f"QListWidget::item:selected{{background:{ACCENT}22;}}"
        )
        lc.addWidget(self._list, 1)

        btn_row = QHBoxLayout()
        apply_btn = QPushButton("Apply Changes")
        apply_btn.setStyleSheet(
            f"QPushButton{{background:{ACCENT};color:white;border:none;"
            f"border-radius:8px;padding:6px 16px;font-size:12px;font-weight:600;}}"
            f"QPushButton:hover{{background:#388bfd;}}"
        )
        apply_btn.clicked.connect(self._apply)
        clear_btn = QPushButton("Remove All Geo-Block Rules")
        clear_btn.setStyleSheet(
            f"QPushButton{{background:{RED}1a;color:{RED};border:1px solid {RED}33;"
            f"border-radius:8px;padding:6px 14px;font-size:12px;}}"
            f"QPushButton:hover{{background:{RED}33;}}"
        )
        clear_btn.clicked.connect(self._clear_all)
        btn_row.addWidget(apply_btn)
        btn_row.addStretch()
        btn_row.addWidget(clear_btn)
        lc.addLayout(btn_row)

        root.addWidget(list_card, 1)

        self._checkboxes: dict[str, QCheckBox] = {}
        self._worker: _BlockWorker | None = None
        self._state = _load_state()
        self._build_list()

    def _build_list(self):
        self._list.clear()
        self._checkboxes.clear()
        for name, iso2 in _COUNTRIES:
            item = QListWidgetItem()
            item.setSizeHint(item.sizeHint().__class__(0, 32))
            cb = QCheckBox(f"  {name}  ({iso2})")
            cb.setStyleSheet(f"color:{TEXT};font-size:12px;")
            cb.setChecked(self._state.get(iso2, False))
            self._list.addItem(item)
            self._list.setItemWidget(item, cb)
            self._checkboxes[iso2] = cb

    def _apply(self):
        if self._worker and self._worker.isRunning():
            return
        pending: list[tuple[str, str, bool]] = []
        for name, iso2 in _COUNTRIES:
            wanted = self._checkboxes[iso2].isChecked()
            current = self._state.get(iso2, False)
            if wanted != current:
                pending.append((iso2, name, wanted))

        if not pending:
            self._status.setText("No changes to apply.")
            return

        self._state_updates = pending[:]
        self._status.setText(f"Applying {len(pending)} change(s)…")
        self._progress.setVisible(True)
        self._progress.setValue(0)
        self._run_next()

    def _run_next(self):
        if not self._state_updates:
            self._status.setText("All changes applied.")
            self._progress.setVisible(False)
            _save_state(self._state)
            return
        iso2, country, enable = self._state_updates.pop(0)
        self._worker = _BlockWorker(iso2, country, enable)
        self._worker.log.connect(self._status.setText)
        self._worker.finished.connect(lambda: self._on_done(iso2, enable))
        self._worker.start()

    def _on_done(self, iso2: str, enabled: bool):
        self._state[iso2] = enabled
        self._run_next()

    def _clear_all(self):
        reply = QMessageBox.question(
            self, "Remove All", "Remove all Sentinel geo-block firewall rules?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self._status.setText("Removing all geo-block rules…")
        for _, iso2 in _COUNTRIES:
            name = _rule_name(iso2)
            for suffix in ["", "_0", "_1", "_2", "_3", "_0_out", "_1_out", "_2_out", "_3_out", "_out"]:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={name}{suffix}",
                ], capture_output=True, timeout=10)
            self._state[iso2] = False
        for cb in self._checkboxes.values():
            cb.setChecked(False)
        _save_state(self._state)
        self._status.setText("All geo-block rules removed.")
