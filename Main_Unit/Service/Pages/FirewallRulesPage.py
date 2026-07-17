"""Firewall Rules Page — view, toggle, and block IPs via Windows Firewall."""
from __future__ import annotations

import subprocess

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QLineEdit, QMessageBox, QFrame,
)

CARD = "#161b22"; BORDER = "#21262d"; SURFACE = "#0d1117"
ACCENT = "#2f81f7"; GREEN = "#3fb950"; RED = "#f85149"; ORANGE = "#d29922"
TEXT = "#e6edf3"; TEXT_DIM = "#8b949e"


class _LoadWorker(QThread):
    done = Signal(list)

    def run(self):
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True, text=True, timeout=15,
            )
            rules = _parse_netsh(result.stdout)
            self.done.emit(rules)
        except Exception:
            self.done.emit([])


def _parse_netsh(output: str) -> list[dict]:
    rules, current = [], {}
    for line in output.splitlines():
        line = line.strip()
        if not line:
            if current.get("Rule Name"):
                rules.append(current)
            current = {}
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            current[key.strip()] = val.strip()
    if current.get("Rule Name"):
        rules.append(current)
    return rules


class FirewallRulesPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        hdr = QHBoxLayout()
        title = QLabel("Firewall Rules")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        hdr.addWidget(title)
        hdr.addStretch()
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setStyleSheet(
            f"QPushButton{{background:{CARD};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:8px;padding:7px 16px;font-size:13px;}}"
            f"QPushButton:hover{{background:#1c2128;}}"
        )
        refresh_btn.clicked.connect(self._load)
        hdr.addWidget(refresh_btn)
        root.addLayout(hdr)

        # Quick block row
        block_card = QFrame()
        block_card.setObjectName("Card")
        bc = QHBoxLayout(block_card)
        bc.setContentsMargins(16, 12, 16, 12)
        bc.setSpacing(10)
        bc.addWidget(QLabel("Block IP:"))
        self._ip_input = QLineEdit()
        self._ip_input.setPlaceholderText("e.g. 192.168.1.100")
        self._ip_input.setStyleSheet(
            f"QLineEdit{{background:{SURFACE};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:6px;padding:5px 10px;font-size:12px;}}"
        )
        block_btn = QPushButton("Block")
        block_btn.setStyleSheet(
            f"QPushButton{{background:{RED}22;color:{RED};border:1px solid {RED}44;"
            f"border-radius:6px;padding:6px 14px;font-size:12px;}}"
            f"QPushButton:hover{{background:{RED}44;}}"
        )
        block_btn.clicked.connect(self._block_ip)
        bc.addWidget(self._ip_input, 1)
        bc.addWidget(block_btn)
        root.addWidget(block_card)

        self._status_lbl = QLabel("Loading firewall rules…")
        self._status_lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        root.addWidget(self._status_lbl)

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Rule Name", "Direction", "Action", "Protocol", "Enabled"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet(f"""
            QTableWidget {{
                background:{CARD};color:{TEXT};border:1px solid {BORDER};
                border-radius:8px;gridline-color:{BORDER};
                alternate-background-color:#0d1117;
            }}
            QHeaderView::section {{
                background:{CARD};color:{TEXT_DIM};font-size:11px;font-weight:600;
                border:none;border-bottom:1px solid {BORDER};padding:6px 8px;
            }}
            QTableWidget::item{{padding:5px 8px;border:none;}}
            QTableWidget::item:selected{{background:{ACCENT}22;color:{TEXT};}}
        """)
        root.addWidget(self._table, 1)

        self._worker: _LoadWorker | None = None
        QTimer.singleShot(300, self._load)

    def _load(self):
        if self._worker and self._worker.isRunning():
            return
        self._status_lbl.setText("Loading firewall rules…")
        self._worker = _LoadWorker()
        self._worker.done.connect(self._populate)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.start()

    def _populate(self, rules: list[dict]):
        self._table.setRowCount(0)
        for rule in rules:
            r = self._table.rowCount()
            self._table.insertRow(r)
            enabled = rule.get("Enabled", "Yes")
            action  = rule.get("Action", "")
            items = [
                rule.get("Rule Name", ""),
                rule.get("Direction", ""),
                action,
                rule.get("Protocol", "Any"),
                enabled,
            ]
            for col, val in enumerate(items):
                item = QTableWidgetItem(str(val))
                if col == 2 and action.lower() == "block":
                    item.setForeground(__import__("PySide6.QtGui", fromlist=["QColor"]).QColor(RED))
                if col == 4 and enabled.lower() == "no":
                    item.setForeground(__import__("PySide6.QtGui", fromlist=["QColor"]).QColor(TEXT_DIM))
                self._table.setItem(r, col, item)
        self._status_lbl.setText(f"{len(rules)} rules loaded")

    def _block_ip(self):
        ip = self._ip_input.text().strip()
        if not ip:
            return
        reply = QMessageBox.question(
            self, "Block IP",
            f"Add firewall BLOCK rule for {ip}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            rule_name = f"Sentinel_Block_{ip}"
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in", "action=block",
                f"remoteip={ip}",
                "enable=yes",
            ], check=True, capture_output=True, timeout=10)
            self._ip_input.clear()
            self._status_lbl.setText(f"Blocked {ip}")
            QTimer.singleShot(800, self._load)
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))
