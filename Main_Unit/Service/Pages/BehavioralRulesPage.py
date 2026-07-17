"""Behavioral Rules Editor — view, add, edit, and delete behavioral detection rules."""
from __future__ import annotations

import json
import os

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QTextEdit, QFrame, QMessageBox,
    QSplitter, QSizePolicy,
)

from Main_Unit.find_items import find_items
from Main_Unit.Config.Sys_Config import BEHAVIORAL_RULES_PATH

CARD = "#161b22"; BORDER = "#21262d"; SURFACE = "#0d1117"
ACCENT = "#2f81f7"; GREEN = "#3fb950"; RED = "#f85149"
TEXT = "#e6edf3"; TEXT_DIM = "#8b949e"; TEXT_MUTED = "#484f58"

_DEFAULT_RULE = {
    "name": "New Rule",
    "enabled": True,
    "conditions": [{"field": "process_name", "op": "contains", "value": "example"}],
    "action": "alert",
    "severity": "MEDIUM",
    "description": "Describe what this rule detects."
}


class BehavioralRulesPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        hdr = QHBoxLayout()
        title = QLabel("Behavioral Rules")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        hdr.addWidget(title)
        hdr.addStretch()
        add_btn = QPushButton("+ New Rule")
        add_btn.setStyleSheet(
            f"QPushButton{{background:{ACCENT};color:white;border:none;"
            f"border-radius:8px;padding:7px 16px;font-size:13px;font-weight:600;}}"
            f"QPushButton:hover{{background:#388bfd;}}"
        )
        add_btn.clicked.connect(self._add_rule)
        hdr.addWidget(add_btn)
        root.addLayout(hdr)

        hint = QLabel(
            "Rules are matched against running processes and file events in real-time. "
            "Edit JSON directly and click Save to apply."
        )
        hint.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        hint.setWordWrap(True)
        root.addWidget(hint)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: rule list
        left = QFrame()
        left.setObjectName("Card")
        ll = QVBoxLayout(left)
        ll.setContentsMargins(12, 12, 12, 12)
        ll.setSpacing(8)

        self._rule_list = QListWidget()
        self._rule_list.setStyleSheet(
            f"QListWidget{{background:transparent;border:none;}}"
            f"QListWidget::item{{padding:8px 6px;border-bottom:1px solid {BORDER};color:{TEXT};}}"
            f"QListWidget::item:selected{{background:{ACCENT}22;}}"
        )
        self._rule_list.currentRowChanged.connect(self._on_select)
        ll.addWidget(self._rule_list, 1)

        lr_btns = QHBoxLayout()
        del_btn = QPushButton("Delete")
        del_btn.setStyleSheet(
            f"QPushButton{{background:{RED}1a;color:{RED};border:1px solid {RED}33;"
            f"border-radius:6px;padding:5px 12px;font-size:12px;}}"
            f"QPushButton:hover{{background:{RED}33;}}"
        )
        del_btn.clicked.connect(self._delete_rule)
        lr_btns.addStretch()
        lr_btns.addWidget(del_btn)
        ll.addLayout(lr_btns)
        splitter.addWidget(left)

        # Right: JSON editor
        right = QFrame()
        right.setObjectName("Card")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(12, 12, 12, 12)
        rl.setSpacing(8)

        edit_lbl = QLabel("Rule JSON")
        edit_lbl.setStyleSheet(f"font-size:11px;font-weight:600;color:{TEXT_DIM};")
        rl.addWidget(edit_lbl)

        self._editor = QTextEdit()
        self._editor.setStyleSheet(
            f"QTextEdit{{background:{SURFACE};color:#7ee787;"
            f"border:1px solid {BORDER};border-radius:8px;"
            f"font-family:'Consolas','Courier New',monospace;font-size:11pt;padding:8px;}}"
        )
        rl.addWidget(self._editor, 1)

        save_btn = QPushButton("Save Changes")
        save_btn.setStyleSheet(
            f"QPushButton{{background:{GREEN}22;color:{GREEN};border:1px solid {GREEN}44;"
            f"border-radius:8px;padding:7px 18px;font-size:13px;font-weight:600;}}"
            f"QPushButton:hover{{background:{GREEN}44;}}"
        )
        save_btn.clicked.connect(self._save_rule)
        rl.addWidget(save_btn, alignment=Qt.AlignmentFlag.AlignRight)
        splitter.addWidget(right)

        splitter.setSizes([220, 580])
        splitter.setStyleSheet("QSplitter::handle{background:#21262d;width:1px;}")
        root.addWidget(splitter, 1)

        self._rules: list[dict] = []
        self._rules_path = find_items(BEHAVIORAL_RULES_PATH)
        QTimer.singleShot(100, self._load)

    def _load(self):
        self._rules = []
        try:
            if self._rules_path and os.path.exists(self._rules_path):
                with open(self._rules_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._rules = data if isinstance(data, list) else data.get("rules", [])
        except Exception:
            pass
        self._populate_list()

    def _populate_list(self):
        self._rule_list.clear()
        for rule in self._rules:
            name    = rule.get("name", "Unnamed")
            enabled = rule.get("enabled", True)
            sev     = rule.get("severity", "MEDIUM")
            sev_color = {"HIGH": "#f85149", "MEDIUM": "#d29922", "LOW": "#3fb950"}.get(sev, TEXT_DIM)
            item = QListWidgetItem(f"{'✅' if enabled else '⏸'}  {name}")
            item.setToolTip(rule.get("description", ""))
            self._rule_list.addItem(item)

    def _on_select(self, row: int):
        if 0 <= row < len(self._rules):
            self._editor.setText(json.dumps(self._rules[row], indent=2))

    def _save_rule(self):
        row = self._rule_list.currentRow()
        if row < 0:
            return
        try:
            updated = json.loads(self._editor.toPlainText())
        except json.JSONDecodeError as e:
            QMessageBox.warning(self, "Invalid JSON", str(e))
            return
        self._rules[row] = updated
        self._flush()
        self._populate_list()
        self._rule_list.setCurrentRow(row)

    def _add_rule(self):
        self._rules.append(dict(_DEFAULT_RULE))
        self._flush()
        self._populate_list()
        self._rule_list.setCurrentRow(len(self._rules) - 1)

    def _delete_rule(self):
        row = self._rule_list.currentRow()
        if row < 0:
            return
        name = self._rules[row].get("name", "this rule")
        reply = QMessageBox.question(
            self, "Delete Rule", f"Delete rule '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._rules.pop(row)
            self._flush()
            self._populate_list()
            self._editor.clear()

    def _flush(self):
        if not self._rules_path:
            return
        try:
            with open(self._rules_path, "w", encoding="utf-8") as f:
                json.dump(self._rules, f, indent=2)
        except Exception as e:
            QMessageBox.warning(self, "Save Error", str(e))
