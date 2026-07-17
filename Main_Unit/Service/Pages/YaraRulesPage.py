"""YARA Rule Manager — import, enable/disable, and test custom .yara rules."""
from __future__ import annotations

import os
import shutil

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QTextEdit, QFrame, QMessageBox,
    QFileDialog, QSplitter, QLineEdit,
)

from Main_Unit.find_items import find_items
from Main_Unit.Config.Sys_Config import RULE_PATH

CARD = "#161b22"; BORDER = "#21262d"; SURFACE = "#0d1117"
ACCENT = "#2f81f7"; GREEN = "#3fb950"; RED = "#f85149"; ORANGE = "#d29922"
TEXT = "#e6edf3"; TEXT_DIM = "#8b949e"


class _TestWorker(QThread):
    result = Signal(str)

    def __init__(self, rule_file: str, sample_file: str):
        super().__init__()
        self._rule   = rule_file
        self._sample = sample_file

    def run(self):
        try:
            import yara
            rules = yara.compile(filepath=self._rule)
            matches = rules.match(self._sample)
            if matches:
                lines = [f"✅ {m.rule} (score={m.meta.get('score','?')})" for m in matches]
                self.result.emit("MATCHES:\n" + "\n".join(lines))
            else:
                self.result.emit("No matches — file appears clean against this rule.")
        except Exception as e:
            self.result.emit(f"Error: {e}")


class YaraRulesPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        hdr = QHBoxLayout()
        title = QLabel("YARA Rule Manager")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        hdr.addWidget(title)
        hdr.addStretch()
        import_btn = QPushButton("Import .yara / .yar")
        import_btn.setStyleSheet(
            f"QPushButton{{background:{ACCENT};color:white;border:none;"
            f"border-radius:8px;padding:7px 16px;font-size:13px;font-weight:600;}}"
            f"QPushButton:hover{{background:#388bfd;}}"
        )
        import_btn.clicked.connect(self._import_rule)
        hdr.addWidget(import_btn)
        root.addLayout(hdr)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: rule list
        left = QFrame()
        left.setObjectName("Card")
        ll = QVBoxLayout(left)
        ll.setContentsMargins(12, 12, 12, 12)
        ll.setSpacing(6)

        self._rule_list = QListWidget()
        self._rule_list.setStyleSheet(
            f"QListWidget{{background:transparent;border:none;}}"
            f"QListWidget::item{{padding:7px 6px;border-bottom:1px solid {BORDER};color:{TEXT};}}"
            f"QListWidget::item:selected{{background:{ACCENT}22;}}"
        )
        self._rule_list.currentRowChanged.connect(self._on_select)
        ll.addWidget(self._rule_list, 1)

        del_btn = QPushButton("Remove Rule")
        del_btn.setStyleSheet(
            f"QPushButton{{background:{RED}1a;color:{RED};border:1px solid {RED}33;"
            f"border-radius:6px;padding:5px 12px;font-size:12px;}}"
            f"QPushButton:hover{{background:{RED}33;}}"
        )
        del_btn.clicked.connect(self._delete_rule)
        ll.addWidget(del_btn)
        splitter.addWidget(left)

        # Right: viewer + tester
        right = QFrame()
        right.setObjectName("Card")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(12, 12, 12, 12)
        rl.setSpacing(8)

        view_lbl = QLabel("Rule Content (read-only)")
        view_lbl.setStyleSheet(f"font-size:11px;font-weight:600;color:{TEXT_DIM};")
        rl.addWidget(view_lbl)

        self._viewer = QTextEdit()
        self._viewer.setReadOnly(True)
        self._viewer.setStyleSheet(
            f"QTextEdit{{background:{SURFACE};color:#7ee787;"
            f"border:1px solid {BORDER};border-radius:8px;"
            f"font-family:'Consolas','Courier New',monospace;font-size:10pt;padding:8px;}}"
        )
        rl.addWidget(self._viewer, 1)

        test_lbl = QLabel("Test against a file")
        test_lbl.setStyleSheet(f"font-size:11px;font-weight:600;color:{TEXT_DIM};")
        rl.addWidget(test_lbl)

        test_row = QHBoxLayout()
        self._sample_path = QLineEdit()
        self._sample_path.setPlaceholderText("Path to sample file…")
        self._sample_path.setStyleSheet(
            f"QLineEdit{{background:{SURFACE};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:6px;padding:5px 8px;font-size:12px;}}"
        )
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self._browse_sample)
        test_btn = QPushButton("Run Test")
        test_btn.setStyleSheet(
            f"QPushButton{{background:{ORANGE}22;color:{ORANGE};border:1px solid {ORANGE}44;"
            f"border-radius:6px;padding:5px 12px;font-size:12px;}}"
            f"QPushButton:hover{{background:{ORANGE}44;}}"
        )
        test_btn.clicked.connect(self._run_test)
        test_row.addWidget(self._sample_path, 1)
        test_row.addWidget(browse_btn)
        test_row.addWidget(test_btn)
        rl.addLayout(test_row)

        self._test_result = QLabel("")
        self._test_result.setWordWrap(True)
        self._test_result.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        rl.addWidget(self._test_result)

        splitter.addWidget(right)
        splitter.setSizes([200, 600])
        splitter.setStyleSheet("QSplitter::handle{background:#21262d;width:1px;}")
        root.addWidget(splitter, 1)

        self._rules_dir = find_items(RULE_PATH)
        self._rule_files: list[str] = []
        self._worker: _TestWorker | None = None
        QTimer.singleShot(100, self._load)

    def _load(self):
        self._rule_files = []
        if self._rules_dir and os.path.isdir(self._rules_dir):
            for root_dir, _, files in os.walk(self._rules_dir):
                for f in files:
                    if f.lower().endswith((".yara", ".yar")):
                        self._rule_files.append(os.path.join(root_dir, f))
        self._rule_list.clear()
        for path in self._rule_files:
            self._rule_list.addItem(os.path.basename(path))

    def _on_select(self, row: int):
        if 0 <= row < len(self._rule_files):
            try:
                with open(self._rule_files[row], "r", encoding="utf-8", errors="replace") as f:
                    self._viewer.setText(f.read())
            except Exception as e:
                self._viewer.setText(f"Could not read file: {e}")

    def _import_rule(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Import YARA Rules", "", "YARA Files (*.yara *.yar)"
        )
        if not paths or not self._rules_dir:
            return
        for src in paths:
            dst = os.path.join(self._rules_dir, os.path.basename(src))
            try:
                shutil.copy2(src, dst)
            except Exception as e:
                QMessageBox.warning(self, "Import Error", f"{os.path.basename(src)}: {e}")
        self._load()

    def _delete_rule(self):
        row = self._rule_list.currentRow()
        if row < 0:
            return
        path = self._rule_files[row]
        reply = QMessageBox.question(
            self, "Remove Rule", f"Delete {os.path.basename(path)}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                os.remove(path)
                self._load()
                self._viewer.clear()
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

    def _browse_sample(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select sample file")
        if p:
            self._sample_path.setText(p)

    def _run_test(self):
        row = self._rule_list.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Rule", "Select a rule first.")
            return
        sample = self._sample_path.text().strip()
        if not sample or not os.path.exists(sample):
            QMessageBox.warning(self, "No Sample", "Enter a valid sample file path.")
            return
        if self._worker and self._worker.isRunning():
            return
        self._test_result.setText("Testing…")
        self._worker = _TestWorker(self._rule_files[row], sample)
        self._worker.result.connect(self._test_result.setText)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.start()
