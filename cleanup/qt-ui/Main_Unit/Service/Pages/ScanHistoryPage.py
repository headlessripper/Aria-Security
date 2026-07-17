"""Scan History Page — searchable, filterable SQLite-backed event log."""
from __future__ import annotations

import os
import time

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QColor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QMessageBox,
)

BG      = "#080c10"; CARD = "#161b22"; BORDER = "#21262d"
ACCENT  = "#2f81f7"; GREEN = "#3fb950"; ORANGE = "#d29922"
RED     = "#f85149"; TEXT = "#e6edf3"; TEXT_DIM = "#8b949e"
TEXT_MUTED = "#484f58"

VERDICT_COLOR = {"MALWARE": RED, "SUSPICIOUS": ORANGE, "CLEAN": GREEN, "IGNORED": TEXT_MUTED}


class _LoadWorker(QThread):
    done = Signal(list)

    def __init__(self, verdict_filter, search):
        super().__init__()
        self._vf = verdict_filter
        self._s  = search

    def run(self):
        try:
            from Main_Unit.Engine.Service.SentinelScanHistory import query
            rows = query(limit=500, verdict_filter=self._vf or None, search=self._s or None)
            self.done.emit(rows)
        except Exception:
            self.done.emit([])


class ScanHistoryPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("Scan History")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        hdr.addWidget(title)
        hdr.addStretch()
        self._stats_lbl = QLabel("Loading…")
        self._stats_lbl.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        hdr.addWidget(self._stats_lbl)
        root.addLayout(hdr)

        # Filter bar
        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Search by filename…")
        self._search.setStyleSheet(
            f"QLineEdit{{background:{CARD};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:8px;padding:6px 10px;font-size:12px;}}"
        )
        self._search.textChanged.connect(self._on_filter_changed)

        self._verdict_cb = QComboBox()
        self._verdict_cb.addItems(["All Verdicts", "MALWARE", "SUSPICIOUS", "CLEAN", "IGNORED"])
        self._verdict_cb.setStyleSheet(
            f"QComboBox{{background:{CARD};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:8px;padding:5px 10px;font-size:12px;}}"
            f"QComboBox::drop-down{{border:none;}}"
            f"QComboBox QAbstractItemView{{background:{CARD};color:{TEXT};border:1px solid {BORDER};}}"
        )
        self._verdict_cb.currentIndexChanged.connect(self._on_filter_changed)

        clear_btn = QPushButton("Clear History")
        clear_btn.setStyleSheet(
            f"QPushButton{{background:{RED}1a;color:{RED};border:1px solid {RED}33;"
            f"border-radius:8px;padding:6px 14px;font-size:12px;}}"
            f"QPushButton:hover{{background:{RED}33;}}"
        )
        clear_btn.clicked.connect(self._clear_history)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setStyleSheet(
            f"QPushButton{{background:{CARD};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:8px;padding:6px 14px;font-size:12px;}}"
            f"QPushButton:hover{{background:#1c2128;}}"
        )
        refresh_btn.clicked.connect(self._load)

        filter_row.addWidget(self._search, 1)
        filter_row.addWidget(self._verdict_cb)
        filter_row.addWidget(refresh_btn)
        filter_row.addWidget(clear_btn)
        root.addLayout(filter_row)

        # Table
        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(
            ["Time", "File", "Verdict", "ML", "YARA Hits", "LLM"]
        )
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet(f"""
            QTableWidget {{
                background:{CARD}; color:{TEXT}; border:1px solid {BORDER};
                border-radius:8px; gridline-color:{BORDER};
                alternate-background-color:#0d1117;
            }}
            QHeaderView::section {{
                background:{CARD}; color:{TEXT_DIM}; font-size:11px;
                font-weight:600; border:none; border-bottom:1px solid {BORDER};
                padding:6px 8px;
            }}
            QTableWidget::item {{ padding:6px 8px; border:none; }}
            QTableWidget::item:selected {{ background:{ACCENT}22; color:{TEXT}; }}
        """)
        root.addWidget(self._table, 1)

        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(300)
        self._debounce.timeout.connect(self._load)

        self._worker: _LoadWorker | None = None
        QTimer.singleShot(200, self._load)

    def _on_filter_changed(self):
        self._debounce.start()

    def _load(self):
        if self._worker and self._worker.isRunning():
            return
        vf = self._verdict_cb.currentText()
        vf = None if vf == "All Verdicts" else vf
        self._worker = _LoadWorker(vf, self._search.text().strip())
        self._worker.done.connect(self._populate)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.start()

    def _populate(self, rows: list[dict]):
        self._table.setRowCount(0)
        for row in rows:
            r = self._table.rowCount()
            self._table.insertRow(r)

            ts_str = time.strftime("%m/%d %H:%M:%S", time.localtime(row.get("timestamp", 0)))
            fname  = os.path.basename(row.get("file_path", ""))
            verdict = row.get("verdict", "")
            ml_str  = f"{row.get('ml_label','')} {row.get('ml_conf','')}%".strip(" %")
            yara    = row.get("yara_hits") or "—"
            llm     = row.get("llm_verdict") or "—"

            items = [ts_str, row.get("file_path",""), verdict, ml_str, yara, llm]
            for col, val in enumerate(items):
                item = QTableWidgetItem(str(val) if val else "—")
                item.setToolTip(str(val))
                if col == 2:
                    color = VERDICT_COLOR.get(verdict, TEXT_DIM)
                    item.setForeground(QColor(color))
                    font = QFont("Segoe UI", 10, QFont.Weight.Bold)
                    item.setFont(font)
                self._table.setItem(r, col, item)

        # Update stats
        total = len(rows)
        threats = sum(1 for r in rows if r.get("verdict") == "MALWARE")
        self._stats_lbl.setText(f"{total} events  •  {threats} threats")

    def _clear_history(self):
        reply = QMessageBox.question(
            self, "Clear History",
            "Delete all scan history records?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                from Main_Unit.Engine.Service.SentinelScanHistory import clear
                clear()
                self._load()
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

    def refresh(self):
        self._load()
