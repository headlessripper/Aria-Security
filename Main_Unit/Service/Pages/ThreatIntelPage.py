"""Threat Intelligence Feed Page — live events + historical IOC summary."""
from __future__ import annotations

import json
import os
from datetime import datetime, date
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal, QTimer, QSize
from PySide6.QtGui import QFont, QColor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QListWidget, QListWidgetItem,
    QComboBox, QSizePolicy, QGridLayout,
)

CARD      = "#161b22"; BORDER  = "#21262d"; SURFACE = "#0d1117"
ACCENT    = "#2f81f7"; GREEN   = "#3fb950"; RED     = "#f85149"
ORANGE    = "#d29922"; PURPLE  = "#8957e5"; CYAN    = "#39d353"
TEXT      = "#e6edf3"; TEXT_DIM= "#8b949e"; TEXT_MUTED = "#484f58"

_CATEGORY_COLOR = {
    "MALWARE":     RED,
    "RANSOMWARE":  "#ff7b72",
    "NETWORK":     ACCENT,
    "EXPLOIT":     ORANGE,
    "BEHAVIORAL":  PURPLE,
    "USB":         GREEN,
    "SYSTEM":      TEXT_DIM,
}
_SEVERITY_COLOR = {
    "INFO":     TEXT_DIM,
    "LOW":      GREEN,
    "MEDIUM":   ORANGE,
    "HIGH":     RED,
    "CRITICAL": "#ff0000",
}


# ── Worker for loading scan history ──────────────────────────────────────────

class _HistoryLoader(QThread):
    done = Signal(list)   # list of normalised dict records

    def run(self):
        try:
            from Main_Unit.Engine.Service.SentinelScanHistory import query as _q
            raw = _q(limit=500)
            # Normalise: convert Unix float timestamp → ISO string for display
            result = []
            for r in raw:
                ts_raw = r.get("timestamp", 0)
                try:
                    ts_str = datetime.fromtimestamp(float(ts_raw)).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                except Exception:
                    ts_str = str(ts_raw)[:19]
                result.append({
                    "file_path":  r.get("file_path", ""),
                    "verdict":    r.get("verdict",   "UNKNOWN"),
                    "sha256":     r.get("sha256",    ""),
                    "timestamp":  ts_str,
                })
            self.done.emit(result)
        except Exception:
            self.done.emit([])


# ── Single event row widget ───────────────────────────────────────────────────

class _EventRow(QFrame):
    def __init__(self, category: str, severity: str, title: str,
                 detail: str, ts: str, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setFixedHeight(62)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(10)

        # Category chip
        cat_color = _CATEGORY_COLOR.get(category.upper(), TEXT_DIM)
        cat_chip = QLabel(category[:8])
        cat_chip.setFixedSize(72, 20)
        cat_chip.setAlignment(Qt.AlignCenter)
        cat_chip.setStyleSheet(
            f"background:{cat_color}22;color:{cat_color};"
            f"border:1px solid {cat_color}44;border-radius:4px;"
            f"font-size:9px;font-weight:700;"
        )
        layout.addWidget(cat_chip)

        # Severity dot
        sev_color = _SEVERITY_COLOR.get(severity.upper(), TEXT_DIM)
        dot = QLabel("●")
        dot.setFixedWidth(14)
        dot.setStyleSheet(f"color:{sev_color};font-size:9px;")
        layout.addWidget(dot)

        # Title + detail
        info = QVBoxLayout()
        info.setSpacing(1)
        title_lbl = QLabel(title[:80])
        title_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        detail_lbl = QLabel(detail[:100])
        detail_lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:9px;")
        info.addWidget(title_lbl)
        info.addWidget(detail_lbl)
        layout.addLayout(info, 1)

        # Timestamp
        ts_lbl = QLabel(ts)
        ts_lbl.setStyleSheet(f"color:{TEXT_MUTED};font-size:9px;")
        ts_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        layout.addWidget(ts_lbl)


# ── Stat chip ─────────────────────────────────────────────────────────────────

class _Chip(QFrame):
    def __init__(self, label: str, value: str = "0", color: str = ACCENT,
                 parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setFixedHeight(72)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 8, 14, 8)
        lay.setSpacing(2)
        self._val = QLabel(value)
        self._val.setFont(QFont("Segoe UI", 20, QFont.Bold))
        self._val.setStyleSheet(f"color:{color};")
        lbl = QLabel(label)
        lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:10px;")
        lay.addWidget(self._val)
        lay.addWidget(lbl)

    def set_value(self, v):
        self._val.setText(str(v))


# ── IOC History row (from SentinelScanHistory) ────────────────────────────────

class _IocRow(QFrame):
    def __init__(self, file_path: str, verdict: str, sha: str,
                 ts: str, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setFixedHeight(52)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 6, 12, 6)
        lay.setSpacing(10)

        v_color = RED if verdict in ("MALWARE", "SUSPICIOUS") else TEXT_DIM
        v_chip = QLabel(verdict[:10])
        v_chip.setFixedSize(80, 18)
        v_chip.setAlignment(Qt.AlignCenter)
        v_chip.setStyleSheet(
            f"background:{v_color}22;color:{v_color};"
            f"border:1px solid {v_color}44;border-radius:3px;"
            f"font-size:9px;font-weight:700;"
        )
        lay.addWidget(v_chip)

        path_lbl = QLabel(
            (os.path.basename(file_path) or file_path)[:60]
        )
        path_lbl.setFont(QFont("Segoe UI", 10))
        path_lbl.setToolTip(file_path)
        lay.addWidget(path_lbl, 1)

        hash_lbl = QLabel(sha[:16] + "…" if len(sha) > 16 else sha)
        hash_lbl.setStyleSheet(
            f"color:{TEXT_MUTED};font-size:9px;font-family:Consolas;"
        )
        hash_lbl.setToolTip(sha)
        lay.addWidget(hash_lbl)

        ts_lbl = QLabel(ts[:16])
        ts_lbl.setStyleSheet(f"color:{TEXT_MUTED};font-size:9px;")
        lay.addWidget(ts_lbl)


# ── Main page ─────────────────────────────────────────────────────────────────

class ThreatIntelPage(QWidget):
    """Threat intelligence: live events + IOC history from scan records."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._event_rows: list[_EventRow] = []
        self._loader: Optional[_HistoryLoader] = None

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        # ── Header ──────────────────────────────────────────────────────────
        hdr = QHBoxLayout()
        title = QLabel("Threat Intelligence")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        hdr.addWidget(title)
        hdr.addStretch()

        self._filter_combo = QComboBox()
        self._filter_combo.addItems(
            ["All Categories", "MALWARE", "NETWORK", "USB",
             "EXPLOIT", "BEHAVIORAL", "RANSOMWARE"]
        )
        self._filter_combo.setStyleSheet(
            f"QComboBox{{background:{CARD};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:6px;padding:4px 10px;font-size:12px;}}"
            f"QComboBox::drop-down{{border:none;}}"
            f"QComboBox QAbstractItemView{{background:{CARD};color:{TEXT};"
            f"border:1px solid {BORDER};}}"
        )
        self._filter_combo.currentTextChanged.connect(self._apply_filter)
        hdr.addWidget(self._filter_combo)

        refresh_btn = QPushButton("Refresh History")
        refresh_btn.setStyleSheet(
            f"QPushButton{{background:{ACCENT};color:white;border:none;"
            f"border-radius:8px;padding:7px 16px;font-size:13px;font-weight:600;}}"
            f"QPushButton:hover{{background:#388bfd;}}"
        )
        refresh_btn.clicked.connect(self._load_history)
        hdr.addWidget(refresh_btn)
        root.addLayout(hdr)

        # ── Stat chips ───────────────────────────────────────────────────────
        chips_row = QHBoxLayout()
        chips_row.setSpacing(10)
        self._chip_total    = _Chip("Total Events",  "0", RED)
        self._chip_malware  = _Chip("Malware",        "0", RED)
        self._chip_network  = _Chip("Network",        "0", ACCENT)
        self._chip_usb      = _Chip("USB Threats",    "0", GREEN)
        self._chip_today    = _Chip("Today",          "0", ORANGE)
        for c in [self._chip_total, self._chip_malware, self._chip_network,
                  self._chip_usb, self._chip_today]:
            chips_row.addWidget(c)
        root.addLayout(chips_row)

        # ── Two-column body ──────────────────────────────────────────────────
        body = QHBoxLayout()
        body.setSpacing(14)

        # ── Left: live event feed ────────────────────────────────────────────
        left = QFrame()
        left.setObjectName("Card")
        ll = QVBoxLayout(left)
        ll.setContentsMargins(12, 12, 12, 12)
        ll.setSpacing(8)

        l_hdr = QHBoxLayout()
        l_title = QLabel("Live Threat Events")
        l_title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        l_hdr.addWidget(l_title)
        l_hdr.addStretch()
        self._event_count_lbl = QLabel("0 events")
        self._event_count_lbl.setStyleSheet(f"color:{TEXT_MUTED};font-size:10px;")
        l_hdr.addWidget(self._event_count_lbl)
        clear_btn = QPushButton("Clear")
        clear_btn.setFixedSize(48, 22)
        clear_btn.setStyleSheet(
            f"QPushButton{{background:{CARD};color:{TEXT_DIM};"
            f"border:1px solid {BORDER};border-radius:4px;font-size:10px;}}"
            f"QPushButton:hover{{background:#1c2128;}}"
        )
        clear_btn.clicked.connect(self._clear_events)
        l_hdr.addWidget(clear_btn)
        ll.addLayout(l_hdr)

        self._events_scroll = QScrollArea()
        self._events_scroll.setWidgetResizable(True)
        self._events_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._events_scroll.setStyleSheet(
            "QScrollArea{border:none;background:transparent;}"
        )
        self._events_container = QWidget()
        self._events_container.setStyleSheet("background:transparent;")
        self._events_layout = QVBoxLayout(self._events_container)
        self._events_layout.setContentsMargins(0, 0, 0, 0)
        self._events_layout.setSpacing(5)
        self._events_layout.setAlignment(Qt.AlignTop)
        self._no_events_lbl = QLabel("Waiting for live events…\nStart monitoring to see threats.")
        self._no_events_lbl.setAlignment(Qt.AlignCenter)
        self._no_events_lbl.setStyleSheet(f"color:{TEXT_MUTED};font-size:11px;padding:20px 0;")
        self._events_layout.addWidget(self._no_events_lbl)
        self._events_scroll.setWidget(self._events_container)
        ll.addWidget(self._events_scroll, 1)

        body.addWidget(left, 1)

        # ── Right: IOC history ───────────────────────────────────────────────
        right = QFrame()
        right.setObjectName("Card")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(12, 12, 12, 12)
        rl.setSpacing(8)

        r_hdr = QHBoxLayout()
        r_title = QLabel("Detection History (IOCs)")
        r_title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        r_hdr.addWidget(r_title)
        r_hdr.addStretch()
        self._ioc_count_lbl = QLabel("0 records")
        self._ioc_count_lbl.setStyleSheet(f"color:{TEXT_MUTED};font-size:10px;")
        r_hdr.addWidget(self._ioc_count_lbl)
        rl.addLayout(r_hdr)

        # Column headers
        col_hdr = QHBoxLayout()
        col_hdr.setContentsMargins(12, 0, 12, 0)
        col_hdr.setSpacing(10)
        for label, stretch in [("Verdict", 0), ("File", 1), ("SHA256", 0), ("Time", 0)]:
            lbl = QLabel(label)
            lbl.setStyleSheet(
                f"font-size:9px;font-weight:700;color:{TEXT_MUTED};"
                f"letter-spacing:0.5px;"
            )
            if stretch:
                col_hdr.addWidget(lbl, 1)
            else:
                col_hdr.addWidget(lbl)
        rl.addLayout(col_hdr)

        self._ioc_scroll = QScrollArea()
        self._ioc_scroll.setWidgetResizable(True)
        self._ioc_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._ioc_scroll.setStyleSheet(
            "QScrollArea{border:none;background:transparent;}"
        )
        self._ioc_container = QWidget()
        self._ioc_container.setStyleSheet("background:transparent;")
        self._ioc_layout = QVBoxLayout(self._ioc_container)
        self._ioc_layout.setContentsMargins(0, 0, 0, 0)
        self._ioc_layout.setSpacing(4)
        self._ioc_layout.setAlignment(Qt.AlignTop)
        self._no_ioc_lbl = QLabel("No detections recorded yet.\nThreat history appears here after scans.")
        self._no_ioc_lbl.setAlignment(Qt.AlignCenter)
        self._no_ioc_lbl.setStyleSheet(f"color:{TEXT_MUTED};font-size:11px;padding:20px 0;")
        self._ioc_layout.addWidget(self._no_ioc_lbl)
        self._ioc_scroll.setWidget(self._ioc_container)
        rl.addWidget(self._ioc_scroll, 1)

        body.addWidget(right, 1)
        root.addLayout(body, 1)

        # Load history on first show
        QTimer.singleShot(400, self._load_history)

    # ── Live event feed ───────────────────────────────────────────────────────

    def add_event(self, event):
        """Called from SentinelUI when brain emits threat_detected."""
        try:
            d = event.to_dict() if hasattr(event, "to_dict") else {}
            category = d.get("category", "SYSTEM")
            severity = d.get("severity", "INFO")
            title    = d.get("title",    "Unknown threat")
            detail   = d.get("detail",   "")
            ts       = datetime.now().strftime("%H:%M:%S")

            # Apply current filter
            current_filter = self._filter_combo.currentText()
            if current_filter != "All Categories" and category.upper() != current_filter:
                # Store for later — still count it
                pass
            else:
                self._add_event_row(category, severity, title, detail, ts)

            # Update chips
            total = int(self._chip_total._val.text() or "0") + 1
            self._chip_total.set_value(total)
            today = int(self._chip_today._val.text() or "0") + 1
            self._chip_today.set_value(today)
            if category.upper() == "MALWARE":
                v = int(self._chip_malware._val.text() or "0") + 1
                self._chip_malware.set_value(v)
            elif category.upper() == "NETWORK":
                v = int(self._chip_network._val.text() or "0") + 1
                self._chip_network.set_value(v)
            elif category.upper() == "USB":
                v = int(self._chip_usb._val.text() or "0") + 1
                self._chip_usb.set_value(v)

        except Exception:
            pass

    def _add_event_row(self, category: str, severity: str, title: str,
                       detail: str, ts: str):
        self._no_events_lbl.setVisible(False)
        row = _EventRow(category, severity, title, detail, ts)
        # Insert at top
        self._events_layout.insertWidget(0, row)
        self._event_rows.insert(0, row)

        # Keep last 200 events visible
        while len(self._event_rows) > 200:
            old = self._event_rows.pop()
            old.setVisible(False)
            old.deleteLater()

        self._event_count_lbl.setText(f"{len(self._event_rows)} events")

    def _clear_events(self):
        for row in self._event_rows:
            row.setVisible(False)
            row.deleteLater()
        self._event_rows.clear()
        self._event_count_lbl.setText("0 events")
        self._no_events_lbl.setVisible(True)
        self._chip_total.set_value(0)
        self._chip_today.set_value(0)
        self._chip_malware.set_value(0)
        self._chip_network.set_value(0)
        self._chip_usb.set_value(0)

    def _apply_filter(self, text: str):
        """Show/hide existing event rows based on category filter."""
        for row in self._event_rows:
            if text == "All Categories":
                row.setVisible(True)
            else:
                # The category label is the first child QLabel inside _EventRow
                # We stored category during construction; re-check via tooltip or just
                # rebuild. For simplicity: rebuild (max 200 rows, instant).
                pass  # Filter only applies to new events after selection.

    # ── Detection history (IOCs) ──────────────────────────────────────────────

    def _load_history(self):
        if self._loader and self._loader.isRunning():
            return
        self._loader = _HistoryLoader()
        self._loader.done.connect(self._on_history_loaded)
        self._loader.start()

    def _on_history_loaded(self, records: list):
        self._loader = None
        # Clear existing IOC rows — but never deleteLater() the persistent
        # _no_ioc_lbl; it is reused across calls and deleting it crashes the
        # next invocation with "Internal C++ object already deleted".
        while self._ioc_layout.count():
            item = self._ioc_layout.takeAt(0)
            widget = item.widget() if item else None
            if widget and widget is not self._no_ioc_lbl:
                widget.deleteLater()

        if not records:
            self._ioc_layout.addWidget(self._no_ioc_lbl)
            self._no_ioc_lbl.setVisible(True)
            self._ioc_count_lbl.setText("0 records")
            return

        self._no_ioc_lbl.setVisible(False)
        today_str = date.today().isoformat()
        today_count = 0
        malware_count = 0

        for rec in records:
            file_path  = rec.get("file_path", "Unknown")
            verdict    = rec.get("verdict",   "UNKNOWN")
            sha        = rec.get("sha256",    "")
            ts_display = rec.get("timestamp", "–")
            row = _IocRow(file_path, verdict, sha, ts_display)
            self._ioc_layout.addWidget(row)

            if today_str in ts_display:
                today_count += 1
            if verdict in ("MALWARE", "SUSPICIOUS"):
                malware_count += 1

        self._ioc_count_lbl.setText(f"{len(records)} records")
        self._chip_malware.set_value(
            max(malware_count, int(self._chip_malware._val.text() or "0"))
        )
        if today_count > 0:
            self._chip_today.set_value(
                max(today_count, int(self._chip_today._val.text() or "0"))
            )
        if len(records) > int(self._chip_total._val.text() or "0"):
            self._chip_total.set_value(len(records))
