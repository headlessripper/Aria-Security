"""VirusTotal Integration Page — lookup file hashes and URLs via VT API v3."""
from __future__ import annotations

import hashlib
import os

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QColor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit, QFrame, QMessageBox, QFileDialog,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
)

CARD = "#161b22"; BORDER = "#21262d"; SURFACE = "#0d1117"
ACCENT = "#2f81f7"; GREEN = "#3fb950"; RED = "#f85149"; ORANGE = "#d29922"
TEXT = "#e6edf3"; TEXT_DIM = "#8b949e"; TEXT_MUTED = "#484f58"

_VT_KEY_PATH = os.path.join(os.path.expanduser("~"), ".AriaSecurity", "vt_api_key.txt")


def _load_api_key() -> str:
    try:
        with open(_VT_KEY_PATH) as f:
            return f.read().strip()
    except Exception:
        return ""


def _save_api_key(key: str):
    os.makedirs(os.path.dirname(_VT_KEY_PATH), exist_ok=True)
    with open(_VT_KEY_PATH, "w") as f:
        f.write(key.strip())


def _sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class _LookupWorker(QThread):
    result = Signal(dict)
    error  = Signal(str)

    def __init__(self, query: str, query_type: str, api_key: str):
        super().__init__()
        self._query      = query
        self._query_type = query_type  # "hash", "url", "ip", "domain"
        self._api_key    = api_key

    def run(self):
        try:
            import requests
        except ImportError:
            self.error.emit("requests library not installed. Run: pip install requests")
            return

        headers = {"x-apikey": self._api_key, "accept": "application/json"}
        qt = self._query_type

        if qt == "hash":
            url = f"https://www.virustotal.com/api/v3/files/{self._query}"
        elif qt == "url":
            import base64
            url_id = base64.urlsafe_b64encode(self._query.encode()).decode().rstrip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        elif qt == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{self._query}"
        elif qt == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{self._query}"
        else:
            self.error.emit(f"Unknown query type: {qt}")
            return

        try:
            r = requests.get(url, headers=headers, timeout=20)
            if r.status_code == 200:
                self.result.emit(r.json())
            elif r.status_code == 404:
                self.error.emit("Not found in VirusTotal database.")
            elif r.status_code == 401:
                self.error.emit("Invalid API key.")
            elif r.status_code == 429:
                self.error.emit("API rate limit exceeded. Wait a minute and retry.")
            else:
                self.error.emit(f"HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            self.error.emit(str(e))


def _fmt_attrs(data: dict) -> dict:
    """Flatten the VT attributes dict into display-ready k/v pairs."""
    attrs = data.get("data", {}).get("attributes", {})
    out: dict[str, str] = {}
    stats = attrs.get("last_analysis_stats", {})
    if stats:
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        total = sum(stats.values())
        out["Detection"] = f"{mal} malicious, {sus} suspicious / {total} engines"
    if "meaningful_name" in attrs:
        out["Name"] = attrs["meaningful_name"]
    if "sha256" in attrs:
        out["SHA-256"] = attrs["sha256"]
    if "md5" in attrs:
        out["MD5"] = attrs["md5"]
    if "size" in attrs:
        out["Size"] = f"{attrs['size']:,} bytes"
    if "type_description" in attrs:
        out["Type"] = attrs["type_description"]
    if "creation_date" in attrs:
        import time
        out["Created"] = time.strftime("%Y-%m-%d", time.gmtime(attrs["creation_date"]))
    if "reputation" in attrs:
        out["Reputation"] = str(attrs["reputation"])
    if "country" in attrs:
        out["Country"] = attrs["country"]
    if "network" in attrs:
        out["Network"] = attrs["network"]
    if "last_analysis_date" in attrs:
        import time
        out["Last Scan"] = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(attrs["last_analysis_date"]))
    return out


def _engine_results(data: dict) -> list[tuple[str, str, str]]:
    """Return list of (engine, category, result) from last_analysis_results."""
    results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    rows = []
    for eng, info in results.items():
        cat    = info.get("category", "undetected")
        result = info.get("result") or "—"
        rows.append((eng, cat, result))
    rows.sort(key=lambda r: (r[1] not in ("malicious", "suspicious"), r[0]))
    return rows


class VirusTotalPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("VirusTotal Lookup")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        hdr.addWidget(title)
        hdr.addStretch()
        root.addLayout(hdr)

        # API key row
        key_card = QFrame()
        key_card.setObjectName("Card")
        kc = QHBoxLayout(key_card)
        kc.setContentsMargins(14, 10, 14, 10)
        kc.setSpacing(8)
        kc.addWidget(QLabel("API Key:"))
        self._key_input = QLineEdit(_load_api_key())
        self._key_input.setPlaceholderText("Paste your VirusTotal API key here (free tier works)…")
        self._key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._key_input.setStyleSheet(
            f"QLineEdit{{background:{SURFACE};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:6px;padding:5px 10px;font-size:12px;}}"
        )
        save_key_btn = QPushButton("Save")
        save_key_btn.setFixedWidth(60)
        save_key_btn.clicked.connect(self._save_key)
        toggle_btn = QPushButton("Show")
        toggle_btn.setFixedWidth(52)
        toggle_btn.setCheckable(True)
        toggle_btn.toggled.connect(
            lambda v: self._key_input.setEchoMode(
                QLineEdit.EchoMode.Normal if v else QLineEdit.EchoMode.Password
            )
        )
        kc.addWidget(self._key_input, 1)
        kc.addWidget(toggle_btn)
        kc.addWidget(save_key_btn)
        root.addWidget(key_card)

        # Query row
        q_card = QFrame()
        q_card.setObjectName("Card")
        qc = QHBoxLayout(q_card)
        qc.setContentsMargins(14, 10, 14, 10)
        qc.setSpacing(8)

        self._query_input = QLineEdit()
        self._query_input.setPlaceholderText("SHA256 hash, IP, domain, or URL…")
        self._query_input.setStyleSheet(
            f"QLineEdit{{background:{SURFACE};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:6px;padding:6px 10px;font-size:12px;}}"
        )
        self._query_input.returnPressed.connect(self._lookup)

        browse_btn = QPushButton("Hash File")
        browse_btn.clicked.connect(self._hash_file)
        browse_btn.setStyleSheet(
            f"QPushButton{{background:{CARD};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:6px;padding:6px 12px;font-size:12px;}}"
            f"QPushButton:hover{{background:#1c2128;}}"
        )

        lookup_btn = QPushButton("Lookup")
        lookup_btn.setStyleSheet(
            f"QPushButton{{background:{ACCENT};color:white;border:none;"
            f"border-radius:6px;padding:6px 18px;font-size:12px;font-weight:600;}}"
            f"QPushButton:hover{{background:#388bfd;}}"
        )
        lookup_btn.clicked.connect(self._lookup)

        qc.addWidget(self._query_input, 1)
        qc.addWidget(browse_btn)
        qc.addWidget(lookup_btn)
        root.addWidget(q_card)

        self._status = QLabel("Enter a hash, IP, domain, or URL above and click Lookup.")
        self._status.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        root.addWidget(self._status)

        # Results tabs
        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(f"""
            QTabWidget::pane{{border:1px solid {BORDER};border-radius:8px;background:{CARD};}}
            QTabBar::tab{{background:{SURFACE};color:{TEXT_DIM};padding:6px 16px;
                         border:1px solid {BORDER};border-bottom:none;
                         border-top-left-radius:6px;border-top-right-radius:6px;}}
            QTabBar::tab:selected{{background:{CARD};color:{TEXT};}}
        """)

        # Summary tab
        summary_widget = QWidget()
        sv = QVBoxLayout(summary_widget)
        sv.setContentsMargins(12, 12, 12, 12)
        self._summary_table = QTableWidget(0, 2)
        self._summary_table.setHorizontalHeaderLabels(["Attribute", "Value"])
        self._summary_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._summary_table.verticalHeader().setVisible(False)
        self._summary_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._summary_table.setStyleSheet(self._table_qss())
        sv.addWidget(self._summary_table)
        self._tabs.addTab(summary_widget, "Summary")

        # Engines tab
        engines_widget = QWidget()
        ev = QVBoxLayout(engines_widget)
        ev.setContentsMargins(12, 12, 12, 12)
        self._engines_table = QTableWidget(0, 3)
        self._engines_table.setHorizontalHeaderLabels(["Engine", "Category", "Result"])
        self._engines_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._engines_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._engines_table.verticalHeader().setVisible(False)
        self._engines_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._engines_table.setAlternatingRowColors(True)
        self._engines_table.setStyleSheet(self._table_qss())
        ev.addWidget(self._engines_table)
        self._tabs.addTab(engines_widget, "Engines")

        # Raw JSON tab
        self._raw = QTextEdit()
        self._raw.setReadOnly(True)
        self._raw.setStyleSheet(
            f"QTextEdit{{background:{SURFACE};color:#7ee787;"
            f"border:1px solid {BORDER};border-radius:8px;"
            f"font-family:'Consolas','Courier New',monospace;font-size:10pt;padding:8px;}}"
        )
        self._tabs.addTab(self._raw, "Raw JSON")

        root.addWidget(self._tabs, 1)

        self._worker: _LookupWorker | None = None

    @staticmethod
    def _table_qss() -> str:
        return f"""
            QTableWidget{{background:{CARD};color:{TEXT};border:1px solid {BORDER};
                border-radius:8px;gridline-color:{BORDER};
                alternate-background-color:#0d1117;}}
            QHeaderView::section{{background:{CARD};color:{TEXT_DIM};font-size:11px;
                font-weight:600;border:none;border-bottom:1px solid {BORDER};padding:6px 8px;}}
            QTableWidget::item{{padding:5px 8px;border:none;}}
            QTableWidget::item:selected{{background:{ACCENT}22;color:{TEXT};}}
        """

    def _save_key(self):
        _save_api_key(self._key_input.text())
        self._status.setText("API key saved.")

    def _hash_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select file to hash")
        if not path:
            return
        try:
            h = _sha256_of_file(path)
            self._query_input.setText(h)
            self._status.setText(f"SHA-256: {h}")
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def _detect_type(self, query: str) -> str:
        q = query.strip()
        if len(q) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in q):
            return "hash"
        if q.startswith("http://") or q.startswith("https://"):
            return "url"
        parts = q.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return "ip"
        return "domain"

    def _lookup(self):
        if self._worker and self._worker.isRunning():
            return
        api_key = self._key_input.text().strip()
        if not api_key:
            QMessageBox.warning(self, "No API Key", "Enter your VirusTotal API key first.")
            return
        query = self._query_input.text().strip()
        if not query:
            return
        qt = self._detect_type(query)
        self._status.setText(f"Looking up {qt}: {query[:60]}…")
        self._summary_table.setRowCount(0)
        self._engines_table.setRowCount(0)
        self._raw.clear()

        self._worker = _LookupWorker(query, qt, api_key)
        self._worker.result.connect(self._on_result)
        self._worker.error.connect(self._on_error)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.start()

    def _on_result(self, data: dict):
        import json
        attrs = _fmt_attrs(data)
        self._summary_table.setRowCount(0)
        for k, v in attrs.items():
            r = self._summary_table.rowCount()
            self._summary_table.insertRow(r)
            self._summary_table.setItem(r, 0, QTableWidgetItem(k))
            val_item = QTableWidgetItem(v)
            if k == "Detection":
                mal = int(v.split()[0])
                val_item.setForeground(QColor(RED if mal > 0 else GREEN))
            self._summary_table.setItem(r, 1, val_item)

        engines = _engine_results(data)
        self._engines_table.setRowCount(0)
        for eng, cat, res in engines:
            r = self._engines_table.rowCount()
            self._engines_table.insertRow(r)
            self._engines_table.setItem(r, 0, QTableWidgetItem(eng))
            cat_item = QTableWidgetItem(cat)
            if cat == "malicious":
                cat_item.setForeground(QColor(RED))
            elif cat == "suspicious":
                cat_item.setForeground(QColor(ORANGE))
            else:
                cat_item.setForeground(QColor(TEXT_DIM))
            self._engines_table.setItem(r, 1, cat_item)
            self._engines_table.setItem(r, 2, QTableWidgetItem(res))

        self._raw.setText(json.dumps(data, indent=2))

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        self._status.setText(
            f"Result: {mal}/{total} engines detected as malicious" if total else "Result loaded."
        )
        self._tabs.setCurrentIndex(0)

    def _on_error(self, msg: str):
        self._status.setText(f"Error: {msg}")
        self._raw.setText(f"Error: {msg}")
