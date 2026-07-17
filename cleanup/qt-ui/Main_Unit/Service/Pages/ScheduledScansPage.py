"""Scheduled Scans Page — add/remove/toggle cron-style scan schedules."""
from __future__ import annotations

import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QComboBox, QListWidget, QListWidgetItem,
    QFrame, QMessageBox, QFileDialog, QDialog, QDialogButtonBox,
    QDoubleSpinBox, QFormLayout,
)

BG      = "#080c10"; CARD = "#161b22"; BORDER = "#21262d"
ACCENT  = "#2f81f7"; GREEN = "#3fb950"; ORANGE = "#d29922"
RED     = "#f85149"; TEXT = "#e6edf3"; TEXT_DIM = "#8b949e"
TEXT_MUTED = "#484f58"


class _AddDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New Scheduled Scan")
        self.setMinimumWidth(400)
        self.setStyleSheet(f"""
            QDialog{{background:{CARD};}}
            QLabel{{color:{TEXT};}}
            QLineEdit,QDoubleSpinBox{{
                background:#0d1117;color:{TEXT};border:1px solid {BORDER};
                border-radius:6px;padding:5px 8px;font-size:12px;
            }}
            QPushButton{{
                background:{CARD};color:{TEXT};border:1px solid {BORDER};
                border-radius:6px;padding:6px 14px;font-size:12px;
            }}
            QPushButton:hover{{background:#1c2128;}}
        """)

        form = QFormLayout(self)
        form.setContentsMargins(20, 20, 20, 20)
        form.setSpacing(12)

        self._label = QLineEdit()
        self._label.setPlaceholderText("e.g. Daily Downloads scan")

        self._path = QLineEdit()
        self._path.setPlaceholderText("C:\\Users\\…")
        browse = QPushButton("Browse")
        browse.clicked.connect(self._browse)
        path_row = QHBoxLayout()
        path_row.addWidget(self._path, 1)
        path_row.addWidget(browse)

        self._interval = QDoubleSpinBox()
        self._interval.setRange(0.5, 720)
        self._interval.setValue(24)
        self._interval.setSuffix(" hours")
        self._interval.setSingleStep(1)

        form.addRow("Label:", self._label)
        form.addRow("Scan Path:", path_row)
        form.addRow("Interval:", self._interval)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        form.addRow(btns)

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "Select directory to scan")
        if d:
            self._path.setText(d)

    def values(self):
        return self._label.text().strip(), self._path.text().strip(), self._interval.value()


class ScheduledScansPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        hdr = QHBoxLayout()
        title = QLabel("Scheduled Scans")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        hdr.addWidget(title)
        hdr.addStretch()
        add_btn = QPushButton("+ New Schedule")
        add_btn.setStyleSheet(
            f"QPushButton{{background:{ACCENT};color:white;border:none;"
            f"border-radius:8px;padding:7px 16px;font-size:13px;font-weight:600;}}"
            f"QPushButton:hover{{background:#388bfd;}}"
        )
        add_btn.clicked.connect(self._add)
        hdr.addWidget(add_btn)
        root.addLayout(hdr)

        hint = QLabel("Scans run automatically at the configured interval while Sentinel is active.")
        hint.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        root.addWidget(hint)

        self._list = QListWidget()
        self._list.setStyleSheet(f"""
            QListWidget{{
                background:{CARD};border:1px solid {BORDER};border-radius:10px;
                padding:4px;
            }}
            QListWidget::item{{
                border-bottom:1px solid {BORDER};padding:0px;color:{TEXT};
            }}
            QListWidget::item:selected{{background:{ACCENT}22;}}
        """)
        root.addWidget(self._list, 1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self._toggle_btn = QPushButton("Enable / Disable")
        self._toggle_btn.setStyleSheet(
            f"QPushButton{{background:{CARD};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:8px;padding:6px 14px;font-size:12px;}}"
            f"QPushButton:hover{{background:#1c2128;}}"
        )
        self._toggle_btn.clicked.connect(self._toggle_selected)
        del_btn = QPushButton("Remove")
        del_btn.setStyleSheet(
            f"QPushButton{{background:{RED}1a;color:{RED};border:1px solid {RED}33;"
            f"border-radius:8px;padding:6px 14px;font-size:12px;}}"
            f"QPushButton:hover{{background:{RED}33;}}"
        )
        del_btn.clicked.connect(self._remove_selected)
        btn_row.addWidget(self._toggle_btn)
        btn_row.addWidget(del_btn)
        btn_row.addStretch()
        root.addLayout(btn_row)

        QTimer.singleShot(100, self._refresh)

    def _refresh(self):
        self._list.clear()
        try:
            from Main_Unit.Engine.Service.SentinelScheduler import load_schedules
            for sched in load_schedules():
                enabled = sched.get("enabled", True)
                nxt = sched.get("next_run", 0)
                nxt_str = time.strftime("%m/%d %H:%M", time.localtime(nxt)) if nxt else "—"
                ih = sched.get("interval_hours", 24)
                label_txt = (
                    f"{'✅' if enabled else '⏸'}  {sched.get('label','Unnamed')}  •  "
                    f"{sched.get('scan_path','?')}  •  every {ih}h  •  next: {nxt_str}"
                )
                item = QListWidgetItem(label_txt)
                item.setData(Qt.ItemDataRole.UserRole, sched["id"])
                item.setSizeHint(__import__('PySide6.QtCore', fromlist=['QSize']).QSize(0, 44))
                self._list.addItem(item)
        except Exception:
            pass

    def _add(self):
        dlg = _AddDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        label, path, interval = dlg.values()
        if not label or not path:
            QMessageBox.warning(self, "Invalid", "Label and path are required.")
            return
        try:
            from Main_Unit.Engine.Service.SentinelScheduler import add_schedule
            add_schedule(label, path, interval)
            self._refresh()
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def _selected_id(self) -> str | None:
        item = self._list.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _toggle_selected(self):
        sid = self._selected_id()
        if not sid:
            return
        try:
            from Main_Unit.Engine.Service.SentinelScheduler import load_schedules, toggle_schedule
            scheds = load_schedules()
            current = next((s for s in scheds if s["id"] == sid), None)
            if current:
                toggle_schedule(sid, not current.get("enabled", True))
                self._refresh()
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def _remove_selected(self):
        sid = self._selected_id()
        if not sid:
            return
        reply = QMessageBox.question(
            self, "Remove Schedule", "Remove this scheduled scan?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                from Main_Unit.Engine.Service.SentinelScheduler import remove_schedule
                remove_schedule(sid)
                self._refresh()
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))
