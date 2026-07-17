"""Secure Vault Page — Fernet-encrypted file vault UI."""
from __future__ import annotations

import os
import time

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QFrame, QMessageBox,
    QFileDialog, QInputDialog, QLineEdit,
)

CARD = "#161b22"; BORDER = "#21262d"; SURFACE = "#0d1117"
ACCENT = "#2f81f7"; GREEN = "#3fb950"; RED = "#f85149"; ORANGE = "#d29922"
TEXT = "#e6edf3"; TEXT_DIM = "#8b949e"; TEXT_MUTED = "#484f58"


def _fmt_bytes(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


class SecureVaultPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        hdr = QHBoxLayout()
        title = QLabel("Secure Vault")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        hdr.addWidget(title)
        hdr.addStretch()
        self._vault_size_lbl = QLabel("")
        self._vault_size_lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        hdr.addWidget(self._vault_size_lbl)
        add_btn = QPushButton("+ Add File")
        add_btn.setStyleSheet(
            f"QPushButton{{background:{ACCENT};color:white;border:none;"
            f"border-radius:8px;padding:7px 16px;font-size:13px;font-weight:600;}}"
            f"QPushButton:hover{{background:#388bfd;}}"
        )
        add_btn.clicked.connect(self._add_file)
        hdr.addWidget(add_btn)
        root.addLayout(hdr)

        hint = QLabel(
            "Files are encrypted with AES-256 (Fernet) using your password. "
            "The original file is removed after encryption. Keep your password safe — it cannot be recovered."
        )
        hint.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        hint.setWordWrap(True)
        root.addWidget(hint)

        vault_card = QFrame()
        vault_card.setObjectName("Card")
        vc = QVBoxLayout(vault_card)
        vc.setContentsMargins(12, 12, 12, 12)
        vc.setSpacing(8)

        self._vault_list = QListWidget()
        self._vault_list.setStyleSheet(
            f"QListWidget{{background:transparent;border:none;}}"
            f"QListWidget::item{{padding:8px 6px;border-bottom:1px solid {BORDER};color:{TEXT};}}"
            f"QListWidget::item:selected{{background:{ACCENT}22;}}"
        )
        vc.addWidget(self._vault_list, 1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        extract_btn = QPushButton("Extract Selected")
        extract_btn.setStyleSheet(
            f"QPushButton{{background:{GREEN}22;color:{GREEN};border:1px solid {GREEN}44;"
            f"border-radius:8px;padding:6px 14px;font-size:12px;}}"
            f"QPushButton:hover{{background:{GREEN}44;}}"
        )
        extract_btn.clicked.connect(self._extract_file)
        del_btn = QPushButton("Permanently Delete")
        del_btn.setStyleSheet(
            f"QPushButton{{background:{RED}1a;color:{RED};border:1px solid {RED}33;"
            f"border-radius:8px;padding:6px 14px;font-size:12px;}}"
            f"QPushButton:hover{{background:{RED}33;}}"
        )
        del_btn.clicked.connect(self._delete_file)
        btn_row.addWidget(extract_btn)
        btn_row.addWidget(del_btn)
        btn_row.addStretch()
        vc.addLayout(btn_row)
        root.addWidget(vault_card, 1)

        QTimer.singleShot(200, self._refresh)

    def _refresh(self):
        self._vault_list.clear()
        try:
            from Main_Unit.Engine.Service.SentinelSecureVault import list_files, vault_size_bytes
            files = list_files()
            for entry in files:
                ts  = time.strftime("%m/%d/%y %H:%M", time.localtime(entry.get("added", 0)))
                sz  = _fmt_bytes(entry.get("size", 0))
                lbl = f"🔒  {entry['orig_name']}  •  {sz}  •  added {ts}"
                item = QListWidgetItem(lbl)
                item.setData(Qt.ItemDataRole.UserRole, entry["vault_id"])
                self._vault_list.addItem(item)
            self._vault_size_lbl.setText(f"Vault: {_fmt_bytes(vault_size_bytes())}")
        except Exception:
            pass

    def _add_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select file to encrypt and store")
        if not path:
            return
        pwd, ok = QInputDialog.getText(
            self, "Vault Password", "Enter password for this file:",
            QLineEdit.EchoMode.Password,
        )
        if not ok or not pwd:
            return
        try:
            from Main_Unit.Engine.Service.SentinelSecureVault import add
            vault_id = add(path, pwd, delete_original=True)
            self._refresh()
            QMessageBox.information(self, "Encrypted", f"File stored as vault ID: {vault_id}")
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def _extract_file(self):
        item = self._vault_list.currentItem()
        if not item:
            return
        vault_id = item.data(Qt.ItemDataRole.UserRole)
        dst = QFileDialog.getExistingDirectory(self, "Extract to directory")
        if not dst:
            return
        pwd, ok = QInputDialog.getText(
            self, "Vault Password", "Enter password:",
            QLineEdit.EchoMode.Password,
        )
        if not ok or not pwd:
            return
        try:
            from Main_Unit.Engine.Service.SentinelSecureVault import extract
            out = extract(vault_id, dst, pwd)
            QMessageBox.information(self, "Extracted", f"File restored to:\n{out}")
        except ValueError:
            QMessageBox.warning(self, "Wrong Password", "Incorrect password or corrupted vault entry.")
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def _delete_file(self):
        item = self._vault_list.currentItem()
        if not item:
            return
        vault_id = item.data(Qt.ItemDataRole.UserRole)
        reply = QMessageBox.question(
            self, "Delete Permanently",
            "Permanently delete this vault entry? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                from Main_Unit.Engine.Service.SentinelSecureVault import delete
                delete(vault_id)
                self._refresh()
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))
