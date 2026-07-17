# SentinellicenseUI.py

from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QHBoxLayout,
)
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QIcon, QDesktopServices, QPalette, QColor

from Main_Unit.find_items import find_items
from Main_Unit.Config.Sys_Config import SYSTEM_ICON_PATH

system_ico = find_items(SYSTEM_ICON_PATH)


def style_button(btn: QPushButton, primary: bool = False):
    base = "#3e3e3e"
    accent = "#ef4444"
    accent_hover = "#f97373"
    text_primary = "#f9fafb"
    text_muted = "#e5e7eb"

    if primary:
        btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {accent};
                color: {text_primary};
                border-radius: 6px;
                padding: 6px 14px;
                border: 1px solid #7f1d1d;
                font-weight: 500;
            }}
            QPushButton:hover {{
                background-color: {accent_hover};
                border-color: #fecaca;
            }}
            QPushButton:pressed {{
                background-color: #b91c1c;
            }}
            """
        )
    else:
        btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {base};
                color: {text_muted};
                border-radius: 6px;
                padding: 6px 14px;
                border: 1px solid #525252;
            }}
            QPushButton:hover {{
                background-color: #4b4b4b;
                border-color: #737373;
            }}
            QPushButton:pressed {{
                background-color: #262626;
            }}
            """
        )


def style_line_edit(edit: QLineEdit):
    edit.setStyleSheet(
        """
        QLineEdit {
            background-color: #262626;
            color: #f9fafb;
            border-radius: 6px;
            border: 1px solid #525252;
            padding: 6px 8px;
            selection-background-color: #ef4444;
        }
        QLineEdit:focus {
            border: 1px solid #ef4444;
        }
        """
    )


def apply_dark_dialog_style(dialog: QDialog, title: str):
    dialog.setWindowTitle(title)
    dialog.setWindowIcon(QIcon(system_ico))
    dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
    dialog.setStyleSheet(
        """
        QDialog {
            background-color: #1f1f1f;
        }
        QLabel {
            color: #e5e7eb;
            font-size: 12px;
        }
        """
    )
    pal = dialog.palette()
    pal.setColor(QPalette.Window, QColor("#1f1f1f"))
    pal.setColor(QPalette.WindowText, QColor("#f9fafb"))
    dialog.setPalette(pal)


class PurchaseDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        apply_dark_dialog_style(self, "Purchase License")
        self.resize(460, 230)

        layout = QVBoxLayout()
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        title = QLabel("Purchase Sentinel License")
        title.setStyleSheet(
            "QLabel { font-size: 14px; font-weight: 600; color: #f9fafb; }"
        )
        layout.addWidget(title)

        info = QLabel(
            "You will be redirected to PayPal in your browser.\n\n"
            "Steps:\n"
            "  1. Complete the payment on PayPal.\n"
            "  2. After payment, PayPal redirects to the Sentinel\n"
            "     license page showing your key.\n"
            "  3. Copy the key and paste it into this app."
        )
        info.setWordWrap(True)
        info.setStyleSheet("QLabel { color: #9ca3af; }")
        layout.addWidget(info)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)

        self.cancel_btn = QPushButton("Cancel")
        style_button(self.cancel_btn, primary=False)
        self.cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(self.cancel_btn)

        self.open_btn = QPushButton("Proceed to Checkout")
        style_button(self.open_btn, primary=True)
        self.open_btn.clicked.connect(self.open_paypal)
        btn_row.addWidget(self.open_btn)

        layout.addLayout(btn_row)
        self.setLayout(layout)

    def open_paypal(self):
        paypal_url = QUrl("https://www.paypal.com/ncp/payment/K4G3HJ28H9PG4")
        QDesktopServices.openUrl(paypal_url)
        self.accept()


class LicenseDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        apply_dark_dialog_style(self, "Enter License Key")

        layout = QVBoxLayout()
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(10)

        title = QLabel("Activate Sentinel")
        title.setStyleSheet(
            "QLabel { font-size: 14px; font-weight: 600; color: #f9fafb; }"
        )
        layout.addWidget(title)

        info = QLabel(
            "Paste your license key below.\n"
            "If you just completed payment, copy the key from the\n"
            "Sentinel license page in your browser."
        )
        info.setWordWrap(True)
        info.setStyleSheet("QLabel { color: #9ca3af; }")
        layout.addWidget(info)

        self.edit = QLineEdit()
        self.edit.setPlaceholderText("57B41-0F99D-BD7EF-55A63-D3070")
        style_line_edit(self.edit)
        layout.addWidget(self.edit)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        self.purchase_btn = QPushButton("Purchase License")
        style_button(self.purchase_btn, primary=False)
        self.purchase_btn.clicked.connect(self.open_purchase_window)

        self.activate_btn = QPushButton("Activate")
        style_button(self.activate_btn, primary=True)
        self.activate_btn.clicked.connect(self.accept)

        btn_layout.addWidget(self.purchase_btn)
        btn_layout.addStretch(1)
        btn_layout.addWidget(self.activate_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def open_purchase_window(self):
        purchase_dialog = PurchaseDialog(self)
        purchase_dialog.exec()

    def get_license_key(self):
        return self.edit.text().strip()
