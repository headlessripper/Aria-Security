from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QCheckBox, QMessageBox,
    QFrame
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon
from PySide6.QtCore import QSettings

from Main_Unit.Config.Sys_Config import SYSTEM_ICON_PATH
from Main_Unit.find_items import find_items
from Main_Unit.Service.find_menu import find_menu

system_ico = find_items(SYSTEM_ICON_PATH)


class TitleBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._mouse_pos = None
        self.setFixedHeight(32)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 4, 10, 4)
        layout.setSpacing(8)

        self.icon_label = QLabel()
        self.icon_label.setPixmap(QIcon(system_ico).pixmap(16, 16))

        self.title_label = QLabel("Authentication Setup")
        self.title_label.setObjectName("TitleLabel")

        self.close_btn = QPushButton("✕")
        self.close_btn.setFixedSize(28, 22)
        self.close_btn.clicked.connect(self.window().close)

        layout.addWidget(self.icon_label)
        layout.addWidget(self.title_label)
        layout.addStretch()
        layout.addWidget(self.close_btn)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._mouse_pos = event.globalPosition().toPoint()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._mouse_pos is not None:
            delta = event.globalPosition().toPoint() - self._mouse_pos
            self.window().move(self.window().pos() + delta)
            self._mouse_pos = event.globalPosition().toPoint()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        self._mouse_pos = None
        super().mouseReleaseEvent(event)


class PinSetupWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Authentication Setup")
        self.resize(400, 340)

        # Frameless + rounded corners
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        self.settings = QSettings("AriaSecurity", "SentinelAuthentication")

        # Root layout (outer transparent, inner rounded card)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)

        container = QFrame()
        container.setObjectName("Container")
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(0)

        # Custom title bar
        self.title_bar = TitleBar(self)
        container_layout.addWidget(self.title_bar)

        # Inner card (content)
        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(16)

        # Title
        title = QLabel("Set Authentication PIN")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(title)

        # PIN input
        pin_layout = QHBoxLayout()
        pin_label = QLabel("6‑digit PIN:")
        self.pin_edit = QLineEdit()
        self.pin_edit.setMaxLength(6)
        self.pin_edit.setEchoMode(QLineEdit.Password)      # fully hidden
        self.pin_edit.setInputMask("000000")
        pin_layout.addWidget(pin_label)
        pin_layout.addWidget(self.pin_edit)
        card_layout.addLayout(pin_layout)

        # Confirm PIN
        confirm_layout = QHBoxLayout()
        confirm_label = QLabel("Confirm PIN:")
        self.confirm_edit = QLineEdit()
        self.confirm_edit.setMaxLength(6)
        self.confirm_edit.setEchoMode(QLineEdit.Password)  # fully hidden
        self.confirm_edit.setInputMask("000000")
        confirm_layout.addWidget(confirm_label)
        confirm_layout.addWidget(self.confirm_edit)
        card_layout.addLayout(confirm_layout)

        # Use auth toggle
        self.use_auth_check = QCheckBox("Enable authentication on startup")
        card_layout.addWidget(self.use_auth_check)

        # Save button
        self.save_btn = QPushButton("Save & Close")
        self.save_btn.clicked.connect(self.save_settings)
        card_layout.addWidget(self.save_btn)

        container_layout.addWidget(card)
        root.addWidget(container)

        # Styles
        self.setStyleSheet("""
        QWidget#Container {
            background-color: #2d2d2d;
            border-radius: 12px;
        }
        QFrame#Card {
            background-color: #2d2d2d;
            border: 1px solid #000000;
            border-radius: 12px;
        }
        QLabel#TitleLabel {
            font-size: 13px;
            font-weight: 600;
            color: #f9fafb;
        }
        QLabel#HeaderTitleLabel {
            font-size: 16px;
            font-weight: 600;
            color: #f9fafb;
        }
        QLabel#MutedLabel {
            color: #9ca3af;
            font-size: 11px;
        }
        QLabel {
            font-size: 13px;
            color: #e5e7eb;
        }
        QPushButton {
            background-color: #000000;
            color: #f9fafb;
            border-radius: 6px;
            padding: 6px 14px;
            border: transparent;
        }
        QPushButton:hover {
            background-color: #1d1d1d;
        }
        QPushButton:pressed {
            background-color: #ffffff;
            color: #000000;
        }
        QPushButton#CloseButton {
            background-color: transparent;
            border-radius: 4px;
            padding: 0;
            min-width: 0;
        }
        QPushButton#CloseButton:hover {
            background-color: #ef4444;
            color: #ffffff;
        }
        """)


        self.load_settings()

    def load_settings(self):
        """Load saved PIN and use‑auth flag."""
        use_auth = self.settings.value("use_authentication", False, type=bool)
        self.use_auth_check.setChecked(use_auth)

    def save_settings(self):
        pin = self.pin_edit.text().strip()
        confirm = self.confirm_edit.text().strip()

        if not pin or len(pin) != 6:
            QMessageBox.warning(self, "Invalid PIN", "Please enter a 6‑digit PIN.")
            return

        if pin != confirm:
            QMessageBox.warning(self, "Mismatch", "PINs do not match.")
            return

        # Save
        self.settings.setValue("use_authentication", self.use_auth_check.isChecked())
        self.settings.setValue("pin", pin)
        self.settings.sync()

        QMessageBox.information(self, "Success", "Authentication settings saved.")
        self.close()
