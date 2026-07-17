from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QMessageBox, QFrame
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon
from PySide6.QtCore import QSettings

from Main_Unit.Config.Sys_Config import SYSTEM_ICON_PATH
from Main_Unit.find_items import find_items
from Main_Unit.Service.find_menu import find_menu

system_ico = find_items(SYSTEM_ICON_PATH)

class AuthTitleBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._mouse_pos = None
        self.setFixedHeight(32)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 4, 10, 4)
        layout.setSpacing(8)

        self.icon_label = QLabel()
        self.icon_label.setPixmap(QIcon(system_ico).pixmap(16, 16))

        self.title_label = QLabel("Authentication Required")
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


class AuthWidget(QWidget):
    def __init__(self, on_authenticated, parent=None):
        """
        :param on_authenticated: callable() to call when PIN is correct.
        """
        super().__init__(parent)
        self.on_authenticated = on_authenticated
        self.setWindowTitle("Authentication Required")
        self.setWindowIcon(QIcon(system_ico))
        self.resize(360, 260)

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
        self.title_bar = AuthTitleBar(self)
        container_layout.addWidget(self.title_bar)

        # Inner card
        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(16)

        # Title
        title = QLabel("Enter PIN")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(title)

        # Subtitle
        subtitle = QLabel("Enter your 6‑digit authentication PIN.")
        subtitle.setObjectName("MutedLabel")
        subtitle.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(subtitle)

        # PIN input
        self.pin_edit = QLineEdit()
        self.pin_edit.setMaxLength(6)
        self.pin_edit.setEchoMode(QLineEdit.Password)
        self.pin_edit.setInputMask("000000")
        self.pin_edit.setFont(QFont("Segoe UI", 14))
        self.pin_edit.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(self.pin_edit)

        # Submit button
        self.submit_btn = QPushButton("Unlock")
        self.submit_btn.clicked.connect(self.check_pin)
        card_layout.addWidget(self.submit_btn)

        self.pin_edit.returnPressed.connect(self.check_pin)

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

        # Initially focus PIN
        self.pin_edit.setFocus()

    def showEvent(self, event):
        """Check if auth is enabled; if not, skip auth."""
        use_auth = self.settings.value("use_authentication", False, type=bool)
        if not use_auth:
            self.on_authenticated()
            self.close()
        else:
            super().showEvent(event)

    def check_pin(self):
        stored_pin = self.settings.value("pin", "")
        entered = self.pin_edit.text().strip()

        if not stored_pin:
            QMessageBox.critical(self, "No PIN set", "Authentication is enabled but no PIN was set.")
            return

        if entered == stored_pin:
            self.on_authenticated()
            self.close()
        else:
            QMessageBox.warning(self, "Wrong PIN", "Incorrect PIN. Try again.")
            self.pin_edit.clear()
