import sys

from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
)
from PySide6.QtCore import (
    Qt,
    QTimer,
)


class Notify(QWidget):
    def __init__(self, message, duration=3000, parent=None):
        if parent is None or not parent.isVisible():
            parent = QApplication.activeWindow()  # Fallback

        # parent as first arg, window flags as second (no 'flags=' kwarg)
        super().__init__(parent, Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool)

        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)

        self.label = QLabel(message, self)
        self.label.setStyleSheet("""
            QLabel {
                background-color: #333333;
                color: #ffffff;
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
                padding: 10px 20px;
                border-radius: 8px;
            }
        """)
        self.label.adjustSize()
        self.resize(self.label.size())

        # Center on parent if given, else center on screen
        if parent:
            parent_rect = parent.geometry()
            self.move(
                parent_rect.center().x() - self.width() // 2,
                parent_rect.top() + 50
            )
        else:
            screen = self.screen().geometry()
            self.move(
                screen.center().x() - self.width() // 2,
                50
            )

        QTimer.singleShot(duration, self.close)
        self.show()
