import sys
from PySide6.QtWidgets import QVBoxLayout, QPushButton, QFrame
from PySide6.QtCore import Qt

class FloatingPanel(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("FloatingPanel")
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.Popup
        )
        # Important: NO translucent background → avoids UpdateLayeredWindowIndirect issues.

        inner = QFrame(self)
        inner.setObjectName("FloatingPanelInner")

        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(10, 8, 10, 8)
        inner_layout.setSpacing(8)

        # Buttons
        self.train_btn = QPushButton("Train")
        self.train_btn.setFixedSize(186, 30)
        self.train_btn.setObjectName("trainButton")

        self.remove_btn = QPushButton("Remove IP BlockRules")
        self.remove_btn.setFixedSize(186, 30)
        self.remove_btn.setObjectName("removeButton")
        
        self.remove_antiscan_btn = QPushButton("Remove AntiScan BlockRules")
        self.remove_antiscan_btn.setFixedSize(186, 30)
        self.remove_antiscan_btn.setObjectName("removeAntiScanButton")

        inner_layout.addWidget(self.train_btn)
        inner_layout.addWidget(self.remove_btn)
        inner_layout.addWidget(self.remove_antiscan_btn)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(inner)

        # Styles (dark + subtle shadcn‑ish look)
        self.setStyleSheet("""
        #FloatingPanelInner {
            background-color: #000000;
            border-radius: 10px;
            border: transparent;
        }
        QPushButton {
            background-color: #000000;
            color: #e5e7eb;
            border: transparent;
            border-radius: 8px;
            font-size: 13px;
            padding: 4px 10px;
        }
        QPushButton:hover {
            background-color: #2d2d2d;
        }

        """)