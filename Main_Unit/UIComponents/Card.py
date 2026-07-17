import sys
from PySide6.QtWidgets import QVBoxLayout, QFrame

class Card(QFrame):
    """
    Simple card with rounded corners and background.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.setFrameShape(QFrame.NoFrame)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)