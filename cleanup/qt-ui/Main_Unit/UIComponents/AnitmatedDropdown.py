import sys
from PySide6.QtWidgets import QToolButton
from PySide6.QtCore import Qt, QPoint, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QIcon
from Main_Unit.UIComponents.FloatingPanel import FloatingPanel

class AnimatedDropdown(QToolButton):
    def __init__(self, icon: QIcon, parent=None):
        super().__init__(parent)
        self.setIcon(icon)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)
        self.setObjectName("AnimatedDropdownButton")

        # Floating panel
        self._panel = FloatingPanel(self.window())
        self._panel.hide()

        # Animation for position
        self._anim_pos = QPropertyAnimation(self._panel, b"pos", self)
        self._anim_pos.setDuration(160)
        self._anim_pos.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim_pos.finished.connect(self._on_anim_finished)

        self._hiding = False

        self.toggled.connect(self._on_toggled)

        # Button styling
        self.setStyleSheet("""

        QPushButton {
            background-color: #000000;
            color: #e5e7eb;
            border: transparent;
            border-radius: 8px;
            font-size: 14px;
        }

        QPushButton:hover {
            background-color: #1e1e1e;
        }

        """)

    @property
    def train_btn(self):
        return self._panel.train_btn

    @property
    def remove_btn(self):
        return self._panel.remove_btn
    
    @property
    def remove_antiscan_btn(self):
        return self._panel.remove_antiscan_btn

    def _on_toggled(self, checked: bool):
        if checked:
            self._show_panel()
        else:
            self._hide_panel()

    def _show_panel(self):
        # Anchor under the button (global coords)
        global_pos = self.mapToGlobal(self.rect().bottomLeft())
        self._panel.adjustSize()

        start_pos = QPoint(global_pos.x(), global_pos.y() - 8)  # slight up
        end_pos = QPoint(global_pos.x(), global_pos.y() + 4)    # drop down

        self._hiding = False
        self._panel.move(start_pos)
        self._panel.show()

        self._anim_pos.stop()
        self._anim_pos.setStartValue(start_pos)
        self._anim_pos.setEndValue(end_pos)
        self._anim_pos.start()

    def _hide_panel(self):
        if not self._panel.isVisible():
            return

        cur_pos = self._panel.pos()
        end_pos = QPoint(cur_pos.x(), cur_pos.y() - 8)

        self._hiding = True
        self._anim_pos.stop()
        self._anim_pos.setStartValue(cur_pos)
        self._anim_pos.setEndValue(end_pos)
        self._anim_pos.start()

    def _on_anim_finished(self):
        if self._hiding:
            self._panel.hide()

    def mousePressEvent(self, event):
        # Default toggle behavior is fine.
        super().mousePressEvent(event)