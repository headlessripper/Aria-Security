import sys
from PySide6.QtWidgets import QPushButton
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve, Property, QRectF
from PySide6.QtGui import QColor, QPainter, QPaintEvent, QPen, QBrush

class AnimatedToggle(QPushButton):
    """
    Android-like animated toggle switch using QPropertyAnimation.
    """
    def __init__(self, parent=None, checked=False):
        super().__init__(parent)
        self.setCheckable(True)
        self.setChecked(checked)
        self._x = 0.0

        self._margin = 3
        self._thumb_radius = 16
        self._track_radius = 18
        self._track_width = 60
        self._track_height = 32

        self.setFixedSize(self._track_width + self._margin * 2,
                          self._track_height + self._margin * 2)

        self._bg_off = QColor("#1b1b1b")
        self._bg_on = QColor("#2d2d2d")
        self._thumb_color = QColor("#f9fafb")

        self._anim = QPropertyAnimation(self, b"offset", self)
        self._anim.setDuration(180)
        self._anim.setEasingCurve(QEasingCurve.InOutCubic)

        self.toggled.connect(self._start_animation)

    def _start_animation(self, checked):
        start = self._x
        end = 1.0 if checked else 0.0
        self._anim.stop()
        self._anim.setStartValue(start)
        self._anim.setEndValue(end)
        self._anim.start()

    def paintEvent(self, event: QPaintEvent):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        # track
        track_rect = self.rect().adjusted(self._margin, self._margin, -self._margin, -self._margin)
        bg_color = self._bg_on if self.isChecked() else self._bg_off
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(bg_color))
        p.drawRoundedRect(track_rect, self._track_radius, self._track_radius)

        # thumb
        x_pos = track_rect.x() + self._x * (track_rect.width() - 2 * self._thumb_radius)
        y_pos = track_rect.y() + (track_rect.height() - 2 * self._thumb_radius) / 2
        thumb_rect = QRectF(x_pos, y_pos, 2 * self._thumb_radius, 2 * self._thumb_radius)

        p.setBrush(QBrush(self._thumb_color))
        p.setPen(QPen(QColor(0, 0, 0, 20)))
        p.drawEllipse(thumb_rect)

        p.end()

    def get_offset(self):
        return self._x

    def set_offset(self, value):
        self._x = value
        self.update()

    offset = Property(float, get_offset, set_offset)