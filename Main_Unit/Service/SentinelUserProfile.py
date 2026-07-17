import sys
import platform
import getpass
import psutil
import math
from dataclasses import dataclass
from typing import Optional, Dict

from PySide6.QtCore import (
    Qt,
    QPoint,
    QRect,
    QSize,
    QPropertyAnimation,
    QEasingCurve,
    QSettings,
)
from PySide6.QtGui import (
    QIcon,
    QPainter,
    QPen,
    QBrush,
    QPainterPath,
)
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QFormLayout,
)

# === YOUR PROJECT IMPORTS (adjust paths if needed) ===
from Main_Unit.Tools.SentinelAccessControler import USBControlApp
from Main_Unit.Service.Pages.SentinelAuthSetupPage import PinSetupWidget
from Main_Unit.Service.Pages.SentinelTaskScope.TaskPage import TaskPage
from Main_Unit.SentinelSense.AiSense.SentinelAiSenseClient import CopilotPage
from Main_Unit.Service.Pages.SentinelNetScope import NetPage
from Main_Unit.Service.SentinelConnectionView import View_Conn
from Main_Unit.Config.Sys_Config import (
    SYSTEM_ICON_PATH,
    COLOR_ACCENT,
    COLOR_BG_GLASS,
    COLOR_SLICE,
    COLOR_BG_HALO,
    COLOR_BORDER,
    COLOR_SLICE_HOVER,
    COLOR_SLICE_ACTIVE,
    COLOR_ICON,
    COLOR_SLICE_BORDER,
    ORG_NAME,
    APP_NAME_WIDGET,
    ICON_SIZE,
)
from Main_Unit.find_items import find_items
from Main_Unit.Service.find_menu import find_menu

system_ico = find_items(SYSTEM_ICON_PATH)


def _read_bool_setting(settings: QSettings, key: str, default: bool) -> bool:
    raw = settings.value(key, default)
    if isinstance(raw, bool):
        return raw
    return str(raw).lower() in ("1", "true", "yes", "on")


@dataclass
class RadialSlice:
    index: int
    start_angle_deg: float
    span_angle_deg: float
    label: str = ""
    hovered: bool = False
    pressed: bool = False
    icon: Optional[QIcon] = None


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

        self.title_label = QLabel("Service Menu")
        self.title_label.setObjectName("TitleLabel")

        layout.addWidget(self.icon_label)
        layout.addWidget(self.title_label)
        layout.addStretch()

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


class SystemInfoWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.settings = QSettings(ORG_NAME, APP_NAME_WIDGET)
        widget_enabled = _read_bool_setting(
            self.settings, "general/sentinel_widget_enabled", True
        )

        self.sentinel_widget: Optional[SentinelRadialGlassWidget] = None

        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.Window
        )
        self.setWindowIcon(QIcon(system_ico))
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setMinimumWidth(460)

        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)

        container = QFrame()
        container.setObjectName("Container")
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(0)

        self.title_bar = TitleBar(self)
        self.title_bar.setObjectName("TitleBar")
        container_layout.addWidget(self.title_bar)

        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 16, 16, 16)
        card_layout.setSpacing(12)

        # Top tools row
        top = QHBoxLayout()
        top.setSpacing(8)

        self._usb_control_app = None
        self._task_viewer_app = None
        self._copilot_app = None
        self._net_app = None
        self._view_app = None

        title = QLabel("Tools:")
        title.setObjectName("HeaderTitleLabel")
        top.addWidget(title, alignment=Qt.AlignmentFlag.AlignLeft)

        btn_group = QHBoxLayout()
        btn_group.setSpacing(4)

        icon_path_info = find_menu("menu/lock.png")
        self.usbcontrol_btn = QPushButton()
        self.usbcontrol_btn.setToolTip("USB CONTROLLER")
        self.usbcontrol_btn.setIcon(QIcon(icon_path_info))
        self.usbcontrol_btn.setFlat(True)
        self.usbcontrol_btn.setFixedHeight(40)
        self.usbcontrol_btn.setFixedWidth(40)
        self.usbcontrol_btn.clicked.connect(self.Sentinel_USBControl)

        icon_path_task = find_menu("menu/monitor.png")
        self.taskview_btn = QPushButton()
        self.taskview_btn.setToolTip("TASK VIEWER")
        self.taskview_btn.setIcon(QIcon(icon_path_task))
        self.taskview_btn.setFlat(True)
        self.taskview_btn.setFixedHeight(40)
        self.taskview_btn.setFixedWidth(40)
        self.taskview_btn.clicked.connect(self.Sentinel_TaskViewer)

        icon_path_copilot = find_menu("menu/copilot.png")
        self.copilot_btn = QPushButton()
        self.copilot_btn.setToolTip("COPILOT")
        self.copilot_btn.setIcon(QIcon(icon_path_copilot))
        self.copilot_btn.setFlat(True)
        self.copilot_btn.setFixedHeight(40)
        self.copilot_btn.setFixedWidth(40)
        self.copilot_btn.clicked.connect(self.Sentinel_Copilot)

        icon_path_net = find_menu("menu/netmon.png")
        self.net_btn = QPushButton()
        self.net_btn.setToolTip("NETWORK")
        self.net_btn.setIcon(QIcon(icon_path_net))
        self.net_btn.setFlat(True)
        self.net_btn.setFixedHeight(40)
        self.net_btn.setFixedWidth(40)
        self.net_btn.clicked.connect(self.Sentinel_Network)

        icon_path_trace = find_menu("menu/trace.png")
        self.trace_btn = QPushButton()
        self.trace_btn.setToolTip("TRACEROUTE")
        self.trace_btn.setIcon(QIcon(icon_path_trace))
        self.trace_btn.setFlat(True)
        self.trace_btn.setFixedHeight(40)
        self.trace_btn.setFixedWidth(40)
        self.trace_btn.clicked.connect(self.Sentinel_ConnView)

        for b in (
            self.copilot_btn,
            self.trace_btn,
            self.net_btn,
            self.usbcontrol_btn,
            self.taskview_btn,
        ):
            btn_group.addWidget(b)

        top.addStretch()
        top.addLayout(btn_group)
        card_layout.addLayout(top)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFrameShadow(QFrame.Sunken)
        sep.setStyleSheet("background-color: #444;")
        card_layout.addWidget(sep)

        # Header
        header_layout = QHBoxLayout()
        title = QLabel("System overview")
        title.setObjectName("HeaderTitleLabel")

        subtitle = QLabel("Device, OS, and hardware information")
        subtitle.setObjectName("MutedLabel")

        header_text = QVBoxLayout()
        header_text.addWidget(title)
        header_text.addWidget(subtitle)

        header_layout.addLayout(header_text)
        header_layout.addStretch()

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.update_info)
        header_layout.addWidget(self.refresh_btn)

        card_layout.addLayout(header_layout)

        # Form content
        self.form = QFormLayout()
        self.form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.form.setFormAlignment(Qt.AlignmentFlag.AlignTop)
        self.form.setHorizontalSpacing(24)
        self.form.setVerticalSpacing(8)

        self.lbl_user = QLabel()
        self.lbl_system = QLabel()
        self.lbl_node = QLabel()
        self.lbl_release = QLabel()
        self.lbl_version = QLabel()
        self.lbl_machine = QLabel()
        self.lbl_processor = QLabel()
        self.lbl_platform = QLabel()
        self.lbl_ram = QLabel()
        self.lbl_disk = QLabel()

        self.form.addRow("User name:", self.lbl_user)
        self.form.addRow("System:", self.lbl_system)
        self.form.addRow("Node name:", self.lbl_node)
        self.form.addRow("Release:", self.lbl_release)
        self.form.addRow("Version:", self.lbl_version)
        self.form.addRow("Machine:", self.lbl_machine)
        self.form.addRow("Processor:", self.lbl_processor)
        self.form.addRow("Platform ID:", self.lbl_platform)
        self.form.addRow("RAM usage:", self.lbl_ram)
        self.form.addRow("Disk usage:", self.lbl_disk)

        card_layout.addLayout(self.form)

        # Footer with toggle button
        footer = QHBoxLayout()
        footer.addStretch()

        setup_btn = QPushButton("Configure Authentication")
        setup_btn.clicked.connect(self.open_pin_setup)
        footer.addWidget(setup_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        footer.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)

        self.widget_toggle = QPushButton("Sentinel Widget")
        self.widget_toggle.setObjectName("SentinelToggle")
        self.widget_toggle.setCheckable(True)
        self.widget_toggle.setChecked(widget_enabled)
        self.widget_toggle.toggled.connect(self.on_widget_toggled)
        footer.addWidget(self.widget_toggle, alignment=Qt.AlignmentFlag.AlignRight)

        card_layout.addLayout(footer)

        container_layout.addWidget(card)
        root.addWidget(container)

        # Styles (with checked-state color for toggle)
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
        QPushButton#SentinelToggle {
            background-color: #444444;
        }
        QPushButton#SentinelToggle:checked {
            background-color: #16a34a;
            color: #ffffff;
        }
        """)

        self.update_info()

        # Restore widget state on startup
        if widget_enabled:
            self._ensure_sentinel_widget(show=True)
        else:
            self.sentinel_widget = None

    def _ensure_sentinel_widget(self, show: bool):
        if self.sentinel_widget is None:
            icon = QIcon(system_ico)
            # parent=None -> independent top-level window
            self.sentinel_widget = SentinelRadialGlassWidget(
                toolset=self,
                parent=None,
                icon=icon,
                slice_count=5,
            )
        self.sentinel_widget.set_enabled(show)
        if show:
            self.sentinel_widget.raise_()
            self.sentinel_widget.activateWindow()

    def on_widget_toggled(self, checked: bool):
        self.settings.setValue("general/sentinel_widget_enabled", checked)
        self.settings.sync()

        if self.sentinel_widget is None:
            icon = QIcon(system_ico)
            self.sentinel_widget = SentinelRadialGlassWidget(
                toolset=self,
                parent=None,
                icon=icon,
                slice_count=5,
            )

        self.sentinel_widget.set_enabled(checked)
        if checked:
            self.sentinel_widget.raise_()
            self.sentinel_widget.activateWindow()

    def open_pin_setup(self):
        setup = PinSetupWidget(self)
        setup.show()

    def Sentinel_USBControl(self):
        if self._usb_control_app is None:
            self._usb_control_app = USBControlApp()
        self._usb_control_app.show()
        self._usb_control_app.raise_()
        self._usb_control_app.activateWindow()

    def Sentinel_TaskViewer(self):
        if self._task_viewer_app is None:
            self._task_viewer_app = TaskPage()
        self._task_viewer_app.show()
        self._task_viewer_app.raise_()
        self._task_viewer_app.activateWindow()

    def Sentinel_Copilot(self):
        if self._copilot_app is None:
            self._copilot_app = CopilotPage()
        self._copilot_app.show()
        self._copilot_app.raise_()
        self._copilot_app.activateWindow()

    def Sentinel_Network(self):
        if self._net_app is None:
            self._net_app = NetPage()
        self._net_app.show()
        self._net_app.raise_()
        self._net_app.activateWindow()

    def Sentinel_ConnView(self):
        if self._view_app is None:
            self._view_app = View_Conn()
        self._view_app.show()
        self._view_app.raise_()
        self._view_app.activateWindow()

    def update_info(self):
        uname = platform.uname()
        username = getpass.getuser()

        self.lbl_user.setText(username)
        self.lbl_system.setText(uname.system)
        self.lbl_node.setText(uname.node)
        self.lbl_release.setText(uname.release)
        self.lbl_version.setText(uname.version)
        self.lbl_machine.setText(uname.machine)
        self.lbl_processor.setText(uname.processor or "Unknown")
        self.lbl_platform.setText(platform.platform())

        cpu_percent = psutil.cpu_percent(interval=0.3)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        self.lbl_ram.setText(
            f"{cpu_percent:.0f}% CPU, "
            f"{ram.used // (1024**3)} / {ram.total // (1024**3)} GB"
        )
        self.lbl_disk.setText(
            f"{disk.used // (1024**3)} / {disk.total // (1024**3)} GB"
        )


class SentinelRadialGlassWidget(QWidget):
    def __init__(self, toolset: SystemInfoWindow, parent=None,
                 icon: Optional[QIcon] = None, slice_count: int = 5):
        super().__init__(parent)

        self.setWindowFlags(
            Qt.FramelessWindowHint
            | Qt.WindowStaysOnTopHint
            | Qt.Tool
        )
        self.setAttribute(Qt.WA_TranslucentBackground)

        self.toolset = toolset

        self.inner_radius = 32
        self.outer_radius = 120
        self.slice_count = slice_count

        self.expanded = False
        self._drag_offset: Optional[QPoint] = None
        self._hover_slice_index: Optional[int] = None
        self._pressed_slice_index: Optional[int] = None

        self.settings = QSettings(ORG_NAME, APP_NAME_WIDGET)
        self.enabled = _read_bool_setting(
            self.settings,
            "general/sentinel_widget_enabled",
            True,
        )

        self.icon = icon or QIcon(system_ico)

        self.win_netscope = None
        self.win_usb = None
        self.win_taskview = None
        self.win_copilot = None
        self.win_connview = None

        self.slices = self._build_slices(self.slice_count)
        self._load_slice_icons()

        screen = QApplication.primaryScreen().availableGeometry()
        size_min = self._widget_size_minimized()
        pos = QPoint(
            screen.right() - size_min.width() - 32,
            screen.bottom() - size_min.height() - 96,
        )
        self.setGeometry(QRect(pos, size_min))

    def set_enabled(self, enabled: bool):
        self.enabled = bool(enabled)
        self.settings.setValue("general/sentinel_widget_enabled", self.enabled)
        self.settings.sync()

        if self.enabled:
            screen = QApplication.primaryScreen().availableGeometry()
            g = self.geometry()
            if not g.isValid() or not screen.contains(g.center()):
                size_min = self._widget_size_minimized()
                pos = QPoint(
                    screen.right() - size_min.width() - 32,
                    screen.bottom() - size_min.height() - 96,
                )
                self.setGeometry(QRect(pos, size_min))
            self.show()
        else:
            self.hide()

    # prevent user/OS from closing/hiding it directly
    def closeEvent(self, event):
        event.ignore()
        self.show()

    def hideEvent(self, event):
        # ignore hide attempts from outside; keep it open if enabled
        event.ignore()
        if self.enabled:
            self.show()
        else:
            QWidget.hide(self)

    def _widget_size_minimized(self) -> QSize:
        d = self.inner_radius * 2 + 24
        return QSize(d, d)

    def _widget_size_maximized(self) -> QSize:
        d = self.outer_radius * 2 + 24
        return QSize(d, d)

    def _center_point(self) -> QPoint:
        return self.rect().center()

    def _build_slices(self, count: int):
        slices = []
        span = 360.0 / max(count, 1)
        for i in range(count):
            start = -90.0 + i * span
            slices.append(RadialSlice(index=i, start_angle_deg=start, span_angle_deg=span))
        return slices

    def _load_slice_icons(self):
        icon_map: Dict[int, str] = {
            0: find_menu("menu/netmon.png"),
            1: find_menu("menu/lock.png"),
            2: find_menu("menu/monitor.png"),
            3: find_menu("menu/copilot.png"),
            4: find_menu("menu/trace.png"),
        }
        for s in self.slices:
            path = icon_map.get(s.index)
            if path:
                s.icon = QIcon(path)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHints(
            QPainter.Antialiasing
            | QPainter.SmoothPixmapTransform
        )

        center = self._center_point()

        if self.expanded:
            painter.setBrush(QBrush(COLOR_BG_HALO))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(center, self.outer_radius, self.outer_radius)

            painter.setBrush(QBrush(COLOR_BG_GLASS))
            painter.setPen(QPen(COLOR_BORDER, 1.5))
            painter.drawEllipse(center, self.outer_radius - 4, self.outer_radius - 4)

            painter.setBrush(Qt.NoBrush)
            painter.setPen(QPen(COLOR_ACCENT, 2))
            painter.drawEllipse(center, self.outer_radius - 18, self.outer_radius - 18)

            self._paint_slices(painter, center)

        painter.setBrush(QBrush(COLOR_BG_GLASS))
        painter.setPen(QPen(COLOR_BORDER, 1.5))
        painter.drawEllipse(center, self.inner_radius + 2, self.inner_radius + 2)

        painter.setBrush(Qt.NoBrush)
        painter.setPen(QPen(COLOR_BG_HALO, 6))
        painter.drawEllipse(center, self.inner_radius - 6, self.inner_radius - 6)

        if not self.icon.isNull():
            pix = self.icon.pixmap(ICON_SIZE, ICON_SIZE)
            icon_rect = QRect(
                center.x() - ICON_SIZE // 2,
                center.y() - ICON_SIZE // 2,
                ICON_SIZE,
                ICON_SIZE,
            )
            painter.drawPixmap(icon_rect, pix)
        else:
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(COLOR_ICON))
            painter.drawEllipse(center, self.inner_radius - 8, self.inner_radius - 8)

    def _paint_slices(self, painter: QPainter, center: QPoint):
        inner_r = self.inner_radius + 12
        outer_r = self.outer_radius - 22

        for s in self.slices:
            if s.pressed:
                fill = COLOR_SLICE_ACTIVE
            elif s.hovered:
                fill = COLOR_SLICE_HOVER
            else:
                fill = COLOR_SLICE

            path = self._slice_path(center, inner_r, outer_r, s.start_angle_deg, s.span_angle_deg)

            painter.setBrush(QBrush(fill))
            painter.setPen(QPen(COLOR_SLICE_BORDER, 1))
            painter.drawPath(path)

            angle_mid = math.radians(s.start_angle_deg + s.span_angle_deg / 2.0)
            midpoint_r = (inner_r + outer_r) / 2.0
            gx = center.x() + midpoint_r * math.cos(angle_mid)
            gy = center.y() + midpoint_r * math.sin(angle_mid)

            if s.icon is not None:
                icon_size = 18
                pix = s.icon.pixmap(icon_size, icon_size)
                icon_rect = QRect(
                    int(gx) - icon_size // 2,
                    int(gy) - icon_size // 2,
                    icon_size,
                    icon_size,
                )
                painter.drawPixmap(icon_rect, pix)
            else:
                painter.setBrush(QBrush(COLOR_ICON))
                painter.setPen(Qt.NoPen)
                painter.drawEllipse(QPoint(int(gx), int(gy)), 5, 5)

    def _slice_path(self, center: QPoint, inner_r: float, outer_r: float,
                    start_angle_deg: float, span_deg: float) -> QPainterPath:
        path = QPainterPath()

        start_rad = math.radians(start_angle_deg)
        end_rad = math.radians(start_angle_deg + span_deg)

        x1 = center.x() + outer_r * math.cos(start_rad)
        y1 = center.y() + outer_r * math.sin(start_rad)
        xi1 = center.x() + inner_r * math.cos(end_rad)
        yi1 = center.y() + inner_r * math.sin(end_rad)

        outer_rect = QRect(
            int(center.x() - outer_r),
            int(center.y() - outer_r),
            int(outer_r * 2),
            int(outer_r * 2),
        )
        inner_rect = QRect(
            int(center.x() - inner_r),
            int(center.y() - inner_r),
            int(inner_r * 2),
            int(inner_r * 2),
        )

        path.moveTo(x1, y1)
        path.arcTo(outer_rect, -start_angle_deg, -span_deg)
        path.lineTo(xi1, yi1)
        path.arcTo(inner_rect, -(start_angle_deg + span_deg), span_deg)
        path.closeSubpath()
        return path

    def toggle_expanded(self):
        self._animate(not self.expanded)

    def _animate(self, expand: bool):
        self.expanded = expand

        current_geo = self.geometry()
        center = current_geo.center()

        target_size = self._widget_size_maximized() if expand else self._widget_size_minimized()

        target_rect = QRect(
            center.x() - target_size.width() // 2,
            center.y() - target_size.height() // 2,
            target_size.width(),
            target_size.height(),
        )

        anim = QPropertyAnimation(self, b"geometry", self)
        anim.setDuration(260)
        anim.setStartValue(current_geo)
        anim.setEndValue(target_rect)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.start()

    def _is_point_in_circle(self, p: QPoint, center: QPoint, r: float) -> bool:
        dx = p.x() - center.x()
        dy = p.y() - center.y()
        return dx * dx + dy * dy <= r * r

    def _hit_slice_index(self, p: QPoint) -> Optional[int]:
        if not self.expanded:
            return None

        center = self._center_point()
        dx = p.x() - center.x()
        dy = p.y() - center.y()
        dist2 = dx * dx + dy * dy
        inner_r = self.inner_radius + 12
        outer_r = self.outer_radius - 22

        if dist2 < inner_r * inner_r or dist2 > outer_r * outer_r:
            return None

        angle = math.degrees(math.atan2(dy, dx))
        angle = (angle + 360) % 360

        for s in self.slices:
            start = (s.start_angle_deg + 360) % 360
            end = (s.start_angle_deg + s.span_angle_deg + 360) % 360

            if s.span_angle_deg >= 0:
                if start <= end:
                    if start <= angle < end:
                        return s.index
                else:
                    if angle >= start or angle < end:
                        return s.index

        return None

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            center = self._center_point()
            pos = event.position().toPoint()

            if self._is_point_in_circle(pos, center, self.inner_radius):
                self._drag_offset = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
                event.accept()
                return

            idx = self._hit_slice_index(pos)
            if idx is not None:
                self._pressed_slice_index = idx
                self.slices[idx].pressed = True
                self.update()
                event.accept()
                return

        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if (event.buttons() & Qt.LeftButton) and self._drag_offset is not None:
            self.move(event.globalPosition().toPoint() - self._drag_offset)
            event.accept()
            return

        if self.expanded:
            idx = self._hit_slice_index(event.position().toPoint())
            if idx != self._hover_slice_index:
                if self._hover_slice_index is not None:
                    self.slices[self._hover_slice_index].hovered = False
                self._hover_slice_index = idx
                if idx is not None:
                    self.slices[idx].hovered = True
                self.update()

        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            center = self._center_point()
            pos = event.position().toPoint()

            if self._is_point_in_circle(pos, center, self.inner_radius):
                self._drag_offset = None
                self.toggle_expanded()
                event.accept()
                return

            idx = self._hit_slice_index(pos)
            if idx is not None and idx == self._pressed_slice_index:
                self._trigger_tool(idx)
                event.accept()

            if self._pressed_slice_index is not None:
                self.slices[self._pressed_slice_index].pressed = False
                self._pressed_slice_index = None
                self.update()

        self._drag_offset = None
        super().mouseReleaseEvent(event)

    def _trigger_tool(self, slice_index: int):
        if slice_index == 0:
            self._tool_netscope()
        elif slice_index == 1:
            self._tool_usb_control()
        elif slice_index == 2:
            self._tool_taskview()
        elif slice_index == 3:
            self._tool_copilot()
        elif slice_index == 4:
            self._tool_connview()
        else:
            print(f"[SentinelWidget] Unknown slice {slice_index}")

    def _tool_netscope(self):
        #print("[SentinelWidget] NetScope tool triggered")
        self.win_netscope = self.toolset.Sentinel_Network()

    def _tool_usb_control(self):
        #print("[SentinelWidget] USB Control tool triggered")
        self.win_usb = self.toolset.Sentinel_USBControl()

    def _tool_taskview(self):
        #print("[SentinelWidget] TaskView tool triggered")
        self.win_taskview = self.toolset.Sentinel_TaskViewer()

    def _tool_copilot(self):
        #print("[SentinelWidget] Copilot tool triggered")
        self.win_copilot = self.toolset.Sentinel_Copilot()

    def _tool_connview(self):
        #print("[SentinelWidget] ConnView tool triggered")
        self.win_connview = self.toolset.Sentinel_ConnView()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = SystemInfoWindow()
    win.show()
    sys.exit(app.exec())
