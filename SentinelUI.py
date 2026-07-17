# SentinelUI.py — Modernized enterprise UI wired to SentinelBrain
# Preserves all existing functionality; replaces visual layer and adds live dashboard.

from __future__ import annotations

import sys, os, time, ctypes, traceback, math
from typing import Optional

# ── Qt ───────────────────────────────────────────────────────────────────────
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFrame, QScrollArea, QPlainTextEdit, QMessageBox,
    QSystemTrayIcon, QMenu, QSizePolicy, QGridLayout,
    QListWidget, QListWidgetItem, QStackedWidget, QSpacerItem,
    QFileDialog, QInputDialog, QLineEdit,
)
from PySide6.QtCore import (
    Qt, QPoint, QPropertyAnimation, QEasingCurve, QSize,
    Signal, QSettings, QTimer, QRectF, Slot, QObject, QThread,
)
from PySide6.QtGui import (
    QFont, QIcon, QPixmap, QAction, QPainter, QColor, QPen,
    QGuiApplication, QLinearGradient,
)
import qtawesome as qta

# ── App modules ───────────────────────────────────────────────────────────────
from Main_Unit.Config.Sys_Config import (
    license_agreement, SYSTEM_ICON_PATH, NET_LOG_LOGGING_FILE, APP_NAME,
    COMPILER_VERSION, VERSION, APP_DESCRIPTION, BUILD_DATE, DEVELOPER,
)
from Main_Unit.Service.find_menu import find_menu
from Main_Unit.find_items import find_items
from Main_Unit.Service.write_to_log import write_to_log
from Main_Unit.Engine.Service.SentinelService_v2 import SentinelService
from Main_Unit.Actions.Check_Update import Update
from Main_Unit.Service.SentinelNotify import Notify
from Main_Unit.Engine.Service.SentinelActivation.Sentinellicense_activation import (
    ensure_activated_once, get_active_features, APP_FEATURES,
)
from Main_Unit.Service.SentinelUserProfile import SystemInfoWindow
from Main_Unit.Service.Pages.SentinelAuthenticationPage import AuthWidget
from Main_Unit.Service.Pages.ScanHistoryPage import ScanHistoryPage
from Main_Unit.Service.Pages.ScheduledScansPage import ScheduledScansPage
from Main_Unit.Service.Pages.BehavioralRulesPage import BehavioralRulesPage
from Main_Unit.Service.Pages.YaraRulesPage import YaraRulesPage
from Main_Unit.Service.Pages.FirewallRulesPage import FirewallRulesPage
from Main_Unit.Service.Pages.UsbAllowlistPage import UsbAllowlistPage
from Main_Unit.Service.Pages.SecureVaultPage import SecureVaultPage
from Main_Unit.Service.Pages.PluginSystemPage import PluginSystemPage
from Main_Unit.Service.Pages.ProcessThreatPage import ProcessThreatPage
from Main_Unit.Service.Pages.NetworkGeoBlockPage import NetworkGeoBlockPage
from Main_Unit.Service.Pages.VirusTotalPage import VirusTotalPage
from Main_Unit.Service.Pages.ServiceControlPage import ServiceControlPage
from Main_Unit.Service.Pages.ThreatIntelPage import ThreatIntelPage
from Main_Unit.Service.Pages.MemoryCleanerPage import MemoryCleanerPage

# ── Optional legacy pages (may require extra deps: psutil, folium, QWebEngine) ──
try:
    from Main_Unit.Service.Pages.CopilotPage import CopilotPage as _CopilotPage
    _HAS_COPILOT = True
except Exception as _e:
    print(f"[SentinelUI] CopilotPage unavailable: {_e}")
    _HAS_COPILOT = False

try:
    from Main_Unit.Tools.SentinelAccessControler import USBControlApp as _USBControlApp
    _HAS_USB_CTRL = True
except Exception as _e:
    print(f"[SentinelUI] USBControlApp unavailable: {_e}")
    _HAS_USB_CTRL = False

try:
    from Main_Unit.Service.Pages.StoragePage import StoragePage as _StoragePage
    _HAS_STORAGE = True
except Exception as _e:
    print(f"[SentinelUI] StoragePage unavailable: {_e}")
    _HAS_STORAGE = False

try:
    from Main_Unit.Service.Pages.InterfacePage import InterfacesListPage as _ConnectionsMapPage
    _HAS_CONNECTIONS_MAP = True
except Exception as _e:
    print(f"[SentinelUI] ConnectionsMapPage unavailable: {_e}")
    _HAS_CONNECTIONS_MAP = False

try:
    from Main_Unit.Service.Pages.SentinelNetScope import NetPage as _NetScopePage
    _HAS_NET_SCOPE = True
except Exception as _e:
    print(f"[SentinelUI] NetScopePage unavailable: {_e}")
    _HAS_NET_SCOPE = False

try:
    from Main_Unit.Service.Pages.SentinelTaskScope.TaskPage import TaskPage as _TaskScopePage
    _HAS_TASK_SCOPE = True
except Exception as _e:
    print(f"[SentinelUI] TaskScopePage unavailable: {_e}")
    _HAS_TASK_SCOPE = False

from Main_Unit.Service.SentinelServiceAgent import EXE_NAMES, start_one
from Main_Unit.Service.PluginInstaller import ensure_all_installed
from Main_Unit.UIComponents.AnimatedToggle import AnimatedToggle
from Main_Unit.Service.FirewallCleanWorker import FirewallCleanupWorker
from Main_Unit.Service.LogTail import EmittingStream
from Main_Unit.Engine.Service.AVBrain import get_avbrain as _get_avbrain

# ── Qt message handler — suppress DirectWrite bitmap-font enumeration noise ──
def _qt_msg_filter(mode, _ctx, message: str) -> None:
    """Module-level so CPython never GC's it while Qt holds the reference."""
    if not message:
        return
    # Suppress known-benign Qt platform noise
    if "CreateFontFaceFromHDC" in message:
        return      # legacy Windows bitmap fonts (8514oem, Fixedsys) Qt can't render via DirectWrite
    if "setPointSize: Point size <= 0" in message:
        return      # Qt computing pointSize() from a stylesheet pixelSize on certain DPI configs
    sys.stderr.write(message + "\n")


# ── Design tokens ─────────────────────────────────────────────────────────────
BG         = "#080c10"
SURFACE    = "#0d1117"
CARD       = "#161b22"
BORDER     = "#21262d"
ACCENT     = "#2f81f7"
GREEN      = "#3fb950"
ORANGE     = "#d29922"
RED        = "#f85149"
PURPLE     = "#8957e5"
CYAN       = "#39d353"
TEXT       = "#e6edf3"
TEXT_DIM   = "#8b949e"
TEXT_MUTED = "#484f58"

CATEGORY_COLOR = {
    "MALWARE": RED, "RANSOMWARE": "#ff7b72",
    "NETWORK": ACCENT, "EXPLOIT": ORANGE,
    "BEHAVIORAL": PURPLE, "USB": GREEN, "SYSTEM": TEXT_DIM,
}
SEVERITY_COLOR = {
    "INFO": TEXT_DIM, "LOW": GREEN,
    "MEDIUM": ORANGE, "HIGH": RED, "CRITICAL": "#ff0000",
}

# ── Global stylesheet ─────────────────────────────────────────────────────────
_QSS = f"""
* {{ font-family: 'Segoe UI', sans-serif; }}
QWidget {{ color: {TEXT}; background: transparent; }}
#Container {{
    background: {BG};
    border-radius: 14px;
    border: 1px solid {BORDER};
}}
#TitleBar {{
    background: {SURFACE};
    border-top-left-radius: 14px;
    border-top-right-radius: 14px;
    border-bottom: 1px solid {BORDER};
}}
#Sidebar {{
    background: {SURFACE};
    border-right: 1px solid {BORDER};
    border-bottom-left-radius: 14px;
}}
#ContentArea {{ background: {BG}; border-bottom-right-radius: 14px; }}
#Card {{
    background: {CARD};
    border-radius: 12px;
    border: 1px solid {BORDER};
}}
#SidebarBtn {{
    background: transparent;
    border-radius: 10px;
    border: none;
    padding: 0px;
}}
#SidebarBtn:hover {{ background: {CARD}; }}
#SidebarBtnActive {{
    background: {ACCENT}22;
    border-radius: 10px;
    border: none;
    padding: 0px;
}}
#CloseBtn {{
    background: transparent;
    border: none;
    border-radius: 6px;
}}
#CloseBtn:hover {{ background: {RED}44; }}
#MinBtn {{
    background: transparent;
    border: none;
    border-radius: 6px;
}}
#MinBtn:hover {{ background: {CARD}; }}
QPushButton {{
    background: {CARD};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 6px 14px;
    font-size: 13px;
}}
QPushButton:hover {{ background: #1c2128; border-color: {TEXT_DIM}; }}
QPushButton:pressed {{ background: {SURFACE}; }}
#AccentBtn {{
    background: {ACCENT};
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    padding: 8px 18px;
}}
#AccentBtn:hover {{ background: #388bfd; }}
#AccentBtnGreen {{
    background: {GREEN}22;
    color: {GREEN};
    border: 1px solid {GREEN}44;
    border-radius: 8px;
    font-weight: 600;
    padding: 8px 18px;
}}
#AccentBtnGreen:hover {{ background: {GREEN}44; }}
#DangerBtn {{
    background: {RED}1a;
    color: {RED};
    border: 1px solid {RED}33;
    border-radius: 8px;
}}
#DangerBtn:hover {{ background: {RED}33; }}
#GhostBtn {{
    background: transparent;
    border: none;
    border-radius: 8px;
}}
#GhostBtn:hover {{ background: {CARD}; }}
QPlainTextEdit {{
    background: {SURFACE};
    color: #7ee787;
    border: 1px solid {BORDER};
    border-radius: 8px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 10pt;
    padding: 6px;
    selection-background-color: {ACCENT};
}}
QScrollBar:vertical {{
    background: transparent;
    width: 6px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 3px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{ background: {TEXT_DIM}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
    background: none;
    height: 0;
}}
QListWidget {{
    background: transparent;
    border: none;
    outline: none;
}}
QListWidget::item {{
    border-bottom: 1px solid {BORDER};
    padding: 0px;
    color: {TEXT};
}}
QListWidget::item:selected {{ background: {CARD}; outline: none; }}
QListWidget::item:hover {{ background: #1c2128; }}
QScrollArea {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QLabel {{ color: {TEXT}; background: transparent; }}
QToolTip {{
    background: {CARD};
    color: {TEXT};
    border: 1px solid {BORDER};
    padding: 4px 8px;
    border-radius: 6px;
    font-size: 12px;
}}
"""

# ─────────────────────────────────────────────────────────────────────────────
# Custom widgets
# ─────────────────────────────────────────────────────────────────────────────

class ProtectionGauge(QWidget):
    """Animated circular arc gauge showing protection level 0–100."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(156, 156)
        self._display  = 100.0
        self._target   = 100
        self._timer    = QTimer(self)
        self._timer.timeout.connect(self._step)

    def set_value(self, v: int):
        self._target = max(0, min(100, v))
        if not self._timer.isActive():
            self._timer.start(16)

    def _step(self):
        diff = self._target - self._display
        if abs(diff) < 0.4:
            self._display = float(self._target)
            self._timer.stop()
        else:
            self._display += diff * 0.14
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        v = self._display
        w, h  = self.width(), self.height()
        m     = 12
        rect  = QRectF(m, m, w - 2*m, h - 2*m)
        start = 225 * 16
        total = -270 * 16
        filled = int(total * v / 100)

        pen = QPen(QColor(BORDER), 9, Qt.SolidLine, Qt.RoundCap)
        p.setPen(pen)
        p.drawArc(rect, start, total)

        if v > 0:
            arc_c = QColor(GREEN if v >= 70 else (ORANGE if v >= 40 else RED))
            p.setPen(QPen(arc_c, 9, Qt.SolidLine, Qt.RoundCap))
            p.drawArc(rect, start, filled)

        p.setPen(QColor(TEXT))
        p.setFont(QFont("Segoe UI", 20, QFont.Bold))
        p.drawText(rect, Qt.AlignCenter, f"{int(round(v))}%")
        p.end()


class ModuleCard(QFrame):
    def __init__(self, name: str, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setFixedHeight(50)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 12, 0)
        layout.setSpacing(8)

        self._dot = QLabel()
        self._dot.setFixedSize(9, 9)
        self._dot_style(False)

        display = name.replace("Protection", "Prot.").replace("Intelligence", "Intel")
        lbl = QLabel(display)
        lbl.setFont(QFont("Segoe UI", 10))

        self._stat = QLabel("Offline")
        self._stat.setFont(QFont("Segoe UI", 9))
        self._stat.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self._stat.setStyleSheet(f"color: {TEXT_MUTED};")

        layout.addWidget(self._dot)
        layout.addWidget(lbl, 1)
        layout.addWidget(self._stat)

    def set_running(self, running: bool):
        self._dot_style(running)
        self._stat.setText("Active" if running else "Offline")
        self._stat.setStyleSheet(f"color: {GREEN if running else TEXT_MUTED};")

    def _dot_style(self, on: bool):
        c = GREEN if on else TEXT_MUTED
        self._dot.setStyleSheet(
            f"background:{c}; border-radius:4px;"
            f"min-width:9px; max-width:9px; min-height:9px; max-height:9px;"
        )


class ThreatRow(QWidget):
    def __init__(self, event, parent=None):
        super().__init__(parent)
        d      = event.to_dict() if hasattr(event, "to_dict") else event
        cat    = d.get("category", "SYSTEM")
        sev    = d.get("severity", "INFO")
        title  = d.get("title", "Event")
        ts     = d.get("timestamp", 0)
        color  = CATEGORY_COLOR.get(cat, TEXT_DIM)
        sev_c  = SEVERITY_COLOR.get(sev, TEXT_DIM)
        t_str  = time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "--:--:--"

        row = QHBoxLayout(self)
        row.setContentsMargins(14, 6, 14, 6)
        row.setSpacing(10)

        dot = QLabel()
        dot.setFixedSize(9, 9)
        dot.setStyleSheet(
            f"background:{color}; border-radius:4px;"
            f"min-width:9px; max-width:9px; min-height:9px; max-height:9px;"
        )

        cat_lbl = QLabel(f" {cat} ")
        cat_lbl.setStyleSheet(
            f"color:{color}; background:{color}22; border-radius:4px;"
            f"padding:0px 5px; font-size:9px; font-weight:600;"
        )
        cat_lbl.setFixedHeight(16)

        title_lbl = QLabel(title)
        title_lbl.setFont(QFont("Segoe UI", 11))
        title_lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        sev_lbl = QLabel(sev)
        sev_lbl.setStyleSheet(f"color:{sev_c}; font-size:10px; font-weight:600;")
        sev_lbl.setFixedWidth(54)
        sev_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        time_lbl = QLabel(t_str)
        time_lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:10px;")
        time_lbl.setFixedWidth(58)
        time_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        row.addWidget(dot)
        row.addWidget(cat_lbl)
        row.addWidget(title_lbl)
        row.addWidget(sev_lbl)
        row.addWidget(time_lbl)


class ThreatFeed(QFrame):
    def __init__(self, title: str = "Recent Threat Events", parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        hdr = QLabel(f"  {title}")
        hdr.setFixedHeight(36)
        hdr.setStyleSheet(
            f"font-size:11px; font-weight:600; color:{TEXT_DIM};"
            f"border-bottom:1px solid {BORDER}; padding-left:14px;"
        )
        layout.addWidget(hdr)

        self._list = QListWidget()
        layout.addWidget(self._list)

    def add_event(self, event):
        row_w = ThreatRow(event)
        item  = QListWidgetItem()
        item.setSizeHint(QSize(0, 40))
        self._list.insertItem(0, item)
        self._list.setItemWidget(item, row_w)
        while self._list.count() > 60:
            self._list.takeItem(self._list.count() - 1)


class StatChip(QFrame):
    def __init__(self, icon_name: str, label: str, value: str = "0",
                 color: str = ACCENT, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setFixedHeight(80)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(2)

        top = QHBoxLayout()
        ico = QLabel()
        ico.setPixmap(qta.icon(icon_name, color=color).pixmap(18, 18))
        ico.setFixedSize(18, 18)
        top.addWidget(ico)
        top.addStretch()
        layout.addLayout(top)

        self._val = QLabel(value)
        self._val.setFont(QFont("Segoe UI", 22, QFont.Bold))
        self._val.setStyleSheet(f"color:{color};")
        layout.addWidget(self._val)

        lbl = QLabel(label)
        lbl.setStyleSheet(f"color:{TEXT_DIM}; font-size:10px;")
        layout.addWidget(lbl)

    def set_value(self, v):
        self._val.setText(str(v))


# ─────────────────────────────────────────────────────────────────────────────
# Pages
# ─────────────────────────────────────────────────────────────────────────────

class DashboardPage(QWidget):
    toggle_protection = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        # ── Title ──
        title = QLabel("Dashboard")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        root.addWidget(title)

        # ── Top row: gauge card + modules grid ──
        top = QHBoxLayout()
        top.setSpacing(14)

        gauge_card = QFrame()
        gauge_card.setObjectName("Card")
        gauge_card.setFixedWidth(210)
        gc = QVBoxLayout(gauge_card)
        gc.setContentsMargins(16, 16, 16, 16)
        gc.setSpacing(8)

        glbl = QLabel("Protection Level")
        glbl.setStyleSheet(f"font-size:11px; font-weight:600; color:{TEXT_DIM};")
        gc.addWidget(glbl)

        self.gauge = ProtectionGauge()
        gc.addWidget(self.gauge, alignment=Qt.AlignCenter)

        self.gauge_status = QLabel("All Systems Active")
        self.gauge_status.setAlignment(Qt.AlignCenter)
        self.gauge_status.setFont(QFont("Segoe UI", 10))
        self.gauge_status.setStyleSheet(f"color:{GREEN};")
        gc.addWidget(self.gauge_status)

        self.toggle_btn = QPushButton("Enable Protection")
        self.toggle_btn.setObjectName("AccentBtn")
        self.toggle_btn.setFixedHeight(36)
        self.toggle_btn.setCursor(Qt.PointingHandCursor)
        self.toggle_btn.clicked.connect(self.toggle_protection)
        gc.addWidget(self.toggle_btn)

        top.addWidget(gauge_card)

        # Modules grid
        mod_card = QFrame()
        mod_card.setObjectName("Card")
        mc = QVBoxLayout(mod_card)
        mc.setContentsMargins(16, 12, 16, 12)
        mc.setSpacing(6)

        mc_title = QLabel("Protection Modules")
        mc_title.setStyleSheet(f"font-size:11px; font-weight:600; color:{TEXT_DIM};")
        mc.addWidget(mc_title)

        self._module_cards: dict[str, ModuleCard] = {}
        _names = [
            "FileScanner", "NetProtection", "RansomProtection", "ExploitProtection",
            "BehavioralEngine", "ThreatIntelligence", "USBMonitor", "PSDS",
        ]
        grid = QGridLayout()
        grid.setSpacing(6)
        for i, n in enumerate(_names):
            c = ModuleCard(n)
            self._module_cards[n] = c
            grid.addWidget(c, i // 2, i % 2)
        mc.addLayout(grid)

        top.addWidget(mod_card, 1)
        root.addLayout(top)

        # ── Stat chips ──
        stat_row = QHBoxLayout()
        stat_row.setSpacing(10)
        self.chip_threats   = StatChip("fa5s.skull-crossbones", "Threats",         "0", RED)
        self.chip_blocked   = StatChip("fa5s.ban",               "IPs Blocked",     "0", ORANGE)
        self.chip_network   = StatChip("fa5s.network-wired",     "Network Events",  "0", ACCENT)
        self.chip_behavioral= StatChip("fa5s.brain",             "Behavioral",      "0", PURPLE)
        for c in [self.chip_threats, self.chip_blocked, self.chip_network, self.chip_behavioral]:
            c.setFixedHeight(100)  # or setSizePolicy if you prefer
            stat_row.addWidget(c)
        root.addLayout(stat_row)

        # ── Threat feed ──
        self.feed = ThreatFeed("Recent Threat Events")
        root.addWidget(self.feed, 1)

    # ── Brain callbacks ──

    def update_module(self, name: str, running: bool):
        card = self._module_cards.get(name)
        if card:
            card.set_running(running)

    def update_protection_level(self, level: int):
        self.gauge.set_value(level)
        if level >= 80:
            txt, col = "All Systems Active", GREEN
        elif level >= 50:
            txt, col = "Partial Protection", ORANGE
        else:
            txt, col = "Protection Degraded", RED
        self.gauge_status.setText(txt)
        self.gauge_status.setStyleSheet(f"color:{col};")

    def add_threat(self, event):
        self.feed.add_event(event)

    def update_stats(self, counts: dict, blocked: int):
        self.chip_threats.set_value(
            counts.get("MALWARE", 0) + counts.get("RANSOMWARE", 0)
            + counts.get("EXPLOIT", 0)
        )
        self.chip_blocked.set_value(blocked)
        self.chip_network.set_value(counts.get("NETWORK", 0))
        self.chip_behavioral.set_value(counts.get("BEHAVIORAL", 0))

    def set_monitoring(self, enabled: bool):
        if enabled:
            self.toggle_btn.setText("Disable Protection")
            self.toggle_btn.setObjectName("AccentBtnGreen")
        else:
            self.toggle_btn.setText("Enable Protection")
            self.toggle_btn.setObjectName("AccentBtn")
        self.toggle_btn.setStyleSheet("")  # force refresh


class ProtectionPage(QWidget):

    _MODULE_META = {
        # key (brain name)  : (display label,  icon)
        "NetProtection":   ("Network Protection",  "fa5s.network-wired"),
        "RansomProtection":("Ransomware Shield",   "fa5s.shield-alt"),
        "ExploitProtection":("Exploit Guard",      "fa5s.bug"),
        "BehavioralEngine":("Behavioral Engine",   "fa5s.brain"),
        "ThreatIntelligence":("Threat Intel Feed", "fa5s.database"),
        "PSDS":            ("Port-Scan Defense",   "fa5s.ban"),
        "USBMonitor":      ("USB Monitor",         "fa5s.usb"),
        "FileScanner":     ("File Scanner",        "fa5s.search"),
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        title = QLabel("Protection")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        root.addWidget(title)

        # ── Toggle card ──────────────────────────────────────────────────
        tc = QFrame()
        tc.setObjectName("Card")
        tc.setFixedHeight(110)
        tc_row = QHBoxLayout(tc)
        tc_row.setContentsMargins(24, 0, 24, 0)
        tc_row.setSpacing(20)

        info = QVBoxLayout()
        info.setSpacing(4)
        self.toggle_label = QLabel("Sentinel Protection: Disabled")
        self.toggle_label.setFont(QFont("Segoe UI", 15, QFont.Bold))
        self.toggle_label.setStyleSheet(f"color:{TEXT_DIM};")
        self.toggle_comment = QLabel("Enable the engine to monitor threats in real-time.")
        self.toggle_comment.setStyleSheet(f"color:{TEXT_MUTED}; font-size:11px;")
        self.toggle_comment.setWordWrap(True)
        info.addWidget(self.toggle_label)
        info.addWidget(self.toggle_comment)

        self.animated_toggle = AnimatedToggle(checked=False)
        tc_row.addLayout(info, 1)
        tc_row.addWidget(self.animated_toggle, alignment=Qt.AlignCenter)
        root.addWidget(tc)

        # ── Module status grid ───────────────────────────────────────────
        mod_card = QFrame()
        mod_card.setObjectName("Card")
        ml = QVBoxLayout(mod_card)
        ml.setContentsMargins(20, 14, 20, 14)
        ml.setSpacing(10)
        ml.addWidget(self._section_label("Module Status"))

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)
        self._module_rows: dict[str, tuple] = {}   # key → (dot_lbl, status_lbl)
        for i, (key, (label, icon)) in enumerate(self._MODULE_META.items()):
            row, col_base = divmod(i, 2)
            col = col_base * 3   # each module occupies 3 grid cols (dot, name, status)

            dot = QLabel("●")
            dot.setFixedWidth(16)
            dot.setStyleSheet(f"color:{TEXT_MUTED}; font-size:10px;")

            name_lbl = QLabel(label)
            name_lbl.setStyleSheet(f"color:{TEXT}; font-size:12px;")

            status_lbl = QLabel("Stopped")
            status_lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:11px;")
            status_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

            grid.addWidget(dot,        row, col,      alignment=Qt.AlignVCenter)
            grid.addWidget(name_lbl,   row, col + 1,  alignment=Qt.AlignVCenter)
            grid.addWidget(status_lbl, row, col + 2,  alignment=Qt.AlignVCenter)
            grid.setColumnStretch(col + 1, 1)

            self._module_rows[key] = (dot, status_lbl)

        ml.addLayout(grid)
        root.addWidget(mod_card)

        # ── Firewall card ────────────────────────────────────────────────
        fw_card = QFrame()
        fw_card.setObjectName("Card")
        fwl = QVBoxLayout(fw_card)
        fwl.setContentsMargins(20, 14, 20, 14)
        fwl.setSpacing(10)
        fwl.addWidget(self._section_label("Firewall Management"))
        fw_row = QHBoxLayout()
        fw_row.setSpacing(8)
        self.btn_rm_ip   = QPushButton("Clear IP Block Rules")
        self.btn_rm_scan = QPushButton("Clear AntiScan Rules")
        for b in [self.btn_rm_ip, self.btn_rm_scan]:
            b.setObjectName("DangerBtn")
            b.setFixedHeight(36)
            b.setCursor(Qt.PointingHandCursor)
        fw_row.addWidget(self.btn_rm_ip)
        fw_row.addWidget(self.btn_rm_scan)
        fwl.addLayout(fw_row)
        root.addWidget(fw_card)
        root.addStretch()

    @staticmethod
    def _section_label(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(f"font-size:11px; font-weight:600; color:{TEXT_DIM};")
        return lbl

    def update_module(self, name: str, running: bool):
        """Update the status dot and label for one module. Called from _auto_refresh."""
        row = self._module_rows.get(name)
        if not row:
            return
        dot, status_lbl = row
        if running:
            dot.setStyleSheet(f"color:{GREEN}; font-size:10px;")
            status_lbl.setText("Running")
            status_lbl.setStyleSheet(f"color:{GREEN}; font-size:11px;")
        else:
            dot.setStyleSheet(f"color:{TEXT_MUTED}; font-size:10px;")
            status_lbl.setText("Stopped")
            status_lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:11px;")

    def set_monitoring(self, enabled: bool):
        if enabled:
            self.toggle_label.setText("Sentinel Protection: Active")
            self.toggle_label.setStyleSheet(f"color:{GREEN}; font-size:15px; font-weight:700;")
            self.toggle_comment.setText("All protection modules are running.")
        else:
            self.toggle_label.setText("Sentinel Protection: Disabled")
            self.toggle_label.setStyleSheet(f"color:{TEXT_DIM}; font-size:15px; font-weight:700;")
            self.toggle_comment.setText("Enable the engine to monitor threats in real-time.")


class NetworkPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        title = QLabel("Network Protection")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        root.addWidget(title)

        stat_row = QHBoxLayout()
        stat_row.setSpacing(10)
        self.chip_blocked = StatChip("fa5s.ban",           "IPs Blocked",    "0", RED)
        self.chip_events  = StatChip("fa5s.shield-alt",    "Network Events", "0", ACCENT)
        self.chip_intel   = StatChip("fa5s.database",      "Threat Intel",   "—", CYAN)
        for c in [self.chip_blocked, self.chip_events, self.chip_intel]:
            c.setFixedHeight(100)  # or setSizePolicy if you prefer
            stat_row.addWidget(c)
        root.addLayout(stat_row)

        self.feed = ThreatFeed("Network Threat Events")
        root.addWidget(self.feed, 1)

        fw_card = QFrame()
        fw_card.setObjectName("Card")
        fwl = QHBoxLayout(fw_card)
        fwl.setContentsMargins(20, 12, 20, 12)
        fwl.setSpacing(12)
        fwl.addWidget(self._dim("Quick Firewall Actions"))
        fwl.addStretch()
        self.btn_rm_ip   = QPushButton("Clear IP Blocks")
        self.btn_rm_scan = QPushButton("Clear AntiScan Blocks")
        for b in [self.btn_rm_ip, self.btn_rm_scan]:
            b.setObjectName("DangerBtn")
            b.setFixedHeight(34)
            b.setCursor(Qt.PointingHandCursor)
        fwl.addWidget(self.btn_rm_ip)
        fwl.addWidget(self.btn_rm_scan)
        root.addWidget(fw_card)

    @staticmethod
    def _dim(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setFont(QFont("Segoe UI", 11))
        lbl.setStyleSheet(f"color:{TEXT_DIM};")
        return lbl

    def add_event(self, event):
        d = event.to_dict() if hasattr(event, "to_dict") else event
        if d.get("category") == "NETWORK":
            self.feed.add_event(event)
            count = int(self.chip_events._val.text() or "0")
            self.chip_events.set_value(count + 1)


class ConsolePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        hdr = QHBoxLayout()
        title = QLabel("System Console")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))

        self.clear_btn = QPushButton()
        self.clear_btn.setIcon(QIcon(find_menu("menu/clear.png")))
        self.clear_btn.setObjectName("GhostBtn")
        self.clear_btn.setFixedSize(34, 34)
        self.clear_btn.setToolTip("Clear")
        self.clear_btn.setCursor(Qt.PointingHandCursor)

        self.copy_btn = QPushButton()
        self.copy_btn.setIcon(QIcon(find_menu("menu/copy.png")))
        self.copy_btn.setObjectName("GhostBtn")
        self.copy_btn.setFixedSize(34, 34)
        self.copy_btn.setToolTip("Copy")
        self.copy_btn.setCursor(Qt.PointingHandCursor)

        hdr.addWidget(title)
        hdr.addStretch()
        hdr.addWidget(self.clear_btn)
        hdr.addWidget(self.copy_btn)
        root.addLayout(hdr)

        self.output = QPlainTextEdit("Console initializing...\n")
        self.output.setReadOnly(True)
        root.addWidget(self.output, 1)

    def append(self, text: str):
        self.output.appendPlainText(text.rstrip())
        sb = self.output.verticalScrollBar()
        sb.setValue(sb.maximum())

    def clear(self):
        self.output.clear()
        self.append("Ready for Sentinel output...")

    def copy(self):
        QGuiApplication.clipboard().setText(self.output.toPlainText())


class WhitelistPage(QWidget):
    """Manage trusted files, IP addresses, and SHA256 hashes."""

    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(12)

        hdr = QLabel("Whitelist")
        hdr.setFont(QFont("Segoe UI", 16, QFont.Bold))
        hdr.setStyleSheet(f"color:{TEXT};")
        root.addWidget(hdr)

        desc = QLabel(
            "Entries listed here are permanently trusted — skipped by all detection layers."
        )
        desc.setStyleSheet(f"color:{TEXT_MUTED}; font-size:11px;")
        root.addWidget(desc)

        cols = QHBoxLayout()
        cols.setSpacing(10)

        self._file_list  = QListWidget()
        self._ip_list    = QListWidget()
        self._hash_list  = QListWidget()

        for lw in (self._file_list, self._ip_list, self._hash_list):
            lw.setStyleSheet(
                f"QListWidget{{background:{SURFACE};color:{TEXT};"
                f"border:1px solid {BORDER};border-radius:6px;font-size:10px;}}"
                f"QListWidget::item:selected{{background:{ACCENT}22;color:{TEXT};}}"
            )

        cols.addWidget(self._make_section(
            "Files & Directories", "fa5s.folder-open", GREEN, self._file_list,
            self._add_file, self._add_dir, self._remove_file
        ))
        cols.addWidget(self._make_section(
            "IP Addresses", "fa5s.network-wired", ACCENT, self._ip_list,
            self._add_ip, None, self._remove_ip
        ))
        cols.addWidget(self._make_section(
            "SHA256 Hashes", "fa5s.fingerprint", PURPLE, self._hash_list,
            self._add_hash, None, self._remove_hash
        ))
        root.addLayout(cols, 1)
        self._refresh()

    def _make_section(self, title, ico, color, list_widget,
                      add_fn, add2_fn, remove_fn) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(8)

        hdr = QHBoxLayout()
        ico_lbl = QLabel()
        ico_lbl.setPixmap(qta.icon(ico, color=color).pixmap(14, 14))
        ttl = QLabel(title)
        ttl.setFont(QFont("Segoe UI", 10, QFont.Bold))
        ttl.setStyleSheet(f"color:{TEXT};")
        hdr.addWidget(ico_lbl)
        hdr.addWidget(ttl, 1)
        cl.addLayout(hdr)

        cl.addWidget(list_widget, 1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        add_btn = QPushButton("+ Add")
        add_btn.setObjectName("AccentBtn")
        add_btn.setFixedHeight(28)
        add_btn.setCursor(Qt.PointingHandCursor)
        add_btn.clicked.connect(add_fn)
        btn_row.addWidget(add_btn)

        if add2_fn:
            add2_btn = QPushButton("+ Add Dir")
            add2_btn.setObjectName("GhostBtn")
            add2_btn.setFixedHeight(28)
            add2_btn.setCursor(Qt.PointingHandCursor)
            add2_btn.clicked.connect(add2_fn)
            btn_row.addWidget(add2_btn)

        rm_btn = QPushButton("Remove")
        rm_btn.setObjectName("DangerBtn")
        rm_btn.setFixedHeight(28)
        rm_btn.setCursor(Qt.PointingHandCursor)
        rm_btn.clicked.connect(remove_fn)
        btn_row.addWidget(rm_btn)
        cl.addLayout(btn_row)
        return card

    def _refresh(self):
        try:
            from Main_Unit.Engine.Service.SentinelWhitelist import get_whitelist
            wl = get_whitelist()
            self._file_list.clear()
            for entry in wl.list_files():
                self._file_list.addItem(entry)
            self._ip_list.clear()
            for entry in wl.list_ips():
                self._ip_list.addItem(entry)
            self._hash_list.clear()
            for entry in wl.list_hashes():
                self._hash_list.addItem(entry)
        except Exception:
            pass

    def _add_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Trust a File")
        if path:
            try:
                from Main_Unit.Engine.Service.SentinelWhitelist import get_whitelist
                get_whitelist().add_file(path)
                self._refresh()
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

    def _add_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Trust a Directory")
        if d:
            try:
                from Main_Unit.Engine.Service.SentinelWhitelist import get_whitelist
                get_whitelist().add_dir(d)
                self._refresh()
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

    def _add_ip(self):
        ip, ok = QInputDialog.getText(self, "Trust an IP", "Enter IP address:")
        if ok and ip.strip():
            try:
                from Main_Unit.Engine.Service.SentinelWhitelist import get_whitelist
                get_whitelist().add_ip(ip.strip())
                self._refresh()
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

    def _add_hash(self):
        h, ok = QInputDialog.getText(self, "Trust a Hash", "Enter SHA256 hash:")
        if ok and h.strip():
            try:
                from Main_Unit.Engine.Service.SentinelWhitelist import get_whitelist
                get_whitelist().add_hash(h.strip())
                self._refresh()
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

    def _remove_file(self):
        item = self._file_list.currentItem()
        if item:
            try:
                from Main_Unit.Engine.Service.SentinelWhitelist import get_whitelist
                get_whitelist().remove_entry(item.text())
                self._refresh()
            except Exception:
                pass

    def _remove_ip(self):
        item = self._ip_list.currentItem()
        if item:
            try:
                from Main_Unit.Engine.Service.SentinelWhitelist import get_whitelist
                get_whitelist().remove_entry(item.text())
                self._refresh()
            except Exception:
                pass

    def _remove_hash(self):
        item = self._hash_list.currentItem()
        if item:
            try:
                from Main_Unit.Engine.Service.SentinelWhitelist import get_whitelist
                get_whitelist().remove_entry(item.text())
                self._refresh()
            except Exception:
                pass


class AboutPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(16)

        title = QLabel("About")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        root.addWidget(title)

        # Developer card
        dev = QFrame()
        dev.setObjectName("Card")
        dvl = QVBoxLayout(dev)
        dvl.setContentsMargins(20, 14, 20, 14)
        dvl.setSpacing(6)
        dvl.addWidget(self._sec("Developer"))
        for text in [
            "Name:    Samuel Ikenna Great",
            "Email:   Nategreat318@gmail.com",
            "Contact: +27 677 9575 72",
        ]:
            l = QLabel(text)
            l.setFont(QFont("Segoe UI", 11))
            l.setStyleSheet("font-family: 'Consolas', monospace;")
            dvl.addWidget(l)

        # Action buttons row
        btns = QHBoxLayout()
        btns.setSpacing(8)
        self.btn_profile = QPushButton()
        self.btn_profile.setIcon(QIcon(find_menu("menu/plugin.png")))
        self.btn_profile.setObjectName("GhostBtn")
        self.btn_profile.setFixedSize(38, 38)
        self.btn_profile.setToolTip("System Profile")
        self.btn_profile.setCursor(Qt.PointingHandCursor)

        self.btn_action = QPushButton()
        self.btn_action.setIcon(QIcon(find_menu("menu/icon-24.png")))
        self.btn_action.setObjectName("GhostBtn")
        self.btn_action.setFixedSize(38, 38)
        self.btn_action.setToolTip("Action Center")
        self.btn_action.setCursor(Qt.PointingHandCursor)

        self.btn_update = QPushButton("  Check for Update")
        self.btn_update.setIcon(QIcon(find_menu("menu/reload.png")))
        self.btn_update.setObjectName("AccentBtn")
        self.btn_update.setFixedHeight(36)
        self.btn_update.setCursor(Qt.PointingHandCursor)

        #btns.addWidget(self.btn_profile)
        #btns.addWidget(self.btn_action)
        btns.addStretch()
        btns.addWidget(self.btn_update)
        dvl.addSpacing(4)
        dvl.addLayout(btns)
        root.addWidget(dev)

        # Version card
        ver = QFrame()
        ver.setObjectName("Card")
        vl = QGridLayout(ver)
        vl.setContentsMargins(20, 14, 20, 14)
        vl.setSpacing(8)
        vl.setColumnStretch(1, 1)
        for row, (k, v) in enumerate([
            ("Version", VERSION), ("Compiler", COMPILER_VERSION), ("Build", BUILD_DATE),
        ]):
            kl = QLabel(k)
            kl.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
            vl2 = QLabel(str(v))
            vl2.setFont(QFont("Segoe UI", 11, QFont.Bold))
            vl.addWidget(kl, row, 0)
            vl.addWidget(vl2, row, 1)
        root.addWidget(ver)

        # License card
        lic = QFrame()
        lic.setObjectName("Card")
        ll = QVBoxLayout(lic)
        ll.setContentsMargins(20, 14, 20, 14)
        ll.setSpacing(6)
        ll.addWidget(self._sec("License Agreement"))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFixedHeight(72)
        scroll.setStyleSheet("background: transparent; border: none;")
        lic_lbl = QLabel(license_agreement)
        lic_lbl.setWordWrap(True)
        lic_lbl.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        scroll.setWidget(lic_lbl)
        ll.addWidget(scroll)
        root.addWidget(lic)
        root.addStretch()

    @staticmethod
    def _sec(text: str) -> QLabel:
        l = QLabel(text)
        l.setStyleSheet(f"font-size:11px; font-weight:600; color:{TEXT_DIM};")
        return l


# ─────────────────────────────────────────────────────────────────────────────
# Action Center Page (embedded — replaces standalone ActionCenterWindow)
# ─────────────────────────────────────────────────────────────────────────────

class ActionCenterPage(QWidget):
    """Embedded threat action center: pending tasks + quarantine vault."""

    def __init__(self):
        super().__init__()
        from Main_Unit.Actions.Execute_Action import QuarantineMonitor, QuarantineItem
        self._QuarantineItem = QuarantineItem
        self._qm = QuarantineMonitor()
        self._qm.newQuarantine.connect(self._add_quar_card)
        self._quar_items: dict = {}
        self._task_cards: dict = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(14)

        hdr = QHBoxLayout()
        ttl = QLabel("Action Center")
        ttl.setFont(QFont("Segoe UI", 16, QFont.Bold))
        ttl.setStyleSheet(f"color:{TEXT};")
        refresh_btn = QPushButton()
        refresh_btn.setObjectName("GhostBtn")
        refresh_btn.setIcon(qta.icon("fa5s.sync", color=TEXT_DIM))
        refresh_btn.setFixedSize(30, 30)
        refresh_btn.setIconSize(QSize(13, 13))
        refresh_btn.setToolTip("Refresh quarantine list")
        refresh_btn.clicked.connect(self._refresh_quarantine)
        hdr.addWidget(ttl)
        hdr.addStretch()
        hdr.addWidget(refresh_btn)
        root.addLayout(hdr)

        body = QHBoxLayout()
        body.setSpacing(12)

        # ── Left: pending threats ──
        left = QFrame()
        left.setObjectName("Card")
        ll = QVBoxLayout(left)
        ll.setContentsMargins(12, 12, 12, 12)
        ll.setSpacing(8)

        lhdr = QLabel("Pending Threats")
        lhdr.setFont(QFont("Segoe UI", 11, QFont.Bold))
        lhdr.setStyleSheet(f"color:{TEXT_DIM};")
        ll.addWidget(lhdr)

        self._tasks_scroll = QScrollArea()
        self._tasks_scroll.setWidgetResizable(True)
        self._tasks_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._tasks_scroll.setStyleSheet("QScrollArea{border:none;background:transparent;}")
        self._tasks_container = QWidget()
        self._tasks_layout = QVBoxLayout(self._tasks_container)
        self._tasks_layout.setAlignment(Qt.AlignTop)
        self._tasks_layout.setContentsMargins(0, 0, 0, 0)
        self._tasks_layout.setSpacing(8)
        self._no_tasks_lbl = QLabel("No pending threats")
        self._no_tasks_lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:12px;")
        self._no_tasks_lbl.setAlignment(Qt.AlignCenter)
        self._tasks_layout.addWidget(self._no_tasks_lbl)
        self._tasks_scroll.setWidget(self._tasks_container)
        ll.addWidget(self._tasks_scroll, 1)

        # ── Right: quarantine vault ──
        right = QFrame()
        right.setObjectName("Card")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(12, 12, 12, 12)
        rl.setSpacing(8)

        rhdr = QLabel("Quarantine Vault")
        rhdr.setFont(QFont("Segoe UI", 11, QFont.Bold))
        rhdr.setStyleSheet(f"color:{TEXT_DIM};")
        rl.addWidget(rhdr)

        self._quar_list = QListWidget()
        self._quar_list.setStyleSheet(f"""
            QListWidget {{
                background:{SURFACE}; border:1px solid {BORDER};
                border-radius:8px; padding:2px;
            }}
            QListWidget::item {{
                padding:8px 6px;
                border-bottom:1px solid {BORDER};
                color:{TEXT};
            }}
            QListWidget::item:selected {{ background:{ACCENT}22; }}
        """)
        self._quar_list.itemDoubleClicked.connect(self._on_quar_double_click)
        rl.addWidget(self._quar_list, 1)

        qbtn_row = QHBoxLayout()
        qbtn_row.setSpacing(8)
        restore_btn = QPushButton("Restore Selected")
        restore_btn.setStyleSheet(
            f"QPushButton{{background:{GREEN}22;color:{GREEN};border:1px solid {GREEN}44;"
            f"border-radius:8px;padding:6px 12px;font-size:12px;}}"
            f"QPushButton:hover{{background:{GREEN}44;}}"
        )
        restore_btn.clicked.connect(self._restore_selected)
        del_btn = QPushButton("Delete Selected")
        del_btn.setObjectName("DangerBtn")
        del_btn.clicked.connect(self._delete_selected)
        qbtn_row.addWidget(restore_btn)
        qbtn_row.addWidget(del_btn)
        rl.addLayout(qbtn_row)

        body.addWidget(left, 1)
        body.addWidget(right, 1)
        root.addLayout(body, 1)

        QTimer.singleShot(600, self._refresh_quarantine)

    # ── Task cards ────────────────────────────────────────────────────────────

    def add_threat_task(self, file_path: str, task_id: int):
        if task_id in self._task_cards:
            return
        self._no_tasks_lbl.setVisible(False)

        card = QFrame()
        card.setObjectName("Card")
        card.setStyleSheet(
            f"QFrame#Card{{background:{CARD};border:1px solid {RED}44;border-radius:10px;}}"
        )
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(5)

        name_row = QHBoxLayout()
        dot = QLabel("●")
        dot.setStyleSheet(f"color:{RED}; font-size:10px;")
        dot.setFixedWidth(14)
        name_lbl = QLabel(os.path.basename(file_path))
        name_lbl.setFont(QFont("Segoe UI", 11, QFont.Bold))
        name_lbl.setStyleSheet(f"color:{TEXT};")
        name_row.addWidget(dot)
        name_row.addWidget(name_lbl, 1)
        cl.addLayout(name_row)

        path_lbl = QLabel(file_path[:75] + ("…" if len(file_path) > 75 else ""))
        path_lbl.setStyleSheet(f"color:{TEXT_MUTED}; font-size:10px;")
        cl.addWidget(path_lbl)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        q_btn = QPushButton("Quarantine")
        q_btn.setStyleSheet(
            f"QPushButton{{background:{ACCENT};color:white;border:none;border-radius:6px;"
            f"padding:5px 10px;font-size:11px;}}"
            f"QPushButton:hover{{background:#388bfd;}}"
        )
        d_btn = QPushButton("Destroy")
        d_btn.setStyleSheet(
            f"QPushButton{{background:{RED}1a;color:{RED};border:1px solid {RED}33;"
            f"border-radius:6px;padding:5px 10px;font-size:11px;}}"
            f"QPushButton:hover{{background:{RED}33;}}"
        )
        btn_row.addWidget(q_btn)
        btn_row.addWidget(d_btn)
        cl.addLayout(btn_row)

        def _remove():
            card.setVisible(False)
            card.deleteLater()
            self._task_cards.pop(task_id, None)
            if not self._task_cards:
                self._no_tasks_lbl.setVisible(True)

        def _quarantine():
            try:
                from Main_Unit.Actions.Execute_Action import Executioner as _E
                _E().handle_threat(file_path)
            except Exception:
                pass
            _remove()

        def _destroy():
            try:
                os.remove(file_path)
            except Exception:
                pass
            _remove()

        q_btn.clicked.connect(_quarantine)
        d_btn.clicked.connect(_destroy)
        self._tasks_layout.addWidget(card)
        self._task_cards[task_id] = card

    # ── Quarantine vault ─────────────────────────────────────────────────────

    def _refresh_quarantine(self):
        self._quar_list.clear()
        self._quar_items.clear()
        self._qm.load_metadata()

    def _add_quar_card(self, quar_dir: str, enc_path: str, basename: str, orig_path: str):
        if quar_dir in self._quar_items:
            return
        item = self._QuarantineItem(quar_dir, enc_path, basename, orig_path)
        item.restored.connect(lambda d: self._remove_quar_entry(d))
        item.deleted.connect(lambda d: self._remove_quar_entry(d))
        self._quar_items[quar_dir] = item
        ts = time.strftime("%H:%M")
        list_item = QListWidgetItem(f"{basename}  •  quarantined {ts}")
        list_item.setData(Qt.UserRole, quar_dir)
        list_item.setToolTip(f"Original path: {orig_path}")
        self._quar_list.addItem(list_item)

    def _remove_quar_entry(self, quar_dir: str):
        self._quar_items.pop(quar_dir, None)
        for i in range(self._quar_list.count()):
            it = self._quar_list.item(i)
            if it and it.data(Qt.UserRole) == quar_dir:
                self._quar_list.takeItem(i)
                break

    def _on_quar_double_click(self, item):
        quar_dir = item.data(Qt.UserRole)
        qitem = self._quar_items.get(quar_dir)
        if not qitem:
            return
        msg = QMessageBox(self)
        msg.setWindowTitle("Quarantine Action")
        msg.setText(f"File: {qitem.basename}")
        msg.setInformativeText(f"Original: {qitem.orig_path}")
        r_btn = msg.addButton("Restore", QMessageBox.YesRole)
        d_btn = msg.addButton("Delete Permanently", QMessageBox.DestructiveRole)
        msg.addButton("Cancel", QMessageBox.RejectRole)
        msg.exec()
        clicked = msg.clickedButton()
        if clicked == r_btn:
            qitem.restore()
        elif clicked == d_btn:
            qitem.delete()

    def _restore_selected(self):
        item = self._quar_list.currentItem()
        if item:
            self._on_quar_double_click(item)

    def _delete_selected(self):
        item = self._quar_list.currentItem()
        if not item:
            return
        quar_dir = item.data(Qt.UserRole)
        qitem = self._quar_items.get(quar_dir)
        if not qitem:
            return
        msg = QMessageBox(self)
        msg.setWindowTitle("Confirm Permanent Delete")
        msg.setText(f"Permanently delete {qitem.basename}?")
        msg.setInformativeText("This cannot be undone.")
        yes = msg.addButton("Delete", QMessageBox.DestructiveRole)
        msg.addButton("Cancel", QMessageBox.RejectRole)
        msg.exec()
        if msg.clickedButton() == yes:
            qitem.delete()


# ─────────────────────────────────────────────────────────────────────────────
# USB Scan Overlay — full-window semi-transparent modal
# ─────────────────────────────────────────────────────────────────────────────

class UsbScanOverlay(QFrame):
    """
    Semi-transparent overlay that covers the entire main window while a USB
    drive is being scanned.  Appears immediately on insertion, updates when
    the scan completes, and can be dismissed only after the result is shown.

    Parent must be the main CustomWindow so geometry can match.
    """

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        # Stretch to cover full parent at all times; updated in show_scanning()
        self.setGeometry(parent.rect())
        self.setStyleSheet("background: rgba(8, 12, 16, 204);")  # ~80 % opacity

        # ── Centered card ────────────────────────────────────────────────────
        self._card = QFrame(self)
        self._card.setObjectName("Card")
        self._card.setFixedSize(460, 290)
        self._card.setStyleSheet(
            f"QFrame#Card{{background:{CARD};border:2px solid {ORANGE};"
            f"border-radius:14px;}}"
        )

        card_layout = QVBoxLayout(self._card)
        card_layout.setContentsMargins(28, 24, 28, 24)
        card_layout.setSpacing(12)

        # Icon + drive row
        top_row = QHBoxLayout()
        self._icon_lbl = QLabel()
        self._icon_lbl.setPixmap(qta.icon("fa5s.hdd", color=ORANGE).pixmap(36, 36))
        self._icon_lbl.setFixedSize(36, 36)
        top_row.addWidget(self._icon_lbl)
        top_row.addSpacing(12)
        drive_info = QVBoxLayout()
        self._drive_lbl = QLabel("USB Drive — E:\\")
        self._drive_lbl.setFont(QFont("Segoe UI", 13, QFont.Bold))
        self._name_lbl = QLabel("USB Drive")
        self._name_lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        drive_info.addWidget(self._drive_lbl)
        drive_info.addWidget(self._name_lbl)
        top_row.addLayout(drive_info)
        top_row.addStretch()
        card_layout.addLayout(top_row)

        # Warning / status message
        self._status_lbl = QLabel("SCANNING IN PROGRESS")
        self._status_lbl.setFont(QFont("Segoe UI", 14, QFont.Bold))
        self._status_lbl.setStyleSheet(f"color:{ORANGE};")
        self._status_lbl.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(self._status_lbl)

        self._detail_lbl = QLabel(
            "DO NOT ACCESS THE DRIVE\n\n"
            "Sentinel is scanning all files for malware,\n"
            "ransomware, and suspicious scripts.\n"
            "You will be notified when it is safe to use."
        )
        self._detail_lbl.setAlignment(Qt.AlignCenter)
        self._detail_lbl.setWordWrap(True)
        self._detail_lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;line-height:1.5;")
        card_layout.addWidget(self._detail_lbl)

        # Progress bar (indeterminate while scanning)
        from PySide6.QtWidgets import QProgressBar
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)  # indeterminate
        self._progress.setFixedHeight(6)
        self._progress.setStyleSheet(
            f"QProgressBar{{background:{SURFACE};border:none;border-radius:3px;}}"
            f"QProgressBar::chunk{{background:{ORANGE};border-radius:3px;}}"
        )
        card_layout.addWidget(self._progress)

        # Dismiss button (disabled while scanning)
        self._dismiss_btn = QPushButton("Scanning…")
        self._dismiss_btn.setFixedHeight(38)
        self._dismiss_btn.setEnabled(False)
        self._dismiss_btn.setStyleSheet(
            f"QPushButton{{background:{CARD};color:{TEXT_MUTED};"
            f"border:1px solid {BORDER};border-radius:8px;"
            f"font-size:13px;font-weight:600;}}"
        )
        self._dismiss_btn.clicked.connect(self.hide)
        card_layout.addWidget(self._dismiss_btn)

        # Pulsing animation for scanning state
        self._pulse_timer = QTimer(self)
        self._pulse_timer.setInterval(600)
        self._pulse_timer.timeout.connect(self._pulse)
        self._pulse_state = False

        self.hide()

    def _pulse(self):
        """Alternate status label brightness while scanning."""
        self._pulse_state = not self._pulse_state
        color = ORANGE if self._pulse_state else "#9a6800"
        self._status_lbl.setStyleSheet(f"color:{color};")

    def show_scanning(self, drive: str, name: str):
        """Show the overlay immediately when a USB drive is inserted."""
        # Resize to cover parent in case window was resized since last call
        self.setGeometry(self.parent().rect())
        cw, ch = self._card.width(), self._card.height()
        pw, ph = self.width(), self.height()
        self._card.move((pw - cw) // 2, (ph - ch) // 2)

        drive_str = drive if drive.endswith("\\") else drive + "\\"
        self._drive_lbl.setText(f"USB Drive — {drive_str}")
        self._name_lbl.setText(name)
        self._status_lbl.setText("SCANNING IN PROGRESS")
        self._status_lbl.setStyleSheet(f"color:{ORANGE};")
        self._card.setStyleSheet(
            f"QFrame#Card{{background:{CARD};border:2px solid {ORANGE};"
            f"border-radius:14px;}}"
        )
        self._detail_lbl.setText(
            "DO NOT ACCESS THE DRIVE\n\n"
            "Sentinel is scanning all files for malware,\n"
            "ransomware, and suspicious scripts.\n"
            "You will be notified when it is safe to use."
        )
        self._progress.setRange(0, 0)  # indeterminate
        self._dismiss_btn.setEnabled(False)
        self._dismiss_btn.setText("Scanning…")
        self._dismiss_btn.setStyleSheet(
            f"QPushButton{{background:{CARD};color:{TEXT_MUTED};"
            f"border:1px solid {BORDER};border-radius:8px;"
            f"font-size:13px;font-weight:600;}}"
        )
        self._pulse_timer.start()
        self.raise_()
        self.show()

    def show_result(self, drive: str, name: str, threat_count: int):
        """Update the overlay with scan results."""
        self._pulse_timer.stop()
        self._progress.setRange(0, 1)
        self._progress.setValue(1)

        if threat_count == 0:
            # Clean drive
            self._status_lbl.setText("DRIVE IS CLEAN")
            self._status_lbl.setStyleSheet(f"color:{GREEN};")
            self._card.setStyleSheet(
                f"QFrame#Card{{background:{CARD};border:2px solid {GREEN};"
                f"border-radius:14px;}}"
            )
            self._progress.setStyleSheet(
                f"QProgressBar{{background:{SURFACE};border:none;border-radius:3px;}}"
                f"QProgressBar::chunk{{background:{GREEN};border-radius:3px;}}"
            )
            self._icon_lbl.setPixmap(qta.icon("fa5s.check-circle", color=GREEN).pixmap(36, 36))
            self._detail_lbl.setText(
                "Scan complete — no threats detected.\n\n"
                f"Drive {drive} is safe to use."
            )
            self._dismiss_btn.setText("OK — Drive is Safe")
            self._dismiss_btn.setStyleSheet(
                f"QPushButton{{background:{GREEN}22;color:{GREEN};"
                f"border:1px solid {GREEN}44;border-radius:8px;"
                f"font-size:13px;font-weight:600;}}"
                f"QPushButton:hover{{background:{GREEN}44;}}"
            )
            # Auto-dismiss after 6 seconds for clean drives
            QTimer.singleShot(6000, self.hide)
        else:
            # Threats found
            self._status_lbl.setText(
                f"{threat_count} THREAT{'S' if threat_count != 1 else ''} FOUND"
            )
            self._status_lbl.setStyleSheet(f"color:{RED};")
            self._card.setStyleSheet(
                f"QFrame#Card{{background:{CARD};border:2px solid {RED};"
                f"border-radius:14px;}}"
            )
            self._progress.setStyleSheet(
                f"QProgressBar{{background:{SURFACE};border:none;border-radius:3px;}}"
                f"QProgressBar::chunk{{background:{RED};border-radius:3px;}}"
            )
            self._icon_lbl.setPixmap(qta.icon("fa5s.exclamation-triangle", color=RED).pixmap(36, 36))
            self._detail_lbl.setText(
                f"{threat_count} malicious file(s) were detected and quarantined.\n\n"
                "Check the Action Center for details and remediation options.\n"
                "Avoid running any files from this drive."
            )
            self._dismiss_btn.setText("View Action Center")
            self._dismiss_btn.setStyleSheet(
                f"QPushButton{{background:{RED}22;color:{RED};"
                f"border:1px solid {RED}44;border-radius:8px;"
                f"font-size:13px;font-weight:600;}}"
                f"QPushButton:hover{{background:{RED}44;}}"
            )

        self._dismiss_btn.setEnabled(True)


# ─────────────────────────────────────────────────────────────────────────────
# Tools Page (Service tools: VT scan, AbuseIPDB, firewall rules, sandbox)
# ─────────────────────────────────────────────────────────────────────────────

class ToolsPage(QWidget):
    """Service tools panel — VT scan, AbuseIPDB lookup, firewall rules, sandbox."""

    _vt_done    = Signal(str)
    _abuse_done = Signal(str)
    _fw_done    = Signal(str)
    _sb_done    = Signal(str)

    def __init__(self):
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(14)

        hdr = QLabel("Service Tools")
        hdr.setFont(QFont("Segoe UI", 16, QFont.Bold))
        hdr.setStyleSheet(f"color:{TEXT};")
        root.addWidget(hdr)

        grid = QGridLayout()
        grid.setSpacing(12)

        # ── Cloud reputation scan ──
        vt_card = self._card("fa5s.virus-slash", RED, "Cloud Reputation Scan",
                              "Hash lookup or full file analysis against cloud intelligence")
        self._vt_input = QPlainTextEdit()
        self._vt_input.setPlaceholderText("SHA256 hash  or  full file path…")
        self._vt_input.setFixedHeight(54)
        self._vt_input.setStyleSheet(self._input_qss())
        self._vt_result = QLabel("–")
        self._vt_result.setTextFormat(Qt.RichText)
        self._vt_result.setWordWrap(True)
        self._vt_result.setStyleSheet(f"color:{TEXT_MUTED}; font-size:11px;")
        vt_btn = QPushButton("Scan")
        vt_btn.setObjectName("AccentBtn")
        vt_btn.clicked.connect(self._do_vt_scan)
        vt_card.layout().addWidget(self._vt_input)
        vt_card.layout().addWidget(self._vt_result)
        vt_card.layout().addWidget(vt_btn)

        # ── IP intelligence ──
        abuse_card = self._card("fa5s.user-slash", ORANGE, "IP Intelligence",
                                 "IP threat score and abuse history (requires API key in Config.json)")
        self._abuse_input = QPlainTextEdit()
        self._abuse_input.setPlaceholderText("IP address (e.g. 185.220.101.45)…")
        self._abuse_input.setFixedHeight(54)
        self._abuse_input.setStyleSheet(self._input_qss())
        self._abuse_result = QLabel("–")
        self._abuse_result.setTextFormat(Qt.RichText)
        self._abuse_result.setWordWrap(True)
        self._abuse_result.setStyleSheet(f"color:{TEXT_MUTED}; font-size:11px;")
        abuse_btn = QPushButton("Check IP")
        abuse_btn.setObjectName("AccentBtn")
        abuse_btn.clicked.connect(self._do_abuse_lookup)
        abuse_card.layout().addWidget(self._abuse_input)
        abuse_card.layout().addWidget(self._abuse_result)
        abuse_card.layout().addWidget(abuse_btn)

        # ── Firewall rules ──
        fw_card = self._card("fa5s.fire", ACCENT, "Active Firewall Rules",
                              "Sentinel_BLOCK_* and PSDS_BLOCK_* rules currently applied")
        self._fw_list = QPlainTextEdit()
        self._fw_list.setReadOnly(True)
        self._fw_list.setFixedHeight(110)
        self._fw_list.setStyleSheet(
            f"QPlainTextEdit{{background:{SURFACE};color:{GREEN};"
            f"border:1px solid {BORDER};border-radius:6px;"
            f"font-family:Consolas;font-size:10px;padding:4px;}}"
        )
        fw_refresh_btn = QPushButton("Refresh Rules")
        fw_refresh_btn.setObjectName("GhostBtn")
        fw_refresh_btn.clicked.connect(self._load_fw_rules)
        fw_card.layout().addWidget(self._fw_list)
        fw_card.layout().addWidget(fw_refresh_btn)

        # ── Sandbox detonation ──
        sb_card = self._card("fa5s.flask", PURPLE, "Sandbox Detonation",
                              "Run file in isolated sandbox; returns verdict + indicators")
        self._sb_path = QPlainTextEdit()
        self._sb_path.setPlaceholderText("Full path to suspicious file…")
        self._sb_path.setFixedHeight(54)
        self._sb_path.setStyleSheet(self._input_qss())
        self._sb_result = QLabel("–")
        self._sb_result.setTextFormat(Qt.RichText)
        self._sb_result.setWordWrap(True)
        self._sb_result.setStyleSheet(f"color:{TEXT_MUTED}; font-size:11px;")
        sb_btn = QPushButton("Detonate in Sandbox")
        sb_btn.setObjectName("DangerBtn")
        sb_btn.clicked.connect(self._do_sandbox)
        sb_card.layout().addWidget(self._sb_path)
        sb_card.layout().addWidget(self._sb_result)
        sb_card.layout().addWidget(sb_btn)

        grid.addWidget(vt_card, 0, 0)
        grid.addWidget(abuse_card, 0, 1)
        grid.addWidget(fw_card, 1, 0)
        grid.addWidget(sb_card, 1, 1)
        root.addLayout(grid, 1)

        QTimer.singleShot(800, self._load_fw_rules)

        self._vt_done.connect(self._vt_result.setText)
        self._abuse_done.connect(self._abuse_result.setText)
        self._fw_done.connect(self._fw_list.setPlainText)
        self._sb_done.connect(self._sb_result.setText)

    @staticmethod
    def _input_qss() -> str:
        return (
            f"QPlainTextEdit{{background:{SURFACE};color:{TEXT};"
            f"border:1px solid {BORDER};border-radius:6px;"
            f"font-family:Consolas;font-size:11px;padding:4px;}}"
        )

    def _card(self, ico: str, ico_color: str, title: str, subtitle: str) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(14, 12, 14, 12)
        cl.setSpacing(8)
        hdr = QHBoxLayout()
        ico_lbl = QLabel()
        ico_lbl.setPixmap(qta.icon(ico, color=ico_color).pixmap(16, 16))
        ttl = QLabel(title)
        ttl.setFont(QFont("Segoe UI", 11, QFont.Bold))
        ttl.setStyleSheet(f"color:{TEXT};")
        hdr.addWidget(ico_lbl)
        hdr.addWidget(ttl, 1)
        cl.addLayout(hdr)
        sub = QLabel(subtitle)
        sub.setStyleSheet(f"color:{TEXT_MUTED}; font-size:10px;")
        cl.addWidget(sub)
        return card

    # ── Tool actions (background threads emit signals → main thread updates UI) ──

    def _do_vt_scan(self):
        query = self._vt_input.toPlainText().strip()
        if not query:
            return
        self._vt_result.setText(f"<span style='color:{TEXT_DIM}'>Querying VirusTotal…</span>")

        def run():
            try:
                from Main_Unit.Engine.Service.SentinelCloudAnalysis import get_vt_client
                vt = get_vt_client()
                if not vt._is_configured():
                    return "<span style='color:{}'>{}</span>".format(
                        ORANGE, "No VT API key — add virustotal_api_key to Config.json")
                if len(query) in (32, 64) and all(c in "0123456789abcdefABCDEF" for c in query):
                    r = vt.check_hash(query.lower())
                elif os.path.isfile(query):
                    r = vt.analyze_file(query)
                else:
                    return f"<span style='color:{RED}'>Not a valid hash or file path</span>"
                if r.error:
                    return f"<span style='color:{RED}'>Error: {r.error}</span>"
                if not r.found:
                    return f"<span style='color:{TEXT_DIM}'>Not found in VT database</span>"
                cmap = {"MALICIOUS": RED, "SUSPICIOUS": ORANGE, "CLEAN": GREEN, "UNKNOWN": TEXT_DIM}
                c = cmap.get(r.verdict_str, TEXT_DIM)
                names = ", ".join(r.threat_names[:3]) if r.threat_names else "–"
                return (f"<span style='color:{c};font-weight:bold'>{r.verdict_str}</span>"
                        f" — {r.malicious}/{r.total_engines} engines | {names}")
            except Exception as e:
                return f"<span style='color:{RED}'>Exception: {e}</span>"

        def _done():
            self._vt_done.emit(run())
        import threading as _t
        _t.Thread(target=_done, daemon=True).start()

    def _do_abuse_lookup(self):
        ip = self._abuse_input.toPlainText().strip()
        if not ip:
            return
        self._abuse_result.setText(f"<span style='color:{TEXT_DIM}'>Checking AbuseIPDB…</span>")

        def run():
            try:
                from Main_Unit.Engine.Service.SentinelThreatIntelligence import lookup_ip_abuseipdb
                from Main_Unit.find_items import find_items
                from Main_Unit.Config.Sys_Config import CONFIG_PATH
                import json as _j
                key = ""
                try:
                    p = find_items(CONFIG_PATH)
                    if p and os.path.exists(p):
                        with open(p) as f:
                            key = _j.load(f).get("abuseipdb_api_key", "")
                except Exception:
                    pass
                if not key:
                    return (f"<span style='color:{ORANGE}'>No AbuseIPDB key — "
                            f"add abuseipdb_api_key to Config.json</span>")
                data = lookup_ip_abuseipdb(ip, key)
                if not data:
                    return f"<span style='color:{TEXT_DIM}'>No data returned for {ip}</span>"
                score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                country = data.get("countryCode", "?")
                isp = data.get("isp", "unknown")
                c = RED if score >= 75 else (ORANGE if score >= 30 else GREEN)
                return (f"<span style='color:{c};font-weight:bold'>{score}% abuse confidence</span>"
                        f"<br>{reports} reports | {country} | {isp}")
            except Exception as e:
                return f"<span style='color:{RED}'>Exception: {e}</span>"

        def _done():
            self._abuse_done.emit(run())
        import threading as _t
        _t.Thread(target=_done, daemon=True).start()

    def _load_fw_rules(self):
        self._fw_list.setPlainText("Loading…")

        def run():
            try:
                import subprocess as _sp, re as _re
                r = _sp.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                    capture_output=True, text=True, timeout=15,
                    creationflags=_sp.CREATE_NO_WINDOW,
                )
                names = _re.findall(
                    r'^Rule Name:\s+((?:Sentinel|PSDS)_BLOCK_.+)', r.stdout, _re.MULTILINE
                )
                if not names:
                    return "No active Sentinel block rules"
                return f"{len(names)} active rules:\n" + "\n".join(names[:60])
            except Exception as e:
                return f"Error: {e}"

        def _done():
            self._fw_done.emit(run())
        import threading as _t
        _t.Thread(target=_done, daemon=True).start()

    def _do_sandbox(self):
        path = self._sb_path.toPlainText().strip()
        if not path or not os.path.isfile(path):
            self._sb_result.setText(
                f"<span style='color:{RED}'>Invalid file path</span>")
            return
        self._sb_result.setText(f"<span style='color:{ORANGE}'>Detonating…</span>")

        def run():
            try:
                from Main_Unit.Engine.Service.SentinelSandbox import detonate
                rep = detonate(path)
                indicators = (", ".join(rep.suspicious_indicators[:3])
                               if rep.suspicious_indicators else "none")
                cmap = {"MALICIOUS": RED, "SUSPICIOUS": ORANGE, "CLEAN": GREEN}
                c = cmap.get(rep.verdict, TEXT_DIM)
                new_p = len(rep.new_processes)
                new_f = len(rep.new_files)
                return (f"<span style='color:{c};font-weight:bold'>{rep.verdict}</span>"
                        f" [{rep.mode}] — {new_p} new procs, {new_f} new files<br>"
                        f"Indicators: {indicators}")
            except Exception as e:
                return f"<span style='color:{RED}'>Sandbox error: {e}</span>"

        def _done():
            self._sb_done.emit(run())
        import threading as _t
        _t.Thread(target=_done, daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
# Main window
# ─────────────────────────────────────────────────────────────────────────────

_PAGES = [
    ("fa5s.th-large",             "Dashboard",          0),
    ("fa5s.shield-alt",           "Protection",         1),
    ("fa5s.network-wired",        "Network",            2),
    ("fa5s.terminal",             "Console",            3),
    ("fa5s.check-circle",         "Whitelist",          4),
    ("fa5s.info-circle",          "About",              5),
    ("fa5s.exclamation-triangle", "Action Center",      6),
    ("fa5s.tools",                "Service Tools",      7),
    ("fa5s.history",              "Scan History",       8),
    ("fa5s.clock",                "Scheduled Scans",    9),
    ("fa5s.sliders-h",            "Behavioral Rules",  10),
    ("fa5s.search",               "YARA Rules",        11),
    ("fa5s.fire-alt",             "Firewall Rules",    12),
    ("fa5s.folder-open",          "USB Allowlist",     13),
    ("fa5s.lock",                 "Secure Vault",      14),
    ("fa5s.plug",                 "Plugins",           15),
    ("fa5s.chart-bar",            "Process Threats",   16),
    ("fa5s.globe",                "Geo-Block",         17),
    ("fa5s.virus",                "VirusTotal",        18),
    ("fa5s.cogs",                 "Service Control",   19),
    ("fa5s.shield-virus",         "Threat Intel",      20),
    ("fa5s.broom",                "Memory Cleaner",    21),
    ("fa5s.hdd",                  "Storage",           22),
    ("fa5s.map-marked-alt",       "Connections Map",   23),
    ("fa5s.chart-line",           "Net Scope",         24),
    ("fa5s.tasks",                "Task Manager",      25),
    ("fa5s.robot",                "AI Copilot",        26),
    ("fa5b.usb",                  "USB Access Control",27),
]

system_ico = find_items(SYSTEM_ICON_PATH)


# ─────────────────────────────────────────────────────────────────────────────
# Background brain-data poller — runs on a dedicated QThread so the main
# event loop is NEVER blocked by brain reads.  Emits `refreshed` with a
# pre-built dict; the main-thread slot _apply_refresh() does only fast widget
# updates from that dict.
# ─────────────────────────────────────────────────────────────────────────────
class _BrainPoller(QObject):
    """Collects SentinelBrain stats on a background thread, emits result."""
    refreshed = Signal(dict)

    def __init__(self, service):
        super().__init__()
        self._service = service
        self._timer: Optional[QTimer] = None

    @Slot()
    def start_polling(self):
        self._timer = QTimer()
        self._timer.setInterval(1000)   # 1 second — fast but not frantic
        self._timer.timeout.connect(self._poll)
        self._timer.start()

    @Slot()
    def stop_polling(self):
        if self._timer:
            self._timer.stop()
            self._timer = None

    def _poll(self):
        try:
            brain = self._service.brain
            data: dict = {
                "counts":  brain.get_threat_counts(),
                "blocked": brain.get_blocked_count(),
                "modules": brain.get_module_statuses(),
                # AVBrain data (None when AVBrain not yet active)
                "avbrain_level":      None,
                "avbrain_assessment": None,
                "avbrain_active":     False,
            }
            try:
                av = _get_avbrain()
                data["avbrain_level"]      = av.get_protection_level()
                data["avbrain_assessment"] = av.get_last_assessment()
                data["avbrain_active"]     = True
            except Exception:
                pass
            self.refreshed.emit(data)
        except Exception:
            pass


class CustomWindow(QWidget):
    def __init__(self, active_features: set):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.resize(980, 660)

        self.active_features = active_features
        self._old_pos        = QPoint()
        self._allow_close    = False
        self._system_info_win: Optional[QWidget] = None
        self.is_monitoring   = False
        self.update_dialog   = None

        # ── Tray ──
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon(system_ico))
        self.tray_icon.setToolTip(APP_NAME)

        # ── Service ──
        self.sentinel_service = SentinelService(parent=self)

        # ── Root layout ──
        outer = QVBoxLayout(self)
        outer.setContentsMargins(1, 1, 1, 1)
        outer.setSpacing(0)

        container = QWidget()
        container.setObjectName("Container")
        cl = QVBoxLayout(container)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)

        # ── Title bar ──
        title_bar = QWidget()
        title_bar.setObjectName("TitleBar")
        title_bar.setFixedHeight(52)
        tb = QHBoxLayout(title_bar)
        tb.setContentsMargins(14, 0, 12, 0)
        tb.setSpacing(8)

        logo = QLabel()
        logo.setPixmap(QPixmap(system_ico).scaled(34, 34, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo.setFixedSize(34, 34)

        app_name = QLabel(APP_NAME)
        app_name.setFont(QFont("Segoe UI", 13, QFont.Bold))

        # Status chip (fed by Brain)
        self.display_status = QLabel("Status: Offline")
        self.display_status.setObjectName("display_status")
        self.display_status.setFont(QFont("Segoe UI", 10))
        self.display_status.setStyleSheet(
            f"color:{TEXT_MUTED}; background:{CARD}; border-radius:6px;"
            f"padding:3px 10px; border:1px solid {BORDER};"
        )

        min_btn = QPushButton()
        min_btn.setObjectName("MinBtn")
        min_btn.setIcon(qta.icon("fa5s.minus", color=TEXT_DIM))
        min_btn.setFixedSize(32, 32)
        min_btn.setIconSize(QSize(14, 14))
        min_btn.clicked.connect(self.showMinimized)
        min_btn.setCursor(Qt.PointingHandCursor)

        close_btn = QPushButton()
        close_btn.setObjectName("CloseBtn")
        close_btn.setIcon(qta.icon("fa5s.times", color=TEXT_DIM))
        close_btn.setFixedSize(32, 32)
        close_btn.setIconSize(QSize(14, 14))
        close_btn.clicked.connect(self.close)
        close_btn.setCursor(Qt.PointingHandCursor)

        tb.addWidget(logo)
        tb.addWidget(app_name)
        tb.addStretch()
        tb.addWidget(self.display_status)
        tb.addSpacing(8)
        tb.addWidget(min_btn)
        tb.addWidget(close_btn)

        cl.addWidget(title_bar)
        self.title_bar = title_bar

        # ── Body: sidebar + content ──
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        # Sidebar
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(64)
        sl = QVBoxLayout(sidebar)
        sl.setContentsMargins(10, 16, 10, 16)
        sl.setSpacing(6)
        sl.setAlignment(Qt.AlignTop)

        _PRIMARY = 5  # pages pinned in sidebar

        self._nav_btns: list[QPushButton] = []
        for ico_name, tip, idx in _PAGES[:_PRIMARY]:
            btn = QPushButton()
            btn.setObjectName("SidebarBtn")
            btn.setIcon(qta.icon(ico_name, color=TEXT_DIM))
            btn.setIconSize(QSize(20, 20))
            btn.setFixedSize(44, 44)
            btn.setToolTip(tip)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _, i=idx: self._switch_page(i))
            sl.addWidget(btn)
            self._nav_btns.append(btn)

        sl.addStretch()

        # Hamburger — opens overflow panel for remaining pages
        self._hamburger_btn = QPushButton()
        self._hamburger_btn.setObjectName("SidebarBtn")
        self._hamburger_btn.setIcon(qta.icon("fa5s.th", color=TEXT_DIM))
        self._hamburger_btn.setIconSize(QSize(20, 20))
        self._hamburger_btn.setFixedSize(44, 44)
        self._hamburger_btn.setToolTip("All pages")
        self._hamburger_btn.setCursor(Qt.PointingHandCursor)
        self._hamburger_btn.clicked.connect(self._toggle_overflow_popup)
        sl.addWidget(self._hamburger_btn)

        body.addWidget(sidebar)

        # Content area
        content_area = QWidget()
        content_area.setObjectName("ContentArea")
        cal = QVBoxLayout(content_area)
        cal.setContentsMargins(0, 0, 0, 0)
        cal.setSpacing(0)

        self._stack = QStackedWidget()

        # Build pages
        self._dashboard_page       = DashboardPage()
        self._protection_page      = ProtectionPage()
        self._network_page         = NetworkPage()
        self._console_page         = ConsolePage()
        self._whitelist_page       = WhitelistPage()
        self._about_page           = AboutPage()
        self._action_center_page   = ActionCenterPage()
        self._tools_page           = ToolsPage()
        self._scan_history_page    = ScanHistoryPage()
        self._scheduled_scans_page = ScheduledScansPage()
        self._behavioral_rules_page= BehavioralRulesPage()
        self._yara_rules_page      = YaraRulesPage()
        self._firewall_rules_page  = FirewallRulesPage()
        self._usb_allowlist_page   = UsbAllowlistPage()
        self._secure_vault_page    = SecureVaultPage()
        self._plugin_system_page   = PluginSystemPage()
        self._process_threat_page  = ProcessThreatPage()
        self._geo_block_page       = NetworkGeoBlockPage()
        self._virustotal_page      = VirusTotalPage()
        self._service_control_page = ServiceControlPage()
        self._threat_intel_page    = ThreatIntelPage()
        self._memory_cleaner_page  = MemoryCleanerPage()

        # ── Legacy pages — instantiated with fallback placeholder on error ──
        def _placeholder(title: str) -> QWidget:
            """Minimal placeholder shown when a page fails to load."""
            w = QWidget()
            lay = QVBoxLayout(w)
            lay.setAlignment(Qt.AlignCenter)
            lbl = QLabel(f"⚠  {title}\nThis page could not be loaded.\nCheck the console for details.")
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:13px;")
            lay.addWidget(lbl)
            return w

        def _embed_main_window(win) -> QWidget:
            """Strip the Qt.Window flag so a QMainWindow can be embedded in a QStackedWidget."""
            win.setWindowFlags(Qt.Widget)
            win.setAttribute(Qt.WA_TranslucentBackground, False)
            return win

        try:
            self._storage_page = _StoragePage() if _HAS_STORAGE else _placeholder("Storage")
        except Exception as _e:
            print(f"[SentinelUI] StoragePage init error: {_e}")
            self._storage_page = _placeholder("Storage")

        try:
            self._connections_map_page = _ConnectionsMapPage() if _HAS_CONNECTIONS_MAP else _placeholder("Connections Map")
        except Exception as _e:
            print(f"[SentinelUI] ConnectionsMapPage init error: {_e}")
            self._connections_map_page = _placeholder("Connections Map")

        try:
            self._net_scope_page = _embed_main_window(_NetScopePage()) if _HAS_NET_SCOPE else _placeholder("Net Scope")
        except Exception as _e:
            print(f"[SentinelUI] NetScopePage init error: {_e}")
            self._net_scope_page = _placeholder("Net Scope")

        try:
            self._task_scope_page = _embed_main_window(_TaskScopePage()) if _HAS_TASK_SCOPE else _placeholder("Task Manager")
        except Exception as _e:
            print(f"[SentinelUI] TaskScopePage init error: {_e}")
            self._task_scope_page = _placeholder("Task Manager")

        try:
            # CopilotPage is a plain QWidget — no window-flag stripping needed
            self._copilot_page = _CopilotPage() if _HAS_COPILOT else _placeholder("AI Copilot")
        except Exception as _e:
            print(f"[SentinelUI] CopilotPage init error: {_e}")
            self._copilot_page = _placeholder("AI Copilot")

        try:
            self._usb_control_page = _USBControlApp() if _HAS_USB_CTRL else _placeholder("USB Access Control")
        except Exception as _e:
            print(f"[SentinelUI] USBControlApp init error: {_e}")
            self._usb_control_page = _placeholder("USB Access Control")

        for page in [
            self._dashboard_page, self._protection_page, self._network_page,
            self._console_page, self._whitelist_page, self._about_page,
            self._action_center_page, self._tools_page,
            self._scan_history_page, self._scheduled_scans_page,
            self._behavioral_rules_page, self._yara_rules_page,
            self._firewall_rules_page, self._usb_allowlist_page,
            self._secure_vault_page,
            self._plugin_system_page, self._process_threat_page,
            self._geo_block_page, self._virustotal_page,
            self._service_control_page, self._threat_intel_page,
            self._memory_cleaner_page,
            self._storage_page, self._connections_map_page,
            self._net_scope_page, self._task_scope_page,
            self._copilot_page, self._usb_control_page,
        ]:
            self._stack.addWidget(page)

        cal.addWidget(self._stack)
        body.addWidget(content_area, 1)
        cl.addLayout(body)
        outer.addWidget(container)

        self.setStyleSheet(_QSS)

        # ── USB scan overlay (full-window modal, child of this widget) ──
        self._usb_overlay = UsbScanOverlay(self)

        # ── Overflow popup (floating child widget, 3-column page grid) ──
        self._overflow_popup = QFrame(self)
        self._overflow_popup.setObjectName("Card")
        self._overflow_popup.setStyleSheet(
            f"#Card{{background:{SURFACE};border:1px solid {BORDER};"
            f"border-radius:12px;}}"
        )
        pop_layout = QVBoxLayout(self._overflow_popup)
        pop_layout.setContentsMargins(10, 10, 10, 10)
        pop_layout.setSpacing(8)

        # Header row
        hdr_row = QHBoxLayout()
        hdr_lbl = QLabel("All Pages")
        hdr_lbl.setStyleSheet(f"font-size:11px;font-weight:600;color:{TEXT_DIM};")
        x_btn = QPushButton("✕")
        x_btn.setFixedSize(22, 22)
        x_btn.setStyleSheet(
            f"QPushButton{{background:transparent;border:none;color:{TEXT_DIM};"
            f"font-size:12px;font-weight:bold;}}"
            f"QPushButton:hover{{color:{RED};}}"
        )
        x_btn.clicked.connect(self._overflow_popup.hide)
        hdr_row.addWidget(hdr_lbl)
        hdr_row.addStretch()
        hdr_row.addWidget(x_btn)
        pop_layout.addLayout(hdr_row)

        # Grid: all pages, 3 per row
        grid_widget = QWidget()
        grid_widget.setStyleSheet("background:transparent;")
        pop_grid = QGridLayout(grid_widget)
        pop_grid.setSpacing(5)
        pop_grid.setContentsMargins(0, 0, 0, 0)

        _btn_qss = (
            f"QPushButton{{background:transparent;color:{TEXT_DIM};"
            f"border:1px solid {BORDER};border-radius:8px;"
            f"font-size:10px;padding:4px 6px;text-align:left;}}"
            f"QPushButton:hover{{background:{CARD};color:{TEXT};border-color:{ACCENT};}}"
        )
        self._overflow_btns: list[QPushButton] = []
        for i, (ico_name, tip, idx) in enumerate(_PAGES):
            row, col = divmod(i, 3)
            pb = QPushButton(f"  {tip}")
            pb.setIcon(qta.icon(ico_name, color=TEXT_DIM))
            pb.setIconSize(QSize(14, 14))
            pb.setFixedHeight(40)
            pb.setStyleSheet(_btn_qss)
            pb.setToolTip(tip)
            pb.setCursor(Qt.PointingHandCursor)
            pb.clicked.connect(lambda _, pg=idx: (self._switch_page(pg),
                                                   self._overflow_popup.hide()))
            pop_grid.addWidget(pb, row, col)
            self._overflow_btns.append(pb)

        pop_layout.addWidget(grid_widget)
        self._overflow_popup.adjustSize()
        self._overflow_popup.hide()

        # ── Wire internal signals ──
        self._dashboard_page.toggle_protection.connect(self._toggle_from_dashboard)
        self._protection_page.animated_toggle.toggled.connect(self.toggle_monitor)
        self._protection_page.btn_rm_ip.clicked.connect(self.remove_sentinel_firewall_rules)
        self._protection_page.btn_rm_scan.clicked.connect(self.remove_sentinel_AntiScan_Block_rules)
        self._network_page.btn_rm_ip.clicked.connect(self.remove_sentinel_firewall_rules)
        self._network_page.btn_rm_scan.clicked.connect(self.remove_sentinel_AntiScan_Block_rules)
        self._console_page.clear_btn.clicked.connect(self._console_page.clear)
        self._console_page.copy_btn.clicked.connect(self._console_copy)
        self._about_page.btn_update.clicked.connect(self.check_update)
        self._about_page.btn_profile.clicked.connect(self.Sentinel_UserProfile)
        self._about_page.btn_action.clicked.connect(self.on_action_center_toggled)

        # ── Console stream ──
        self.stdout_stream = EmittingStream("logs/SystemSentinel.log")
        self.stdout_stream.text_written.connect(self._console_page.append)
        # sys.stdout = self.stdout_stream  # TEMPORARILY DISABLED — output goes to real console
        # sys.stderr = self.stdout_stream  # TEMPORARILY DISABLED — errors go to real console

        # ── Wire Brain signals ──
        brain = self.sentinel_service.brain
        brain.signals.threat_detected.connect(self.on_threat_event)
        brain.signals.protection_level_changed.connect(self.on_protection_level)
        brain.signals.module_status_changed.connect(self._dashboard_page.update_module)
        brain.signals.status_line_changed.connect(self._on_status_line)

        # ── Wire USB scan overlay signals (from SentinelWorker via Qt queue) ──
        # These connect after the service is created but before the thread starts,
        # so the connections are in place before any USB event can fire.
        self.sentinel_service.worker.usb_scanning.connect(self._on_usb_scanning)
        self.sentinel_service.worker.usb_scan_complete.connect(self._on_usb_scan_complete)

        # ── Feed live Brain threat events into ThreatIntelPage ──
        brain.signals.threat_detected.connect(self._threat_intel_page.add_event)

        # ── App-quit cleanup — stop all QThreads before Qt destroys objects ──
        # Without this, QThreads parented to this window are destroyed by Qt's
        # parent-child mechanism while their C++ threads are still running →
        # "QThread: Destroyed while thread '' is still running"
        QApplication.instance().aboutToQuit.connect(self._on_about_to_quit)

        # toggle_label compat: SentinelService calls parent.toggle_label.setText
        self.toggle_label = self._protection_page.toggle_label

        # ── Tray setup ──
        tray_menu = QMenu()   # no parent — avoids position quirks with hidden parent
        self._tray_show_a  = QAction("Show Sentinel",  self)
        self._tray_hide_a  = QAction("Hide to Tray",   self)
        self._tray_about_a = QAction("About",          self)
        quit_a             = QAction("Quit Sentinel",  self)

        self._tray_show_a.triggered.connect(self.show_normal_from_tray)
        self._tray_hide_a.triggered.connect(self.hide)
        self._tray_about_a.triggered.connect(self.show_about)
        quit_a.triggered.connect(self.quit_from_tray)

        tray_menu.addAction(self._tray_show_a)
        tray_menu.addAction(self._tray_hide_a)
        tray_menu.addSeparator()
        tray_menu.addAction(self._tray_about_a)
        tray_menu.addSeparator()
        tray_menu.addAction(quit_a)
        tray_menu.setStyleSheet(f"""
            QMenu {{ background:{SURFACE}; color:{TEXT}; border:1px solid {BORDER}; padding:4px; }}
            QMenu::item {{ padding:4px 22px 4px 24px; background:transparent; }}
            QMenu::item:selected {{ background:{ACCENT}; color:white; border-radius:4px; }}
            QMenu::separator {{ height:1px; background:{BORDER}; margin:4px 6px; }}
        """)
        # Update Show/Hide visibility each time the menu is about to open
        tray_menu.aboutToShow.connect(self._update_tray_menu)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_activated)
        self.tray_icon.setVisible(True)   # must come after setContextMenu

        # ── Feature flags ──
        self.info_btn_feature = "feature_advanced_tools"
        self.info_btn = self._about_page.btn_profile
        self.btn_action_center = self._about_page.btn_action
        self.apply_feature_flags()

        # ── Auto-refresh — brain data collected on background thread ──────────
        # _BrainPoller runs on _refresh_thread; emits refreshed(dict) which Qt
        # delivers to _apply_refresh() on the main thread via queued connection.
        # The main thread only does fast widget updates — never blocks.
        self._refresh_worker = _BrainPoller(self.sentinel_service)
        self._refresh_thread = QThread(self)
        self._refresh_worker.moveToThread(self._refresh_thread)
        self._refresh_thread.started.connect(self._refresh_worker.start_polling)
        self._refresh_worker.refreshed.connect(self._apply_refresh)
        self._refresh_thread.start()

        # ── Scheduled scan runner ──
        try:
            from Main_Unit.Engine.Service.SentinelScheduler import SchedulerThread
            self._scheduler_thread = SchedulerThread(parent=self)
            self._scheduler_thread.scan_due.connect(self._on_scheduled_scan)
            self._scheduler_thread.start()
        except Exception:
            self._scheduler_thread = None

        # Activate dashboard
        self._switch_page(0)

    # ─── Page navigation ─────────────────────────────────────────────────────

    def _toggle_overflow_popup(self):
        if self._overflow_popup.isVisible():
            self._overflow_popup.hide()
            return
        # Position: just right of sidebar, just below title bar
        self._overflow_popup.adjustSize()
        self._overflow_popup.move(66, 54)
        self._overflow_popup.raise_()
        self._overflow_popup.show()

    def _switch_page(self, idx: int):
        _PRIMARY = 5
        self._stack.setCurrentIndex(idx)

        # Update the 5 pinned sidebar buttons
        for i, btn in enumerate(self._nav_btns):
            page_idx = _PAGES[i][2]
            active = (page_idx == idx)
            ico_name = _PAGES[i][0]
            btn.setIcon(qta.icon(ico_name, color=ACCENT if active else TEXT_DIM))
            btn.setObjectName("SidebarBtnActive" if active else "SidebarBtn")
            btn.setStyleSheet("")

        # Hamburger highlights when an overflow page is active
        overflow_active = idx >= _PRIMARY
        self._hamburger_btn.setObjectName(
            "SidebarBtnActive" if overflow_active else "SidebarBtn"
        )
        self._hamburger_btn.setIcon(
            qta.icon("fa5s.th", color=ACCENT if overflow_active else TEXT_DIM)
        )
        self._hamburger_btn.setStyleSheet("")

        # Highlight the matching button inside the overflow popup
        for i, pb in enumerate(self._overflow_btns):
            page_idx = _PAGES[i][2]
            active = (page_idx == idx)
            ico_name = _PAGES[i][0]
            pb.setIcon(qta.icon(ico_name, color=ACCENT if active else TEXT_DIM))
            pb.setStyleSheet(
                pb.styleSheet().replace(f"color:{ACCENT}", f"color:{TEXT_DIM}")
            )
            if active:
                pb.setStyleSheet(
                    f"QPushButton{{background:{ACCENT}22;color:{ACCENT};"
                    f"border:1px solid {ACCENT}44;border-radius:8px;"
                    f"font-size:10px;padding:4px 6px;text-align:left;}}"
                    f"QPushButton:hover{{background:{ACCENT}33;}}"
                )
            else:
                pb.setStyleSheet(
                    f"QPushButton{{background:transparent;color:{TEXT_DIM};"
                    f"border:1px solid {BORDER};border-radius:8px;"
                    f"font-size:10px;padding:4px 6px;text-align:left;}}"
                    f"QPushButton:hover{{background:{CARD};color:{TEXT};border-color:{ACCENT};}}"
                )

    # ─── Auto-refresh (main-thread slot, receives pre-collected data) ────────

    @Slot(dict)
    def _apply_refresh(self, data: dict):
        """Receive brain snapshot from background _BrainPoller and update UI.
        All brain reads happen on the worker thread; only fast widget updates
        happen here so the main event loop never stalls."""
        if not self.is_monitoring:
            return
        try:
            counts  = data["counts"]
            blocked = data["blocked"]
            modules = data["modules"]

            # ── Dashboard ──────────────────────────────────────────────
            self._dashboard_page.update_stats(counts, blocked)
            for ms in modules:
                self._dashboard_page.update_module(ms.name, ms.running)

            # AVBrain: push AI protection level + assessment to dashboard
            if data.get("avbrain_active"):
                av_level = data.get("avbrain_level")
                av_assessment = data.get("avbrain_assessment")
                if av_level is not None:
                    self._dashboard_page.update_protection_level(av_level)
                if av_assessment is not None:
                    # Push assessment summary if dashboard supports it
                    if hasattr(self._dashboard_page, "update_avbrain_summary"):
                        self._dashboard_page.update_avbrain_summary(
                            av_assessment.summary,
                            av_assessment.recommended_action,
                            av_assessment.threat_level,
                        )

            # ── Protection page module grid ────────────────────────────
            if self._protection_page.isVisible():
                for ms in modules:
                    self._protection_page.update_module(ms.name, ms.running)

            # ── Network page chips ─────────────────────────────────────
            net_count = counts.get("NETWORK", 0)
            self._network_page.chip_blocked.set_value(blocked)
            self._network_page.chip_events.set_value(net_count)
            for ms in modules:
                if ms.name == "ThreatIntelligence":
                    self._network_page.chip_intel.set_value(
                        ms.event_count if ms.event_count else ("ON" if ms.running else "—")
                    )
                    break

            # ── Whitelist page (only when visible — avoids hidden work) ─
            if self._whitelist_page.isVisible():
                self._whitelist_page._refresh()

        except Exception:
            pass

    # ─── Scheduler callback ──────────────────────────────────────────────────

    def _on_scheduled_scan(self, schedule_id: str, scan_path: str):
        """Triggered by SchedulerThread when a scheduled scan is due."""
        try:
            from Main_Unit.Engine.Service.SentinelScheduler import update_last_run
            update_last_run(schedule_id)
        except Exception:
            pass
        if self.is_monitoring and hasattr(self.sentinel_service, "start_directory_scan"):
            try:
                self.sentinel_service.start_directory_scan(scan_path)
            except Exception:
                pass

    # ─── Brain callbacks ─────────────────────────────────────────────────────

    def on_threat_event(self, event):
        """Receive ThreatEvent from Brain — update all relevant pages."""
        self._dashboard_page.add_threat(event)
        self._network_page.add_event(event)

        # Route file-system threats to Action Center as actionable tasks
        if (hasattr(event, "category")
                and event.category.name in ("MALWARE", "USB", "RANSOMWARE")
                and hasattr(event, "file_path")
                and event.file_path):
            task_id = id(event)
            self._action_center_page.add_threat_task(event.file_path, task_id)

        # Refresh stats
        brain = self.sentinel_service.brain
        self._dashboard_page.update_stats(
            brain.get_threat_counts(),
            brain.get_blocked_count(),
        )
        if hasattr(event, "category") and event.category.name == "NETWORK":
            self._network_page.chip_blocked.set_value(brain.get_blocked_count())

    def on_protection_level(self, level: int):
        self._dashboard_page.update_protection_level(level)

    # ─── USB scan overlay callbacks ──────────────────────────────────────────

    @Slot(str, str)
    def _on_usb_scanning(self, drive: str, name: str):
        """Show the USB scan overlay as soon as a drive is detected."""
        self._usb_overlay.show_scanning(drive, name)
        # Log to console
        ts = time.strftime("%H:%M:%S")
        self._console_page.append(
            f"[{ts}] USB drive detected: {name} ({drive}) — scanning…"
        )

    @Slot(str, str, int)
    def _on_usb_scan_complete(self, drive: str, name: str, threat_count: int):
        """Update the USB scan overlay with the scan result."""
        self._usb_overlay.show_result(drive, name, threat_count)
        ts = time.strftime("%H:%M:%S")
        if threat_count == 0:
            self._console_page.append(
                f"[{ts}] USB scan complete: {name} ({drive}) — CLEAN"
            )
        else:
            self._console_page.append(
                f"[{ts}] USB scan complete: {name} ({drive}) — "
                f"{threat_count} THREAT(S) FOUND"
            )
            # Route to Action Center — open it if hidden
            self._switch_page(6)

    def _on_status_line(self, line: str):
        # Trim to fit compact chip
        parts = line.split("|")
        compact = parts[0].strip() if parts else line
        self.display_status.setText(compact)

    # ─── Monitoring toggle ───────────────────────────────────────────────────

    def _toggle_from_dashboard(self):
        """Dashboard toggle button clicked — mirrors the protection page toggle."""
        checked = not self.is_monitoring
        self._protection_page.animated_toggle.setChecked(checked)
        self.toggle_monitor(checked)

    @Slot()
    def toggle_monitor(self, checked: bool = None):
        if checked is None:
            checked = not self.is_monitoring
        if not self.sentinel_service:
            print("SentinelService not initialized")
            return
        if checked and not self.sentinel_service.thread.isRunning():
            self.start_monitor()
        elif not checked:
            print("Stopping monitoring...")
            self.sentinel_service.stop_monitoring()
            self._set_monitoring_ui(False)

    def start_monitor(self):
        if self.sentinel_service:
            self.sentinel_service.start_monitoring()
            self._set_monitoring_ui(True)
        else:
            Notify("Service missing!", parent=self)

    def stop_monitor(self):
        if self.sentinel_service:
            self.sentinel_service.stop_monitoring()
            self._set_monitoring_ui(False)

    def _set_monitoring_ui(self, enabled: bool):
        self.is_monitoring = enabled
        self._protection_page.set_monitoring(enabled)
        self._dashboard_page.set_monitoring(enabled)
        status = "Status: Online" if enabled else "Status: Offline"
        self.display_status.setText(status)
        color = GREEN if enabled else TEXT_MUTED
        self.display_status.setStyleSheet(
            f"color:{color}; background:{CARD}; border-radius:6px;"
            f"padding:3px 10px; border:1px solid {BORDER};"
        )

    # ─── Console helpers ─────────────────────────────────────────────────────

    def append_output(self, text: str):
        self._console_page.append(text)

    def log_console(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self._console_page.append(f"[{ts}] {msg}")

    def clear_console(self):
        self._console_page.clear()

    def copy_console(self):
        self._console_copy()

    def _console_copy(self):
        self._console_page.copy()
        Notify("Console copied to clipboard", parent=self)

    # ─── QR code ─────────────────────────────────────────────────────────────

    # ─── Firewall cleanup ────────────────────────────────────────────────────

    def remove_sentinel_firewall_rules(self):
        Notify("Removing Sentinel firewall rules...", parent=self)
        self._fw1 = FirewallCleanupWorker("Sentinel_BLOCK_*", parent=self)
        self._fw1.finished_ok.connect(
            lambda: Notify("Sentinel firewall rules removed.", parent=self))
        self._fw1.finished_error.connect(
            lambda m: Notify(f"Error: {m}", parent=self))
        self._fw1.start()

    def remove_sentinel_AntiScan_Block_rules(self):
        Notify("Removing AntiScan block rules...", parent=self)
        self._fw2 = FirewallCleanupWorker("PSDS_BLOCK_*", parent=self)
        self._fw2.finished_ok.connect(
            lambda: Notify("AntiScan rules removed.", parent=self))
        self._fw2.finished_error.connect(
            lambda m: Notify(f"Error: {m}", parent=self))
        self._fw2.start()

    # ─── Update dialog ───────────────────────────────────────────────────────

    def check_update(self):
        if getattr(self, "check_widget", None) is not None and self.check_widget.isVisible():
            return
        self.check_widget = QWidget(self)
        self.check_widget.setWindowTitle("Check for Update")
        self.check_widget.setFixedSize(420, 300)
        self.check_widget.setWindowFlags(
            Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint
        )
        self.check_widget.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.check_widget.setStyleSheet(f"QWidget {{ background:{SURFACE}; border-radius:12px; }}")
        layout = QVBoxLayout(self.check_widget)
        layout.setContentsMargins(10, 10, 10, 10)
        if self.update_dialog is None:
            self.update_dialog = Update()
            self.update_dialog.later_btn.clicked.disconnect()
            self.update_dialog.later_btn.clicked.connect(self._fade_out_update)
        self.update_dialog.setParent(self.check_widget)
        self.update_dialog.setWindowFlags(Qt.Widget)
        self.update_dialog.show()
        layout.addWidget(self.update_dialog)
        r = self.geometry()
        self.check_widget.move(
            r.x() + (r.width() - self.check_widget.width()) // 2,
            r.y() + (r.height() - self.check_widget.height()) // 2,
        )
        self.check_widget.setWindowOpacity(0.0)
        self.check_widget.show()
        anim = QPropertyAnimation(self.check_widget, b"windowOpacity", self)
        anim.setDuration(400)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.start()
        self._update_fade_in = anim

    def _fade_out_update(self):
        if getattr(self, "check_widget", None) is None or not self.check_widget.isVisible():
            return
        anim = QPropertyAnimation(self.check_widget, b"windowOpacity", self)
        anim.setDuration(300)
        anim.setStartValue(1.0)
        anim.setEndValue(0.0)
        anim.setEasingCurve(QEasingCurve.Type.InCubic)
        anim.finished.connect(lambda: (self.check_widget.close(), setattr(self, "check_widget", None)))
        anim.start()
        self._update_fade_out = anim

    # Legacy alias
    def fade_out_check(self):
        self._fade_out_update()

    # ─── System info / action center ────────────────────────────────────────

    def Sentinel_UserProfile(self):
        if self._system_info_win is None:
            self._system_info_win = SystemInfoWindow(self)
        self._system_info_win.show()
        self._system_info_win.raise_()
        self._system_info_win.activateWindow()

    def on_action_center_toggled(self, *_):
        self._switch_page(6)

    # ─── Feature flags ───────────────────────────────────────────────────────

    def apply_feature_flags(self):
        self._apply_feature(self.info_btn, self.info_btn_feature)

    def _apply_feature(self, widget, feature_name: str):
        if feature_name in self.active_features:
            widget.setEnabled(True)
            widget.show()
        else:
            widget.setEnabled(False)
            widget.hide()

    # ─── Tray / window events ────────────────────────────────────────────────

    def show_normal_from_tray(self):
        self.show()
        self.setWindowState(
            (self.windowState() & ~Qt.WindowMinimized) | Qt.WindowActive
        )
        self.raise_()
        self.activateWindow()

    def quit_from_tray(self):
        self._allow_close = True
        self.tray_icon.hide()
        QApplication.instance().quit()

    def _update_tray_menu(self):
        """Show only the relevant Show/Hide action before the menu opens."""
        visible = self.isVisible() and not self.isMinimized()
        self._tray_show_a.setVisible(not visible)
        self._tray_hide_a.setVisible(visible)

    def on_tray_activated(self, reason):
        """Single-click OR double-click toggles window visibility."""
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,        # single left-click
            QSystemTrayIcon.ActivationReason.DoubleClick,    # double left-click
        ):
            if self.isVisible() and not self.isMinimized():
                self.hide()
            else:
                self.show_normal_from_tray()

    def show_about(self):
        """Restore window (if hidden) and navigate to the About page."""
        self.show_normal_from_tray()
        self._switch_page(5)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Keep the USB scan overlay covering the full window
        if hasattr(self, "_usb_overlay") and self._usb_overlay.isVisible():
            self._usb_overlay.setGeometry(self.rect())
            cw, ch = self._usb_overlay._card.width(), self._usb_overlay._card.height()
            self._usb_overlay._card.move(
                (self.width()  - cw) // 2,
                (self.height() - ch) // 2,
            )

    def _on_about_to_quit(self):
        """
        Called by QApplication.aboutToQuit — fires before the event loop stops
        and BEFORE Qt's parent-child destructor tears down QThread C++ objects.
        Stop every long-running thread here so their C++ counterparts are already
        idle when Qt destroys them, avoiding "QThread: Destroyed while thread is
        still running".
        """
        # 0. Background brain-poller thread
        try:
            rw = getattr(self, "_refresh_worker", None)
            rt = getattr(self, "_refresh_thread", None)
            if rw:
                rw.stop_polling()
            if rt and rt.isRunning():
                rt.quit()
                rt.wait(2000)
        except Exception:
            pass

        # 1. All SentinelService threads (9 total: 8 per-module + 1 file-scan).
        # stop_monitoring() checks isRunning() for each thread internally, so
        # it is safe to call unconditionally even if monitoring was never started.
        try:
            self.sentinel_service.stop_monitoring()
        except Exception:
            pass

        # Belt-and-suspenders: any per-module thread that survived stop_monitoring()
        try:
            for t in self.sentinel_service._module_threads:
                if t.isRunning():
                    t.quit()
                    t.wait(1000)
        except Exception:
            pass

        # 2. Scheduled-scan thread (only present when monitoring is enabled)
        # IMPORTANT: SchedulerThread uses a custom while-loop with msleep —
        # it never runs Qt's event loop, so quit() alone is a no-op.
        # Must call stop() first so _running becomes False and the loop exits.
        try:
            st = getattr(self, "_scheduler_thread", None)
            if st and st.isRunning():
                st.stop()   # sets _running = False; loop exits within 1 s
                st.quit()   # harmless; stops any Qt event loop if ever added
                st.wait(5000)
        except Exception:
            pass

        # 3. Memory cleaner live-stats worker (runs continuously in background)
        try:
            mc = getattr(self, "_memory_cleaner_page", None)
            if mc:
                sw = getattr(mc, "_stats_worker", None)
                if sw and sw.isRunning():
                    sw.stop()
                    sw.wait(3000)
        except Exception:
            pass

        # 4. Storage page workers (deep-clean + quick-scan threads)
        try:
            sp = getattr(self, "_storage_page", None)
            if sp:
                for attr in ("worker", "quick_worker"):
                    w = getattr(sp, attr, None)
                    if w and hasattr(w, "isRunning") and w.isRunning():
                        try:
                            w.cancel()
                        except Exception:
                            pass
                        w.wait(2000)
        except Exception:
            pass

        # 5. Connections-map worker (geo IP lookup)
        try:
            cm = getattr(self, "_connections_map_page", None)
            if cm:
                cw = getattr(cm, "conn_worker", None)
                if cw and hasattr(cw, "isRunning") and cw.isRunning():
                    try:
                        cw.stop()
                    except Exception:
                        pass
                    cw.wait(2000)
        except Exception:
            pass

        # 6. NetScope workers (NetworkWorker + LatencyWorker)
        try:
            ns = getattr(self, "_net_scope_page", None)
            if ns:
                for attr in ("worker", "latency_worker"):
                    w = getattr(ns, attr, None)
                    if w and hasattr(w, "isRunning") and w.isRunning():
                        try:
                            w.stop()
                        except Exception:
                            pass
                        w.wait(2000)
        except Exception:
            pass

        # 7. TaskScope process worker
        try:
            ts = getattr(self, "_task_scope_page", None)
            if ts:
                pw = getattr(ts, "process_worker", None)
                if pw and hasattr(pw, "isRunning") and pw.isRunning():
                    try:
                        pw.stop()
                    except Exception:
                        pass
                    pw.wait(2000)
        except Exception:
            pass

        # 8. Short-lived firewall-cleanup threads
        for attr in ("_fw1", "_fw2"):
            try:
                fw = getattr(self, attr, None)
                if fw and fw.isRunning():
                    fw.wait(4000)   # these finish quickly (PowerShell command)
            except Exception:
                pass

    def closeEvent(self, event):
        if not self._allow_close:
            event.ignore()
            self.hide()
        else:
            event.accept()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._old_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event):
        if event.buttons() & Qt.LeftButton:
            widget_under = self.childAt(event.position().toPoint())
            # Only drag from title bar area
            if self.title_bar.geometry().contains(event.position().toPoint()):
                delta = event.globalPosition().toPoint() - self._old_pos
                self.move(self.pos() + delta)
                self._old_pos = event.globalPosition().toPoint()


# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap
# ─────────────────────────────────────────────────────────────────────────────

def is_windows() -> bool:
    return os.name == "nt"

def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def relaunch_as_admin() -> bool:
    if not is_windows():
        return False
    try:
        exe_path = sys.executable
        if getattr(sys, "frozen", False):
            params = " ".join(f'"{a}"' for a in sys.argv[1:])
        else:
            script  = os.path.abspath(sys.argv[0])
            params  = " ".join([f'"{script}"'] + [f'"{a}"' for a in sys.argv[1:]])
        h = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe_path, params, None, 1)
        return h > 32
    except Exception:
        traceback.print_exc()
        return False

def start_app():
    import signal as _signal
    from PySide6.QtCore import qInstallMessageHandler

    # Install module-level handler (defined near top of file) — module scope
    # prevents CPython GC from freeing it after start_app() returns.
    qInstallMessageHandler(_qt_msg_filter)

    app = QApplication(sys.argv)

    # Route Ctrl+C → QApplication.quit() so aboutToQuit fires and threads are
    # stopped cleanly before Qt's destructor tears down parented QThread objects.
    # Without this, KeyboardInterrupt interrupts app.exec() at the C++ level and
    # aboutToQuit is never emitted, causing "QThread: Destroyed while running".
    def _sigint_handler(*_):
        a = QApplication.instance()
        if a:
            a.quit()
    _signal.signal(_signal.SIGINT, _sigint_handler)

    ensure_activated_once(app)
    ensure_all_installed()

    #try:
    #    from Main_Unit.Engine.Service.SentinelSelfProtection import activate_self_protection
    #    activate_self_protection()
    #except Exception:
    #    pass

    for exe_name in EXE_NAMES:
        start_one(exe_name)

    active_features = set(get_active_features())
    settings        = QSettings("AriaSecurity", "SentinelAuthentication")
    use_auth        = settings.value("use_authentication", False, type=bool)
    app.setQuitOnLastWindowClosed(False)

    main_win = CustomWindow(active_features)
    if use_auth:
        auth = AuthWidget(on_authenticated=lambda: main_win.show())
        auth.show()
    else:
        main_win.show()

    sys.exit(app.exec())

def main():
    if is_windows() and not is_admin():
        launched = relaunch_as_admin()
        if launched:
            print("Relaunching with administrator privileges... exiting current process.")
            sys.exit(0)
        else:
            print("[Warning] Failed to relaunch as administrator. Continuing without elevation.")
    start_app()

if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    main()
