# SentinelNetworkVisualizer.py

import sys
import time
import psutil
import platform
import subprocess
import statistics
from collections import deque

from PySide6.QtCore import Qt, QThread, Signal, QRectF, QPoint, QTimer
from PySide6.QtGui import QPainter, QColor, QPen, QPainterPath, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QStackedWidget, QGraphicsView,
    QGraphicsScene, QGraphicsLineItem, QGraphicsPathItem, QFrame
)

from Main_Unit.Service.Pages.Style_Qss.qss import qss
from Main_Unit.find_items import find_items
from Main_Unit.Service.find_menu import find_menu
from Main_Unit.Config.Sys_Config import SYSTEM_ICON_PATH

system_ico = find_items(SYSTEM_ICON_PATH)


# ===================== Worker Thread =====================

class NetworkWorker(QThread):
    data_updated = Signal(dict)  # { 'bytes_sent', 'bytes_recv', 'packets_sent', 'packets_recv', 'dropin', 'dropout' }
    health = Signal(bool)

    def __init__(self, interface, interval=1.0, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.interval = interval
        self._running = True

    def run(self):
        while self._running:
            try:
                # use nowrap to avoid wrap-around on long-lived systems
                stats_all = psutil.net_io_counters(pernic=True, nowrap=True)  # important[web:20][web:72]
                if self.interface not in stats_all:
                    # Interface missing (disabled, unplugged, etc.) – emit unhealthy and retry later
                    self.health.emit(False)
                    self.msleep(int(self.interval * 1000))
                    continue

                s = stats_all[self.interface]
                data = {
                    "bytes_sent": s.bytes_sent,
                    "bytes_recv": s.bytes_recv,
                    "packets_sent": s.packets_sent,
                    "packets_recv": s.packets_recv,
                    "dropin": getattr(s, "dropin", 0),
                    "dropout": getattr(s, "dropout", 0),
                }
                self.data_updated.emit(data)
                self.health.emit(True)
            except Exception as e:
                # Never let the thread die silently
                print(f"[NetworkWorker:{self.interface}] error: {e}")
                self.health.emit(False)
            self.msleep(int(self.interval * 1000))

    def stop(self):
        self._running = False
        self.quit()
        self.wait()


# ===================== Latency Worker (ping) =====================

class LatencyWorker(QThread):
    latency_updated = Signal(float)  # average latency in ms, -1 if unavailable
    health = Signal(bool)

    def __init__(self, target="8.8.8.8", interval=2.0, parent=None):
        super().__init__(parent)
        self.target = target
        self.interval = interval
        self._running = True
        self._samples = deque(maxlen=10)

    def run(self):
        while self._running:
            try:
                latency = self._ping_once(self.target)
                if latency >= 0:
                    self._samples.append(latency)
                    try:
                        avg = statistics.mean(self._samples)
                    except statistics.StatisticsError:
                        avg = latency
                    self.latency_updated.emit(avg)
                    self.health.emit(True)
                else:
                    self.latency_updated.emit(-1.0)
                    self.health.emit(False)
            except Exception as e:
                print(f"[LatencyWorker] error: {e}")
                self.latency_updated.emit(-1.0)
                self.health.emit(False)
            self.msleep(int(self.interval * 1000))

    def stop(self):
        self._running = False
        self.quit()
        self.wait()

    @staticmethod
    def _ping_once(host: str) -> float:
        try:
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", host]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", host]

            startupinfo = None
            if platform.system() == "Windows":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE

            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                startupinfo=startupinfo,
            )
            if proc.returncode != 0:
                return -1.0

            out = proc.stdout.lower()
            idx = out.find("time=")
            if idx == -1:
                idx = out.find("time<")
                if idx == -1:
                    return -1.0

            sub = out[idx:]
            for token in sub.split():
                if "ms" in token:
                    num = token.replace("time", "").replace("=", "").replace("<", "").replace("ms", "").replace(" ", "")
                    return float(num)
            return -1.0
        except Exception:
            return -1.0


# ===================== Graph View =====================

class NetworkGraphView(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setRenderHint(QPainter.Antialiasing)
        self.setFrameShape(QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)

        self.history = deque(maxlen=60)
        self.prev_stats = None

        self.in_path_item = QGraphicsPathItem()
        self.out_path_item = QGraphicsPathItem()

        self.in_path_item.setPen(QPen(QColor("#38bdf8"), 2.0))   # IN line
        self.out_path_item.setPen(QPen(QColor("#f472b6"), 2.0))  # OUT line

        self.scene.addItem(self.in_path_item)
        self.scene.addItem(self.out_path_item)

        self.grid_items = []
        self._init_grid()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._init_grid()
        self._update_paths()

    def _init_grid(self):
        for item in self.grid_items:
            self.scene.removeItem(item)
        self.grid_items.clear()

        pad = 8
        rect = QRectF(
            pad,
            pad,
            max(self.width() - pad * 2, 100),
            max(self.height() - pad * 2, 100),
        )
        self.scene.setSceneRect(rect)

        grid_pen = QPen(QColor(148, 163, 184, 40), 1.0)

        rows = 5
        for i in range(1, rows):
            y = rect.top() + rect.height() * i / rows
            line = QGraphicsLineItem(rect.left(), y, rect.right(), y)
            line.setPen(grid_pen)
            self.scene.addItem(line)
            self.grid_items.append(line)

        cols = 8
        for j in range(1, cols):
            x = rect.left() + rect.width() * j / cols
            line = QGraphicsLineItem(x, rect.top(), x, rect.bottom())
            line.setPen(grid_pen)
            self.scene.addItem(line)
            self.grid_items.append(line)

    def update_stats(self, data: dict):
        if self.prev_stats is not None:
            d_recv = max(0, data["bytes_recv"] - self.prev_stats["bytes_recv"])
            d_sent = max(0, data["bytes_sent"] - self.prev_stats["bytes_sent"])
            in_kb = d_recv / 1024.0
            out_kb = d_sent / 1024.0
            self.history.append((in_kb, out_kb))
        self.prev_stats = data
        self._update_paths()
        # force repaint to ensure updates are shown even after thread restarts[web:73][web:75]
        self.viewport().update()

    def _update_paths(self):
        if not self.history:
            return

        rect = self.scene.sceneRect()
        max_rate = max(max(v) for v in self.history)
        max_rate = max(max_rate, 1.0)

        n = len(self.history)
        if n < 2:
            return

        step_x = rect.width() / (n - 1)

        in_path = QPainterPath()
        out_path = QPainterPath()

        for idx, (in_kb, out_kb) in enumerate(self.history):
            x = rect.left() + idx * step_x
            y_in = rect.bottom() - (in_kb / max_rate) * rect.height()
            y_out = rect.bottom() - (out_kb / max_rate) * rect.height()
            if idx == 0:
                in_path.moveTo(x, y_in)
                out_path.moveTo(x, y_out)
            else:
                in_path.lineTo(x, y_in)
                out_path.lineTo(x, y_out)

        self.in_path_item.setPath(in_path)
        self.out_path_item.setPath(out_path)


# ===================== Interface Page (per NIC) =====================

class InterfacePage(QWidget):
    def __init__(self, interface_name: str, parent=None):
        super().__init__(parent)
        self.interface_name = interface_name

        self.in_rate = 0.0
        self.out_rate = 0.0
        self.total_in = 0.0
        self.total_out = 0.0
        self.packets = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        inner_header = QWidget()
        inner_header.setObjectName("InnerGraphHeader")
        ih_lay = QHBoxLayout(inner_header)
        ih_lay.setContentsMargins(16, 12, 16, 0)
        ih_lay.setSpacing(8)

        title_box = QVBoxLayout()
        title_lbl = QLabel(f"{interface_name} traffic")
        title_lbl.setObjectName("GraphTitle")
        sub_lbl = QLabel("Realtime interface consumption")
        sub_lbl.setObjectName("GraphSubtitle")
        title_box.addWidget(title_lbl)
        title_box.addWidget(sub_lbl)
        ih_lay.addLayout(title_box)

        ih_lay.addStretch()

        self.btn_rt = QPushButton("Realtime")
        self.btn_rt.setObjectName("FilterChip")
        self.btn_rt.setProperty("active", True)

        self.btn_1m = QPushButton("1 min")
        self.btn_1m.setObjectName("FilterChip")
        self.btn_1m.setProperty("active", False)

        self.btn_5m = QPushButton("5 min")
        self.btn_5m.setObjectName("FilterChip")
        self.btn_5m.setProperty("active", False)

        ih_lay.addWidget(self.btn_rt)
        ih_lay.addWidget(self.btn_1m)
        ih_lay.addWidget(self.btn_5m)

        graph_container = QWidget()
        graph_container.setObjectName("GraphContainer")
        gc_lay = QVBoxLayout(graph_container)
        gc_lay.setContentsMargins(16, 8, 16, 16)
        gc_lay.setSpacing(0)

        self.graph = NetworkGraphView()
        gc_lay.addWidget(self.graph)

        stats_row = QWidget()
        stats_row.setObjectName("StatsRow")
        sr_lay = QHBoxLayout(stats_row)
        sr_lay.setContentsMargins(0, 0, 0, 0)
        sr_lay.setSpacing(10)

        self.card_in = self._create_stat_card("Inbound", "0.0 KB/s")
        self.card_out = self._create_stat_card("Outbound", "0.0 KB/s")
        self.card_total = self._create_stat_card("Total", "0.0 MB")
        self.card_packets = self._create_stat_card("Packets", "0")

        sr_lay.addWidget(self.card_in)
        sr_lay.addWidget(self.card_out)
        sr_lay.addWidget(self.card_total)
        sr_lay.addWidget(self.card_packets)

        layout.addWidget(inner_header)
        layout.addWidget(graph_container, 1)
        layout.addWidget(stats_row)

    def _create_stat_card(self, title, value):
        card = QWidget()
        card.setObjectName("StatCard")
        v = QVBoxLayout(card)
        v.setContentsMargins(16, 12, 16, 12)
        v.setSpacing(4)

        t = QLabel(title)
        t.setProperty("statTitle", True)
        val = QLabel(value)
        val.setProperty("statValue", True)

        v.addWidget(t)
        v.addWidget(val)
        v.addStretch()
        card.value_label = val
        return card

    def update_from_stats(self, data):
        if hasattr(self, "_prev"):
            d_recv = max(0, data["bytes_recv"] - self._prev["bytes_recv"])
            d_sent = max(0, data["bytes_sent"] - self._prev["bytes_sent"])
            self.in_rate = d_recv / 1024.0
            self.out_rate = d_sent / 1024.0
        self._prev = data

        self.total_in = data["bytes_recv"] / (1024 * 1024)
        self.total_out = data["bytes_sent"] / (1024 * 1024)
        self.packets = data["packets_recv"] + data["packets_sent"]

        self.graph.update_stats(data)

        self.card_in.value_label.setText(f"{self.in_rate:.1f} KB/s")
        self.card_out.value_label.setText(f"{self.out_rate:.1f} KB/s")
        self.card_total.value_label.setText(f"{(self.total_in + self.total_out):.1f} MB")
        self.card_packets.value_label.setText(str(self.packets))


# ===================== Header Bar (Overview) =====================

class HeaderBar(QWidget):
    interface_selected = Signal(int)

    def __init__(self, interfaces, parent=None):
        super().__init__(parent)
        self.interfaces = interfaces
        self.current_index = 0

        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(16)

        shield_icon_label = QLabel()
        shield_icon_label.setPixmap(QPixmap(system_ico).scaled(48, 48, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        shield_icon_label.setFixedSize(48, 48)
        shield_icon_label.setAlignment(Qt.AlignCenter)
        shield_icon_label.setScaledContents(False)
        layout.addWidget(shield_icon_label)

        title_box = QVBoxLayout()
        lbl_title = QLabel("Sentinel NetScope")
        lbl_title.setObjectName("HeaderTitle")
        lbl_bread = QLabel("Dashboard · Live monitoring")
        lbl_bread.setObjectName("HeaderBreadcrumb")
        title_box.addWidget(lbl_title)
        title_box.addWidget(lbl_bread)
        layout.addLayout(title_box)

        layout.addStretch()

        seg_container = QWidget()
        seg_container.setObjectName("SegmentContainer")
        seg_container.setFixedWidth(300)
        seg_lay = QHBoxLayout(seg_container)
        seg_lay.setContentsMargins(4, 4, 4, 4)
        seg_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        seg_lay.setSpacing(4)

        self.seg_buttons = []
        for idx, iface in enumerate(self.interfaces):
            btn = QPushButton(iface)
            btn.setObjectName("Segment")
            btn.setCheckable(True)
            btn.setChecked(idx == 0)
            btn.setProperty("active", idx == 0)
            btn.clicked.connect(lambda checked, i=idx: self._segment_clicked(i))
            self.seg_buttons.append(btn)
            seg_lay.addWidget(btn)

        layout.addWidget(seg_container)

        icon_path_close = find_menu("menu/close.png")
        close_btn = QPushButton()
        close_btn.setFixedSize(30, 30)
        close_btn.setIcon(QIcon(icon_path_close))
        close_btn.clicked.connect(self._close_main)
        close_btn.setObjectName("closeButton")
        close_btn.setStyleSheet("""
        QPushButton {
            background-color: #000000;
            color: #e5e7eb;
            border: 1px solid #000000;
            border-radius: 8px;
            font-size: 14px;
        }
        QPushButton:hover {
            background-color: #27272a;
        }
        QPushButton:pressed {
            background-color: #0f172a;
        }
        #closeButton {
            border-radius: 6px;
        }
        """)

        layout.addWidget(close_btn)

    def _segment_clicked(self, idx):
        if idx == self.current_index:
            return
        self.current_index = idx
        for i, b in enumerate(self.seg_buttons):
            active = (i == idx)
            b.setChecked(active)
            b.setProperty("active", active)
            b.style().unpolish(b)
            b.style().polish(b)
        self.interface_selected.emit(idx)

    def _close_main(self):
        win = self.window()
        if isinstance(win, QMainWindow):
            win.close()

    def _min_main(self):
        win = self.window()
        if isinstance(win, QMainWindow):
            win.showMinimized()


# ===================== Main Window (Overview only) =====================

class NetPage(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel NetScope")
        self.setWindowIcon(QIcon(find_items('icons/icon.png') or 'icons/icon.png'))
        self.setStyleSheet(qss)
        self.resize(1280, 768)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowMinimizeButtonHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

        self._drag_pos = QPoint()

        outer = QWidget()
        outer.setObjectName("Outer")
        outer_lay = QVBoxLayout(outer)
        outer_lay.setContentsMargins(16, 16, 16, 16)
        outer_lay.setSpacing(0)

        shell = QWidget()
        shell.setObjectName("Shell")
        shell_lay = QHBoxLayout(shell)
        shell_lay.setContentsMargins(12, 12, 12, 12)
        shell_lay.setSpacing(12)

        center = QWidget()
        center.setObjectName("Center")
        center_lay = QVBoxLayout(center)
        center_lay.setContentsMargins(0, 0, 0, 0)
        center_lay.setSpacing(12)

        # Interface ordering: Wi-Fi first, then Ethernet, then others
        all_ifaces = list(psutil.net_io_counters(pernic=True, nowrap=True).keys())
        wifi = [i for i in all_ifaces if "wi" in i.lower() or "wlan" in i.lower()]
        eth = [i for i in all_ifaces if "eth" in i.lower() or "en" in i.lower() or "lan" in i.lower()]
        others = [i for i in all_ifaces if i not in wifi and i not in eth and "lo" not in i.lower()]
        self.interfaces = wifi + eth + others
        if not self.interfaces:
            self.interfaces = all_ifaces or ["Wi-Fi"]

        self.interfaces = self.interfaces[:3]  # clamp to 3 UI segments

        # Overview components
        self.header_bar = HeaderBar(self.interfaces)
        self.header_bar.setObjectName("HeaderBar")
        self.header_bar.interface_selected.connect(self.switch_interface)

        self.overview_container = QWidget()
        oc_lay = QVBoxLayout(self.overview_container)
        oc_lay.setContentsMargins(0, 0, 0, 0)
        oc_lay.setSpacing(12)

        self.graph_card = QWidget()
        self.graph_card.setObjectName("GraphCard")
        gc_lay = QVBoxLayout(self.graph_card)
        gc_lay.setContentsMargins(18, 18, 18, 18)
        gc_lay.setSpacing(0)

        self.graph_host = QWidget()
        self.graph_host_lay = QVBoxLayout(self.graph_host)
        self.graph_host_lay.setContentsMargins(0, 0, 0, 0)
        self.graph_host_lay.setSpacing(0)

        # stacked interface pages => persistent state per interface
        self.page_stack = QStackedWidget()
        self.graph_host_lay.addWidget(self.page_stack)
        gc_lay.addWidget(self.graph_host)

        self.bottom_stats = QWidget()
        self.bottom_stats.setObjectName("BottomStats")
        bs_lay = QHBoxLayout(self.bottom_stats)
        bs_lay.setContentsMargins(0, 12, 0, 0)
        bs_lay.setSpacing(10)

        self.bottom_stat_1 = self._create_bottom_tile("Latency", "— ms")
        self.bottom_stat_2 = self._create_bottom_tile("Packet loss", "0")
        self.bottom_stat_3 = self._create_bottom_tile("Active connections", "0")
        self.bottom_stat_4 = self._create_bottom_tile("Alerts", "0")

        bs_lay.addWidget(self.bottom_stat_1)
        bs_lay.addWidget(self.bottom_stat_2)
        bs_lay.addWidget(self.bottom_stat_3)
        bs_lay.addWidget(self.bottom_stat_4)

        gc_lay.addWidget(self.bottom_stats)
        oc_lay.addWidget(self.graph_card, 1)

        center_lay.addWidget(self.header_bar)
        center_lay.addWidget(self.overview_container, 1)

        shell_lay.addWidget(center, 1)
        outer_lay.addWidget(shell)
        self.setCentralWidget(outer)

        self.pages = {}        # iface -> InterfacePage
        self.workers = {}      # iface -> NetworkWorker
        self.last_emit_time = {}  # iface -> last data timestamp

        self.current_interface_idx = 0

        # ensure first interface page exists and is active
        self._ensure_interface_page(0)
        self.page_stack.setCurrentIndex(0)

        # latency worker (ping a default host, e.g. 8.8.8.8)
        self.latency_value = -1.0
        self.last_latency_time = 0.0
        self.latency_worker = LatencyWorker(target="8.8.8.8", interval=2.0, parent=self)
        self.latency_worker.latency_updated.connect(self._on_latency_updated)
        self.latency_worker.health.connect(self._on_latency_health)
        self.latency_worker.start()

        # bottom stats live update
        self._stats_timer = QTimer(self)
        self._stats_timer.timeout.connect(self.update_overview_stats)
        self._stats_timer.start(1000)

        # watchdog for workers & latency
        self._watchdog_timer = QTimer(self)
        self._watchdog_timer.timeout.connect(self._check_workers_health)
        self._watchdog_timer.start(2000)

    def _create_bottom_tile(self, title, value):
        tile = QWidget()
        tile.setObjectName("BottomTile")
        v = QVBoxLayout(tile)
        v.setContentsMargins(14, 12, 14, 12)
        v.setSpacing(2)
        t = QLabel(title)
        t.setProperty("statTitle", True)
        val = QLabel(value)
        val.setProperty("statValueSmall", True)
        v.addWidget(t)
        v.addWidget(val)
        return tile

    def _ensure_interface_page(self, idx: int):
        if idx < 0 or idx >= len(self.interfaces):
            return
        iface = self.interfaces[idx]

        if iface in self.pages:
            return

        page = InterfacePage(iface)
        self.pages[iface] = page
        self.page_stack.addWidget(page)

        worker = NetworkWorker(iface)

        # Wrap update handler to record last emit timestamp
        def on_data(data, iface_name=iface, page_ref=page):
            # print(f"{iface_name} in={data['bytes_recv']} out={data['bytes_sent']}")  # debug
            self.last_emit_time[iface_name] = time.time()
            page_ref.update_from_stats(data)

        worker.data_updated.connect(on_data)
        worker.health.connect(lambda ok, iface_name=iface: self._on_worker_health(iface_name, ok))
        worker.start()
        self.workers[iface] = worker
        self.last_emit_time[iface] = time.time()

    def switch_interface(self, idx):
        if idx == self.current_interface_idx:
            return
        self.current_interface_idx = idx
        self._ensure_interface_page(idx)
        self.page_stack.setCurrentIndex(idx)

    def _on_latency_updated(self, value_ms: float):
        self.latency_value = value_ms
        self.last_latency_time = time.time()

    def _on_latency_health(self, ok: bool):
        if ok:
            self.last_latency_time = time.time()

    def _on_worker_health(self, iface: str, ok: bool):
        if ok:
            self.last_emit_time[iface] = time.time()

    def _check_workers_health(self):
        now = time.time()
        # restart stalled interface workers (no data for > 10s)
        for iface in list(self.workers.keys()):
            last = self.last_emit_time.get(iface, 0)
            if now - last > 10:
                print(f"[Watchdog] Restarting stalled worker for {iface}")
                w = self.workers.pop(iface)
                w.stop()
                # reset page/graph prev stats so we get fresh deltas
                page = self.pages.get(iface)
                if page is not None and hasattr(page, "_prev"):
                    del page._prev
                if page is not None and hasattr(page.graph, "prev_stats"):
                    page.graph.prev_stats = None
                idx = self.interfaces.index(iface)
                self._ensure_interface_page(idx)

        # restart latency worker if no update > 15s
        if now - self.last_latency_time > 15:
            if hasattr(self, "latency_worker") and self.latency_worker.isRunning():
                print("[Watchdog] Restarting stalled latency worker")
                self.latency_worker.stop()
            self.latency_worker = LatencyWorker(target="8.8.8.8", interval=2.0, parent=self)
            self.latency_worker.latency_updated.connect(self._on_latency_updated)
            self.latency_worker.health.connect(self._on_latency_health)
            self.latency_worker.start()
            self.last_latency_time = now

    def update_overview_stats(self):
        if not self.interfaces:
            return
        iface = self.interfaces[self.current_interface_idx]

        # latency tile (average ms from LatencyWorker)
        latency_label = self.bottom_stat_1.findChildren(QLabel)[1]
        if self.latency_value >= 0:
            latency_label.setText(f"{self.latency_value:.0f} ms")
        else:
            latency_label.setText("— ms")

        # packet loss for current interface (dropin + dropout)
        try:
            io_all = psutil.net_io_counters(pernic=True, nowrap=True)
            if iface in io_all:
                s = io_all[iface]
                drop_total = getattr(s, "dropin", 0) + getattr(s, "dropout", 0)
            else:
                drop_total = 0
        except Exception as e:
            print(f"[Stats] packet loss error: {e}")
            drop_total = 0

        # active connections (system-wide for now)
        try:
            conns = psutil.net_connections(kind="inet")
            active = sum(1 for c in conns if c.status == psutil.CONN_ESTABLISHED)
        except Exception as e:
            print(f"[Stats] active connections error: {e}")
            active = 0

        packet_loss_label = self.bottom_stat_2.findChildren(QLabel)[1]
        packet_loss_label.setText(str(drop_total))

        active_conn_label = self.bottom_stat_3.findChildren(QLabel)[1]
        active_conn_label.setText(str(active))

        # total traffic (all interfaces combined) since boot
        try:
            io_tot = psutil.net_io_counters(nowrap=True)
            total_bytes = io_tot.bytes_sent + io_tot.bytes_recv
        except Exception as e:
            print(f"[Stats] total traffic error: {e}")
            total_bytes = 0

        total_mb = total_bytes / (1024 * 1024)
        if total_mb < 1024:
            total_text = f"{total_mb:.1f} MB"
        else:
            total_gb = total_mb / 1024
            total_text = f"{total_gb:.2f} GB"

        # alerts tile remains static for now
        alerts_label = self.bottom_stat_4.findChildren(QLabel)[1]
        alerts_label.setText("0")

    # frameless dragging
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() & Qt.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def closeEvent(self, event):
        # cleanly stop all workers
        for w in self.workers.values():
            w.stop()
        if hasattr(self, "latency_worker") and self.latency_worker.isRunning():
            self.latency_worker.stop()
        event.accept()


# ===================== main =====================

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    w = NetPage()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
