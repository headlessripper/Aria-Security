# SentinelTaskManager.py

import sys
import time
import psutil

from PySide6.QtCore import Qt, QThread, Signal, QTimer, QPoint, QRect
from PySide6.QtGui import QIcon, QPainterPath, QRegion, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
    QAbstractItemView,
    QFrame,
    QHeaderView,
)
from Main_Unit.Service.Pages.Style_Qss.qss import qss as DARK_QSS
from Main_Unit.Service.find_menu import find_menu
from Main_Unit.find_items import find_items
from Main_Unit.Config.Sys_Config import SYSTEM_ICON_PATH

system_ico = find_items(SYSTEM_ICON_PATH)

# ===================== Dark shadcn-like QSS =====================


# ===================== HeaderBar (used as custom frame/title bar) =====================

class HeaderBar(QWidget):
    interface_selected = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_index = 0

        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(16)
        
        # Custom app icon from local file
        shield_icon_label = QLabel()
        shield_icon_label.setPixmap(QPixmap(system_ico).scaled(48, 48, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        shield_icon_label.setFixedSize(48, 48)
        shield_icon_label.setAlignment(Qt.AlignCenter)
        shield_icon_label.setScaledContents(False)
        layout.addWidget(shield_icon_label)

        title_box = QVBoxLayout()
        lbl_title = QLabel("Sentinel TaskScope")
        lbl_title.setObjectName("HeaderTitle")
        lbl_bread = QLabel("Dashboard · Top 20 processes")
        lbl_bread.setObjectName("HeaderBreadcrumb")
        title_box.addWidget(lbl_title)
        title_box.addWidget(lbl_bread)
        layout.addLayout(title_box)

        layout.addStretch()

        # In this standalone file we skip icons, just use text buttons
        icon_path_notif = find_items("icons/monitor.png")
        notif = QPushButton()
        notif.setIcon(QIcon(icon_path_notif))
        notif.setFixedSize(30, 30)
        notif.clicked.connect(self._min_main)
        notif.setObjectName("IconButton")

        icon_path_close = find_menu("menu/close.png")
        close_btn = QPushButton()
        close_btn.setIcon(QIcon(icon_path_close))
        close_btn.setFixedSize(30, 30)
        close_btn.clicked.connect(self._close_main)
        close_btn.setObjectName("closeButton")

        #layout.addWidget(notif)
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


# ===================== Worker: top 20 by memory =====================

class ProcessWorker(QThread):
    processes_updated = Signal(list)  # list of dict

    def __init__(self, interval=2.0, parent=None):
        super().__init__(parent)
        self.interval = interval
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        while self._running:
            proc_info_list = []
            for p in psutil.process_iter(["pid", "name", "memory_info", "cpu_percent", "status"]):
                if not self._running:
                    break
                try:
                    mem_info = p.info.get("memory_info")
                    rss = mem_info.rss if mem_info else 0
                    info = {
                        "pid": p.pid,                              # p.pid is always safe; p.info["pid"] can KeyError on process exit
                        "name": p.info.get("name") or "Unknown",
                        "memory": rss,
                        "cpu_percent": p.info.get("cpu_percent") or 0.0,
                        "status": p.info.get("status", ""),
                    }
                    proc_info_list.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, KeyError):
                    continue

            proc_info_list.sort(key=lambda x: x["memory"], reverse=True)
            top20 = proc_info_list[:20]
            self.processes_updated.emit(top20)
            self.msleep(int(self.interval * 1000))


# ===================== Main Window (frameless, rounded, HeaderBar) =====================

class TaskPage(QMainWindow):
    RADIUS = 16

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel TaskScope")
        self.setWindowIcon(QIcon(find_items('icons/icon.png') or 'icons/icon.png'))
        self.resize(1100, 680)
        self.setStyleSheet(DARK_QSS)
        self.setWindowFlag(Qt.FramelessWindowHint, True)
        self.setAttribute(Qt.WA_TranslucentBackground, True)

        self._drag_pos = QPoint()
        self.process_data = []

        # Root & shell
        root = QWidget()
        root.setObjectName("Root")
        outer = QVBoxLayout(root)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(0)

        shell = QFrame()
        shell.setObjectName("Shell")
        shell_lay = QVBoxLayout(shell)
        shell_lay.setContentsMargins(0, 0, 0, 0)
        shell_lay.setSpacing(0)

        # HeaderBar used as custom frame/title bar
        self.header_bar = HeaderBar()
        self.header_bar.setObjectName("HeaderBar")
        shell_lay.addWidget(self.header_bar)

        # Content
        content = QWidget()
        content_lay = QVBoxLayout(content)
        content_lay.setContentsMargins(20, 12, 20, 16)
        content_lay.setSpacing(14)

        # sub-header under HeaderBar
        hdr = QHBoxLayout()
        left = QVBoxLayout()
        lbl_title = QLabel("Memory overview")
        lbl_title.setProperty("role", "headerTitle")
        lbl_sub = QLabel("Top 20 processes by memory usage")
        lbl_sub.setProperty("role", "headerSubtitle")
        left.addWidget(lbl_title)
        left.addWidget(lbl_sub)
        hdr.addLayout(left)
        hdr.addStretch()

        self.btn_refresh = QPushButton("Refresh now")
        self.btn_refresh.setProperty("variant", "primary")
        self.btn_refresh.clicked.connect(self.request_manual_refresh)
        hdr.addWidget(self.btn_refresh)

        content_lay.addLayout(hdr)

        # stats row
        stats_row = QHBoxLayout()
        stats_row.setSpacing(14)
        self.card_cpu = self._create_stat_card("CPU usage", "— %", "Combined CPU load")
        self.card_mem = self._create_stat_card("Memory", "— %", "RAM usage")
        self.card_proc = self._create_stat_card("Processes", "0", "Total processes")
        self.card_top = self._create_stat_card("Top process", "—", "By memory")
        stats_row.addWidget(self.card_cpu, 1)
        stats_row.addWidget(self.card_mem, 1)
        stats_row.addWidget(self.card_proc, 1)
        stats_row.addWidget(self.card_top, 1)
        content_lay.addLayout(stats_row)

        # main card
        main_card = QFrame()
        main_card.setProperty("card", True)
        mc_lay = QVBoxLayout(main_card)
        mc_lay.setContentsMargins(18, 16, 18, 16)
        mc_lay.setSpacing(10)

        mc_header = QHBoxLayout()
        block = QVBoxLayout()
        lbl_table_title = QLabel("Top processes")
        lbl_table_title.setProperty("role", "headerTitle")
        lbl_table_sub = QLabel("Real‑time memory and CPU usage")
        lbl_table_sub.setProperty("role", "headerSubtitle")
        block.addWidget(lbl_table_title)
        block.addWidget(lbl_table_sub)
        mc_header.addLayout(block)
        mc_header.addStretch()
        mc_lay.addLayout(mc_header)

        table_container = QWidget()
        table_container.setProperty("card", "sub")
        tc_lay = QVBoxLayout(table_container)
        tc_lay.setContentsMargins(10, 8, 10, 10)
        tc_lay.setSpacing(4)

        self.table = QTableWidget(0, 6, self)
        self.table.setHorizontalHeaderLabels(
            ["Name", "PID", "Memory (MB)", "CPU %", "Status", ""]
        )
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)

        tc_lay.addWidget(self.table)
        mc_lay.addWidget(table_container, 1)

        card_footer = QLabel("Ending critical system processes may cause instability or data loss.")
        card_footer.setProperty("role", "footer")
        mc_lay.addWidget(card_footer)

        content_lay.addWidget(main_card, 1)

        self.footer_label = QLabel("Updates every 2 seconds. Sorted by private memory (RSS).")
        self.footer_label.setProperty("role", "footer")
        content_lay.addWidget(self.footer_label)

        shell_lay.addWidget(content)
        outer.addWidget(shell)
        self.setCentralWidget(root)

        # worker & timers
        self.worker = ProcessWorker(interval=2.0, parent=self)
        self.worker.processes_updated.connect(self.update_from_worker)
        self.worker.start()

        self._can_manual_refresh = True
        self._manual_timer = QTimer(self)
        self._manual_timer.setSingleShot(True)
        self._manual_timer.timeout.connect(self._enable_manual_refresh)

        self._summary_timer = QTimer(self)
        self._summary_timer.timeout.connect(self.update_summary_stats)
        self._summary_timer.start(1000)

        self._update_mask()

    # ----- rounded mask -----

    def _update_mask(self):
        rect = QRect(0, 0, self.width(), self.height())
        path = QPainterPath()
        path.addRoundedRect(rect, 16, 16)
        region = QRegion(path.toFillPolygon().toPolygon())
        self.setMask(region)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_mask()

    # ----- helpers -----

    def _create_stat_card(self, title, value, sub) -> QFrame:
        card = QFrame()
        card.setProperty("card", True)
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(6)

        t = QLabel(title)
        t.setProperty("role", "statTitle")
        v = QLabel(value)
        v.setProperty("role", "statValue")
        s = QLabel(sub)
        s.setProperty("role", "statSub")

        lay.addWidget(t)
        lay.addWidget(v)
        lay.addWidget(s)
        lay.addStretch()

        card.value_label = v
        card.sub_label = s
        return card

    # ----- worker updates -----

    def update_from_worker(self, processes: list):
        self.process_data = processes
        self._update_table(processes)
        self._update_process_card(processes)

    def _update_table(self, processes: list):
        self.table.setRowCount(len(processes))
        for row, info in enumerate(processes):
            name_item = QTableWidgetItem(info["name"])
            pid_item = QTableWidgetItem(str(info["pid"]))
            mem_mb = info["memory"] / (1024 * 1024)
            mem_item = QTableWidgetItem(f"{mem_mb:.1f}")
            cpu_item = QTableWidgetItem(f"{info['cpu_percent']:.1f}")
            status_item = QTableWidgetItem(info["status"])

            for it in (name_item, pid_item, mem_item, cpu_item, status_item):
                it.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)

            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, pid_item)
            self.table.setItem(row, 2, mem_item)
            self.table.setItem(row, 3, cpu_item)
            self.table.setItem(row, 4, status_item)

            btn = QPushButton("End task")
            btn.setProperty("variant", "destructive")
            btn.setMinimumWidth(88)
            btn.clicked.connect(
                lambda checked=False, pid=info["pid"], name=info["name"]: self.end_task(pid, name)
            )
            self.table.setCellWidget(row, 5, btn)

    def _update_process_card(self, processes: list):
        total = len(processes)
        self.card_proc.value_label.setText(str(total))
        if processes:
            top = processes[0]
            mem_mb = top["memory"] / (1024 * 1024)
            self.card_top.value_label.setText(top["name"])
            self.card_top.sub_label.setText(f"PID {top['pid']} · {mem_mb:.1f} MB")
        else:
            self.card_top.value_label.setText("—")
            self.card_top.sub_label.setText("No processes.")

    # ----- system summary -----

    def update_summary_stats(self):
        try:
            cpu = psutil.cpu_percent(interval=None)
        except Exception:
            cpu = 0.0
        self.card_cpu.value_label.setText(f"{cpu:.0f} %")

        try:
            mem = psutil.virtual_memory()
            self.card_mem.value_label.setText(f"{mem.percent:.0f} %")
            self.card_mem.sub_label.setText(
                f"{mem.used / (1024**3):.1f} / {mem.total / (1024**3):.1f} GB"
            )
        except Exception:
            self.card_mem.value_label.setText("— %")
            self.card_mem.sub_label.setText("Memory info unavailable")

    # ----- end task -----

    def end_task(self, pid: int, name: str):
        reply = QMessageBox.question(
            self,
            "End task",
            f"Are you sure you want to end:\n\n{name} (PID {pid})?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except psutil.TimeoutExpired:
                proc.kill()
            QMessageBox.information(
                self, "End task", f"Process {name} (PID {pid}) terminated."
            )
        except psutil.NoSuchProcess:
            QMessageBox.warning(self, "End task", "Process no longer exists.")
        except psutil.AccessDenied:
            QMessageBox.critical(
                self,
                "End task",
                "Access denied. Try running Sentinel as administrator.",
            )
        except Exception as e:
            QMessageBox.critical(self, "End task", f"Failed to terminate process:\n{e}")

    # ----- manual refresh -----

    def request_manual_refresh(self):
        if not hasattr(self, "_can_manual_refresh") or not self._can_manual_refresh:
            return
        self.footer_label.setText("Waiting for next auto update…")
        self._can_manual_refresh = False
        self._manual_timer.start(1500)

    def _enable_manual_refresh(self):
        self._can_manual_refresh = True
        self.footer_label.setText("Updates every 2 seconds. Sorted by private memory (RSS).")

    # ----- frameless drag -----

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() & Qt.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    # ----- cleanup -----

    def closeEvent(self, event):
        if hasattr(self, "worker") and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        event.accept()


# ===================== main =====================

#def main():
#    app = QApplication(sys.argv)
#    app.setStyle("Fusion")
#    app.setStyleSheet(DARK_QSS)
#    w = MainWindow()
#    w.show()
#    sys.exit(app.exec())


#if __name__ == "__main__":
#    main()
