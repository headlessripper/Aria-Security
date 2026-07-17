import os
import shutil
import threading
import time
import queue
import socket
from datetime import datetime
from cryptography.fernet import Fernet
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QScrollArea, QFrame, QListWidget,
    QListWidgetItem, QMessageBox, QStackedWidget
)
from PySide6.QtCore import Qt, Signal, QObject, QTimer, Slot, QFileSystemWatcher, QPoint, QSize
from PySide6.QtGui import QFont, QPixmap, QIcon
from pathlib import Path
from typing import Dict
import qtawesome as qta
import json

from Main_Unit.Service.find_menu import find_menu
from Main_Unit.Config.Sys_Config import SYSTEM_ICON_PATH, COMMAND_PORT

# =========================
# Central Quarantine Directory
# =========================

QUARANTINE_ROOT = Path.home() / ".AriaSecurity" / ".SentinelQuarantine"
QUARANTINE_ROOT.mkdir(parents=True, exist_ok=True)

METADATA_FILE = QUARANTINE_ROOT / "quarantine_metadata.json"


# =========================
# Global metadata helpers
# =========================

def save_quarantine_metadata(quar_dir: str, basename: str, orig_path: str):
    """Scanner calls this after quarantine creation."""
    metadata_path = METADATA_FILE
    try:
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
        else:
            metadata = {}
        metadata[quar_dir] = {'basename': basename, 'orig_path': orig_path}
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"📝 Saved metadata for {quar_dir}")
    except Exception as e:
        print(f"❌ Metadata save failed: {e}")


def load_quarantine_metadata() -> Dict:
    """UI loads all quarantines."""
    metadata_path = METADATA_FILE
    if metadata_path.exists():
        with open(metadata_path, 'r') as f:
            return json.load(f)
    return {}


def remove_quarantine_metadata(quar_dir: str):
    """Cleanup after restore/delete."""
    metadata_path = METADATA_FILE
    if metadata_path.exists():
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        if quar_dir in metadata:
            del metadata[quar_dir]
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)


# =========================
# Quarantine domain objects
# =========================

class QuarantineItem(QObject):
    restored = Signal(str)
    deleted = Signal(str)

    def __init__(self, quar_dir: str, enc_path: str, basename: str, orig_path: str):
        super().__init__()
        self.quar_dir = quar_dir          # string path to directory
        self.enc_path = enc_path          # string path to encrypted file
        self.basename = basename
        self.orig_path = orig_path
        # key lives next to the quarantine folder in QUARANTINE_ROOT
        self.key_path = QUARANTINE_ROOT / f"{Path(quar_dir).name}.key"

    @Slot()
    def restore(self):
        if not self.key_path.exists() or not Path(self.enc_path).exists():
            print(f"❌ Files missing: {self.key_path}, {self.enc_path}")
            return False
        try:
            with open(self.key_path, 'rb') as kf:
                key = kf.read()
            fernet = Fernet(key)
            with open(self.enc_path, 'rb') as src:
                encrypted_data = src.read()
            decrypted_data = fernet.decrypt(encrypted_data)

            # Ensure original directory exists
            orig_parent = Path(self.orig_path).parent
            orig_parent.mkdir(parents=True, exist_ok=True)

            with open(self.orig_path, 'wb') as dst:
                dst.write(decrypted_data)
            print(f"✅ Restored '{self.basename}' → {self.orig_path}")

            # Remove quarantine folder and key
            shutil.rmtree(self.quar_dir)
            if self.key_path.exists():
                self.key_path.unlink()

            remove_quarantine_metadata(self.quar_dir)
            self.restored.emit(self.quar_dir)
            return True
        except Exception as e:
            print(f"❌ Restore failed: {e}")
            return False

    @Slot()
    def delete(self):
        try:
            if Path(self.quar_dir).exists():
                shutil.rmtree(self.quar_dir)
            if self.key_path.exists():
                self.key_path.unlink()
            print(f"🗑️ Deleted: {self.quar_dir}")
            remove_quarantine_metadata(self.quar_dir)
            self.deleted.emit(self.quar_dir)
        except Exception as e:
            print(f"❌ Delete failed: {e}")


class QuarantineMonitor(QObject):
    newQuarantine = Signal(str, str, str, str)

    def __init__(self):
        super().__init__()
        self.watcher = QFileSystemWatcher()
        self.watcher.directoryChanged.connect(self.on_dir_changed)
        # Watch the central quarantine root
        self.watcher.addPath(str(QUARANTINE_ROOT))
        self.load_metadata()

    def load_metadata(self):
        metadata = load_quarantine_metadata()
        for quar_dir, data in metadata.items():
            enc_path = os.path.join(quar_dir, data['basename'])
            key_path = QUARANTINE_ROOT / f"{Path(quar_dir).name}.key"
            if key_path.exists() and Path(enc_path).exists():
                self.newQuarantine.emit(quar_dir, enc_path, data['basename'], data['orig_path'])

    @Slot(str)
    def on_dir_changed(self, path):
        self.check_new_quarantines()

    def check_new_quarantines(self):
        metadata = load_quarantine_metadata()
        for quar_dir in metadata:
            key_path = QUARANTINE_ROOT / f"{Path(quar_dir).name}.key"
            if key_path.exists():
                data = metadata[quar_dir]
                enc_path = os.path.join(quar_dir, data['basename'])
                if Path(enc_path).exists():
                    self.newQuarantine.emit(quar_dir, enc_path, data['basename'], data['orig_path'])


# =========================
# Core Task Model
# =========================

class Task:
    """Represents a single threat handling task."""
    def __init__(self, file_path: str, task_id: int):
        self.file_path = file_path
        self.task_id = task_id
        self.action = None          # 'quarantine' or 'destroy'
        self.app_name = os.path.basename(file_path)  # name.ext


# =========================
# GUI Components
# =========================

class NotificationWindow(QFrame):
    """Floating notification with custom frameless title bar."""
    decision = Signal(int, str)  # task_id, action

    def __init__(self, task: Task, parent=None):
        super().__init__(parent)
        self.task = task
        self.setObjectName("notificationWindow")

        # Frameless + always on top
        self.setWindowFlags(
            Qt.FramelessWindowHint |
            Qt.WindowStaysOnTopHint |
            Qt.Tool
        )
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.resize(380, 140)

        self.old_pos = QPoint()

        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(1, 1, 1, 1)
        main_layout.setSpacing(0)

        # Container
        container = QWidget()
        container.setObjectName("container")
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(0)

        # Title bar
        title_bar = QWidget()
        title_bar.setFixedHeight(40)
        title_bar.setObjectName("titleBar")
        title_bar_layout = QHBoxLayout(title_bar)
        title_bar_layout.setContentsMargins(12, 0, 12, 0)
        title_bar_layout.setSpacing(8)

        # App icon
        icon_path_label = SYSTEM_ICON_PATH
        icon_label = QLabel()
        icon_label.setPixmap(QPixmap(f"{icon_path_label}").scaled(24, 24, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        icon_label.setFixedSize(24, 24)

        # Threat title
        threat_title = QLabel(f"Sentinel Treat Alert: {task.app_name}")
        threat_title.setFont(QFont("Segoe UI", 11, QFont.Bold))
        threat_title.setAlignment(Qt.AlignVCenter)

        title_bar_layout.addWidget(icon_label)
        title_bar_layout.addWidget(threat_title)
        title_bar_layout.addStretch()

        # Content area
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(20, 12, 20, 16)

        # Path label
        short_path = task.file_path[:70] + "..." if len(task.file_path) > 70 else task.file_path
        path_lbl = QLabel(short_path)
        path_lbl.setWordWrap(True)
        path_lbl.setStyleSheet("color: #9ca3af; font-size: 11px;")

        # Action buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        action = QPushButton("Action Center")
        action.clicked.connect(lambda: self._emit_decision("action_center"))

        btn_row.addWidget(action)
        content_layout.addWidget(path_lbl)
        content_layout.addLayout(btn_row)

        # Assemble
        container_layout.addWidget(title_bar)
        container_layout.addWidget(content_widget)
        main_layout.addWidget(container)
        self.title_bar = title_bar

        # Auto-close after 5 min (independent of auto-quarantine)
        QTimer.singleShot(300000, self.close)

        self.setStyleSheet("""
        #container {
            background: #0e0e0e;
            border-radius: 10px;
        }
        #titleBar {
            background-color: #121212;
            border-top-left-radius: 10px;
            border-top-right-radius: 10px;
        }
        #card {
            background-color: #2e2e2e;
            border-radius: 10px;
            border: transparent;
        }
        QLabel {
            color: #e5e7eb;
        }
        QPushButton {
            background-color: #18181b;
            color: #e5e7eb;
            border: 1px solid #27272a;
            border-radius: 8px;
            font-size: 14px;
        }
        QPushButton:hover {
            background-color: #27272a;
        }
        QPushButton:pressed {
            background-color: #0f172a;
        }
        #pageButton {
            border-radius: 6px;
            border: none;
            background-color: transparent;
        }
        #pageButton:hover {
            background-color: #1f2937;
        }
        #closeButton {
            border-radius: 6px;
        }
        """)

    def show_at_top_right(self):
        screen = QApplication.primaryScreen()
        if not screen:
            self.show()
            return
        geo = screen.geometry()
        self.move(geo.right() - self.width() - 24, geo.top() + 24)
        self.show()

    def _emit_decision(self, action: str):
        self.decision.emit(self.task.task_id, action)
        self.close()

    # Draggable from title bar only
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.title_bar.geometry().contains(event.position().toPoint()):
            self.old_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event):
        if event.buttons() & Qt.LeftButton:
            delta = event.globalPosition().toPoint() - self.old_pos
            self.move(self.pos() + delta)
            self.old_pos = event.globalPosition().toPoint()


class ActionCenterWindow(QMainWindow):
    """Central window listing all pending tasks and quarantine items."""

    task_decided = Signal(int, str)  # task_id, action

    def __init__(self) -> None:
        super().__init__()

        # Frameless window
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.resize(600, 380)

        self.old_pos = QPoint()
        self._is_description_page = False

        # Data containers and monitor
        self._cards: Dict[int, QWidget] = {}
        self.quar_items: Dict[str, QuarantineItem] = {}
        self.monitor = QuarantineMonitor()
        self.monitor.newQuarantine.connect(self.add_quar_card)

        # ---- Central structure ----
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(1, 1, 1, 1)
        main_layout.setSpacing(0)

        container = QWidget()
        container.setObjectName("container")

        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(0)

        # ---- Custom title bar ----
        title_bar = QWidget()
        title_bar.setFixedHeight(60)
        title_bar.setObjectName("titleBar")
        self.title_bar = title_bar

        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(12, 0, 12, 0)
        title_layout.setSpacing(8)

        # App icon
        shield_icon_label = QLabel()
        try:
            pix = QPixmap(SYSTEM_ICON_PATH)
            if not pix.isNull():
                shield_icon_label.setPixmap(
                    pix.scaled(48, 48, Qt.AspectRatioMode.KeepAspectRatio,
                               Qt.TransformationMode.SmoothTransformation)
                )
        except Exception:
            pass
        shield_icon_label.setFixedSize(48, 48)
        shield_icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QLabel("Aria Security - Action Center")
        title.setFont(QFont("Segoe UI", 16))
        title.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)

        # Page toggle button
        self.page_btn = QPushButton()
        self.page_btn.setFixedSize(32, 32)
        self.page_btn.setFlat(True)
        self.page_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.page_btn.setObjectName("pageButton")

        menu_icon = qta.icon("fa5s.bars", color="#e5e7eb")
        self.page_btn.setIcon(menu_icon)
        self.page_btn.setIconSize(QSize(18, 18))

        # Close button
        icon_path_close = find_menu("menu/close.png")
        close_btn = QPushButton()
        close_btn.setFixedSize(30, 30)
        close_btn.setObjectName("closeButton")
        try:
            close_btn.setIcon(QIcon(icon_path_close))
        except Exception:
            close_btn.setText("✕")
        close_btn.clicked.connect(self.close)

        title_layout.addWidget(shield_icon_label)
        title_layout.addWidget(title)
        title_layout.addStretch()
        title_layout.addWidget(self.page_btn)
        title_layout.addWidget(close_btn)

        # ---- Page 1: tasks scroll area ----
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        self._scroll.setStyleSheet(
            """
            QScrollArea {
                background-color: transparent;
                border: none;
            }
            QScrollArea QWidget {
                background-color: transparent;
            }
            QScrollBar:vertical {
                background: transparent;
                width: 8px;
                margin: 0px;
                border: none;
            }
            QScrollBar::handle:vertical {
                background: #ffffff;
                min-height: 20px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: #1b1b1b;
            }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical,
            QScrollBar::add-page:vertical,
            QScrollBar::sub-page:vertical {
                background: none;
                height: 0px;
                border: none;
            }
            QScrollBar:horizontal {
                background: transparent;
                height: 8px;
                margin: 0px;
                border: none;
            }
            QScrollBar::handle:horizontal {
                background: rgba(0, 0, 0, 0.2);
                min-width: 20px;
                border-radius: 4px;
            }
            QScrollBar::handle:horizontal:hover {
                background: rgba(0, 0, 0, 0.4);
            }
            QScrollBar::add-line:horizontal,
            QScrollBar::sub-line:horizontal,
            QScrollBar::add-page:horizontal,
            QScrollBar::sub-page:horizontal {
                background: none;
                width: 0px;
                border: none;
            }
            QToolTip {
                background-color: #000000;
                color: white;
                border: 1px solid #444;
                padding: 6px;
                font-size: 12px;
                font-family: Consolas, monospace;
                border-radius: 4px;
            }
            """
        )

        self._container = QWidget()
        self._container_layout = QVBoxLayout(self._container)
        self._container_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._container_layout.setContentsMargins(20, 20, 20, 20)
        self._container_layout.setSpacing(12)
        self._scroll.setWidget(self._container)

        # ---- Page 2: quarantine list ----
        page_2 = QWidget()
        page_2_layout = QVBoxLayout(page_2)
        page_2_layout.setContentsMargins(20, 20, 20, 20)
        page_2_layout.setSpacing(10)

        self.quar_title = QLabel("Quarantined Hazards")
        self.quar_title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        self.quar_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        page_2_layout.addWidget(self.quar_title)

        self.list_widget = QListWidget()
        self.list_widget.setAlternatingRowColors(True)
        self.list_widget.itemDoubleClicked.connect(self.on_item_double_click)
        page_2_layout.addWidget(self.list_widget)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setFixedHeight(50)
        self.refresh_btn.clicked.connect(self.refresh_list)
        page_2_layout.addWidget(self.refresh_btn)

        # ---- Stacked pages ----
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.addWidget(self._scroll)  # index 0
        self.stacked_widget.addWidget(page_2)        # index 1

        container_layout.addWidget(title_bar)
        container_layout.addWidget(self.stacked_widget)
        main_layout.addWidget(container)

        # Connections / init
        self.page_btn.clicked.connect(self.toggle_page)
        QTimer.singleShot(100, self._post_init)

        # Stylesheet
        self.setStyleSheet(
            """
            #container {
                background: #0e0e0e;
                border-radius: 10px;
            }
            #titleBar {
                background-color: #121212;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
            }
            #card {
                background-color: #2e2e2e;
                border-radius: 10px;
                border: transparent;
            }
            QListWidget {
                background-color: transparent;
            }
            QLabel {
                color: #e5e7eb;
            }
            QPushButton {
                background-color: #18181b;
                color: #e5e7eb;
                border: 1px solid #27272a;
                border-radius: 8px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #27272a;
            }
            QPushButton:pressed {
                background-color: #0f172a;
            }
            #pageButton {
                border-radius: 6px;
                border: none;
                background-color: transparent;
            }
            #pageButton:hover {
                background-color: #1f2937;
            }
            #closeButton {
                border-radius: 6px;
            }
            """
        )

    # -------------------------------------------------------------------
    # Post-init
    # -------------------------------------------------------------------
    def _post_init(self) -> None:
        self.monitor.load_metadata()
        self.refresh_list()

    def add_quar_card(self, quar_dir: str, enc_path: str, basename: str, orig_path: str):
        if quar_dir in self.quar_items:
            return
        item = QuarantineItem(quar_dir, enc_path, basename, orig_path)
        item.restored.connect(self.on_item_removed)
        item.deleted.connect(self.on_item_removed)
        self.quar_items[quar_dir] = item
        display_text = f"{basename}\n{quar_dir}\nOriginal: \n{orig_path}"
        list_item = QListWidgetItem(display_text)
        list_item.setData(Qt.UserRole, quar_dir)
        list_item.setData(Qt.UserRole + 1, enc_path)
        list_item.setData(Qt.UserRole + 2, orig_path)
        self.list_widget.addItem(list_item)

    @Slot(str)
    def on_item_removed(self, quar_dir: str):
        if quar_dir in self.quar_items:
            del self.quar_items[quar_dir]
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if item.data(Qt.UserRole) == quar_dir:
                self.list_widget.takeItem(i)
                break

    def refresh_list(self):
        self.list_widget.clear()
        self.quar_items.clear()
        self.monitor.load_metadata()

    def on_item_double_click(self, item):
        print("🖱️ Double-click detected")
        quar_dir = item.data(Qt.UserRole)
        orig_path = item.data(Qt.UserRole + 2)
        qitem = self.quar_items.get(quar_dir)
        if not qitem:
            print("❌ No QuarantineItem found")
            return

        print(f"🎯 Action for: {quar_dir}")
        msg = QMessageBox(self)
        msg.setWindowIcon(QIcon(SYSTEM_ICON_PATH))
        msg.setIcon(QMessageBox.Question)
        msg.setWindowTitle("Quarantine Action")
        msg.setText(f"File: {qitem.basename}")
        msg.setInformativeText(f"Folder: {quar_dir}\n Original: {orig_path}")

        restore_btn = msg.addButton("Restore", QMessageBox.YesRole)
        delete_btn = msg.addButton("Delete", QMessageBox.NoRole)
        msg.addButton("Cancel", QMessageBox.RejectRole)

        ret = msg.exec()
        clicked = msg.clickedButton()
        print(f"Dialog clicked: {clicked.text()} (ret={ret})")

        if clicked == restore_btn:
            print("🚀 RESTORE!")
            success = qitem.restore()
            print("✅ Restore complete" if success else "❌ Restore failed")
        elif clicked == delete_btn:
            print("🗑️ DELETE!")
            qitem.delete()
        else:
            print("❌ Cancel")

    def add_task_card(self, task: Task):
        card = QFrame()
        card.setObjectName("card")
        card.setFrameShape(QFrame.Box)
        card.setStyleSheet("""
            QFrame#card {
                border-radius: 8px;
                border: 1px solid #444;
                padding: 8px;
                background-color: #111;
            }
            QPushButton {
                background-color: #3e3e3e;
                color: #e5e7eb;
                border: transparent;
                border-radius: 8px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #ffffff;
            }
            QPushButton:pressed {
                background-color: #d1d5db;
            }
        """)
        v = QVBoxLayout(card)

        title = QLabel(task.app_name)
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        path_lbl = QLabel(task.file_path)
        path_lbl.setWordWrap(True)
        path_lbl.setStyleSheet("color: #aaa;")

        btn_row = QHBoxLayout()
        btn_destroy = QPushButton("Destroy")
        btn_destroy.setFixedSize(100, 50)
        btn_quarantine = QPushButton("Quarantine")
        btn_quarantine.setFixedSize(100, 50)

        btn_destroy.clicked.connect(
            lambda _, tid=task.task_id: self._decide(tid, "destroy")
        )
        btn_quarantine.clicked.connect(
            lambda _, tid=task.task_id: self._decide(tid, "quarantine")
        )

        btn_row.addWidget(btn_destroy)
        btn_row.addWidget(btn_quarantine)

        v.addWidget(title)
        v.addWidget(path_lbl)
        v.addLayout(btn_row)

        self._container_layout.addWidget(card)
        self._cards[task.task_id] = card

    def toggle_page(self):
        """Cycle between Action Center and Quarantined Hazards."""
        if not hasattr(self, '_current_page'):
            self._current_page = 0

        self._current_page = (self._current_page + 1) % 2  # 0↔1

        if self._current_page == 0:
            self.stacked_widget.setCurrentIndex(0)
            menu_icon = qta.icon("fa5s.home", color="#e5e7eb")
            self.page_btn.setIcon(menu_icon)
            self.page_btn.setToolTip("Go to Quarantined Hazards")
        else:
            self.stacked_widget.setCurrentIndex(1)
            console_icon = qta.icon("fa5s.bars", color="#fb923c")
            self.page_btn.setIcon(console_icon)
            self.page_btn.setToolTip("Go to Action Center")

    def _decide(self, task_id: int, action: str):
        card = self._cards.pop(task_id, None)
        if card is not None:
            card.setParent(None)
        self.task_decided.emit(task_id, action)

    def bring_to_front(self):
        self.show()
        self.raise_()
        self.activateWindow()

    # Enable dragging from title bar
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.old_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event):
        if event.buttons() & Qt.LeftButton:
            delta = event.globalPosition().toPoint() - self.old_pos
            self.move(self.pos() + delta)
            self.old_pos = event.globalPosition().toPoint()


# =========================
# Executioner (Task Manager)
# =========================

class Executioner(QObject):
    """
    Threaded task manager with workers and PySide6 UI.

    You must create QApplication in your main script, then:

        app = QApplication(sys.argv)
        executor = Executioner()
        executor.handle_threat(path)
        app.exec()
    """

    # GUI-side signals
    request_show_task = Signal(Task)     # create notif + card
    decision_made = Signal(int, str)     # task_id, action
    auto_quarantine = Signal(int)        # task_id (timer expired → quarantine)

    # Show/hide control signals (can be triggered from TCP thread)
    sig_show_action_center = Signal()
    sig_hide_action_center = Signal()
    sig_toggle_action_center = Signal()

    def __init__(self):
        super().__init__()

        if QApplication.instance() is None:
            raise RuntimeError("QApplication must be created before Executioner")

        self.task_queue = queue.Queue()
        self.tasks = {}          # task_id -> Task
        self.next_task_id = 0
        self.max_workers = 3
        self.workers = [self.Worker(i, self) for i in range(self.max_workers)]
        self.lock = threading.Lock()

        self.action_center = ActionCenterWindow()
        self.action_center.task_decided.connect(self._on_action_center_decision)

        # Decisions shared with workers
        self._decisions = {}     # task_id -> action
        self._decisions_lock = threading.Lock()

        # Auto-quarantine timers (GUI thread, parent=self so they live)
        self.task_timers: Dict[int, QTimer] = {}

        # Connect GUI signals
        self.request_show_task.connect(self._gui_show_task)
        self.decision_made.connect(self._on_decision_from_gui)
        self.auto_quarantine.connect(self._on_auto_quarantine)

        # Connect show/hide/toggle signals to slots that manipulate window
        self.sig_show_action_center.connect(self.show_action_center)
        self.sig_hide_action_center.connect(self.hide_action_center)
        self.sig_toggle_action_center.connect(self.toggle_action_center)

        # Start hidden
        self.action_center.hide()

        # Start TCP command server in background thread
        self._command_thread = threading.Thread(
            target=self._command_server_loop, daemon=True
        )
        self._command_thread.start()

    # ---------- Public API ----------

    def handle_threat(self, file_path: str):
        if not os.path.exists(file_path):
            print(f"⚠️ File path does not exist: {file_path}")
            return None

        with self.lock:
            task_id = self.next_task_id
            self.next_task_id += 1

        task = Task(file_path, task_id)
        self.tasks[task_id] = task
        self.task_queue.put(task_id)

        # Ask GUI to show notification + card
        self.request_show_task.emit(task)

        self._assign_workers()
        return task_id

    # ---------- Worker Management ----------

    class Worker:
        def __init__(self, worker_id: int, manager: "Executioner"):
            self.id = worker_id
            self.manager = manager
            self.busy = False

        def start(self, task_id: int):
            t = threading.Thread(target=self.run, args=(task_id,), daemon=True)
            t.start()

        def run(self, task_id: int):
            self.busy = True
            try:
                self.manager._process_task(task_id)
            finally:
                self.busy = False
                self.manager._assign_workers()

    def _assign_workers(self):
        with self.lock:
            for w in self.workers:
                if self.task_queue.empty():
                    break
                if not w.busy:
                    try:
                        task_id = self.task_queue.get_nowait()
                    except queue.Empty:
                        break
                    w.start(task_id)

    # ---------- GUI handler for new tasks ----------

    def _gui_show_task(self, task: Task):
        """Create notification + Action Center card (GUI thread) and start timer."""
        notif = NotificationWindow(task)
        notif.decision.connect(self._on_notification_decision)
        notif.show_at_top_right()

        self.action_center.add_task_card(task)

        # START auto-quarantine timer now that the notification is visible
        self._start_auto_timer(task.task_id)

    # ---------- Decision flows ----------

    def _on_notification_decision(self, task_id: int, action: str):
        """Called in GUI thread when user clicks notification buttons."""
        self.decision_made.emit(task_id, action)

    def _on_action_center_decision(self, task_id: int, action: str):
        """Called in GUI thread when user clicks buttons in Action Center cards."""
        self.decision_made.emit(task_id, action)

    def _on_decision_from_gui(self, task_id: int, action: str):
        """Unified handler for decisions, stored in shared dict (thread-safe)."""
        if action == "action_center":
            self.show_action_center()
            return

        # Cancel auto-timer on explicit destroy/quarantine
        self._cancel_auto_timer(task_id)

        with self._decisions_lock:
            self._decisions[task_id] = action

    @Slot(int)
    def _on_auto_quarantine(self, task_id: int):
        """Timer expired: auto-quarantine if user has not decided yet."""
        with self._decisions_lock:
            if task_id not in self._decisions:
                self._decisions[task_id] = "quarantine"
                print(f"⏰ Auto-quarantined task {task_id} after inactivity timeout")

    # ---------- Worker-side processing ----------

    def _process_task(self, task_id: int):
        task = self.tasks.get(task_id)
        if not task:
            return

        # Wait for GUI decision (destroy/quarantine/None)
        action = self._wait_for_decision(task_id)
        task.action = action

        if task.action == "destroy":
            self._destroy_file(task.file_path)
        elif task.action == "quarantine":
            self._quarantine_file(task.file_path)
        else:
            print(f"ℹ️ No action taken for {task.file_path}")

    def _wait_for_decision(self, task_id: int, timeout: float = 600.0):
        """Poll for decision (auto-quarantine or manual) with upper bound."""
        start = time.time()
        while time.time() - start < timeout:
            with self._decisions_lock:
                if task_id in self._decisions:
                    return self._decisions.pop(task_id)
            time.sleep(0.1)
        return None

    # ---------- Auto-quarantine timers (GUI thread) ----------

    def _start_auto_timer(self, task_id: int):
        """Start fixed 2-minute timer for this task (runs in GUI thread)."""
        if task_id in self.task_timers:
            self.task_timers[task_id].stop()

        # Parent=self to keep timer alive with Executioner
        timer = QTimer(self)
        timer.setSingleShot(True)

        delay = 120000  # 2 minutes in milliseconds

        timer.timeout.connect(lambda tid=task_id: self.auto_quarantine.emit(tid))
        timer.start(delay)
        self.task_timers[task_id] = timer
        print(f"⏳ Auto-quarantine timer started for task {task_id}: {delay/1000:.0f}s")

    def _cancel_auto_timer(self, task_id: int):
        """Cancel timer on manual decision."""
        timer = self.task_timers.pop(task_id, None)
        if timer is not None:
            timer.stop()
            print(f"❌ Auto-timer cancelled for task {task_id}")

    # ---------- Actions ----------

    def _destroy_file(self, file_path: str):
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"💀 Destroyed: {file_path}")
            except Exception as e:
                print(f"❌ Failed to destroy {file_path}: {e}")
        else:
            print(f"⚠️ File not found (destroy): {file_path}")

    def _quarantine_file(self, file_path: str):
        if not os.path.exists(file_path):
            print(f"⚠️ File not found (quarantine): {file_path}")
            return

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        quarantine_dir = QUARANTINE_ROOT / f"Quarantine-Hazard_{timestamp}"
        quarantine_dir.mkdir(parents=True, exist_ok=True)

        filename = os.path.basename(file_path)
        dest = quarantine_dir / filename

        try:
            shutil.move(file_path, dest)
        except Exception as e:
            print(f"❌ Failed to move to quarantine: {e}")
            return

        key = Fernet.generate_key()
        fernet = Fernet(key)

        # Save metadata with string path for JSON
        save_quarantine_metadata(str(quarantine_dir), filename, file_path)
        print(f"🛡️ Quarantined: {file_path} → {quarantine_dir}")

        try:
            with open(dest, "rb") as src:
                data = src.read()
            encrypted = fernet.encrypt(data)
            with open(dest, "wb") as dst:
                dst.write(encrypted)
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            return

        key_path = QUARANTINE_ROOT / f"{quarantine_dir.name}.key"
        try:
            with open(key_path, "wb") as kf:
                kf.write(key)
        except Exception as e:
            print(f"❌ Failed to write key: {e}")
            return

        print(f"🛡️ Quarantined & encrypted: {file_path}")
        print(f"   Folder: {quarantine_dir}")
        print(f"   Key:    {key_path}")

    # ---------- Show/Hide/Toggle slots ----------

    @Slot()
    def show_action_center(self):
        self.action_center.show()
        self.action_center.raise_()
        self.action_center.activateWindow()

    @Slot()
    def hide_action_center(self):
        self.action_center.hide()

    @Slot()
    def toggle_action_center(self):
        if self.action_center.isVisible():
            self.hide_action_center()
        else:
            self.show_action_center()

    # ---------- TCP command server (runs in background thread) ----------

    def _command_server_loop(self):
        """Simple TCP server on localhost to receive show/hide/toggle commands."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", COMMAND_PORT))
            sock.listen(5)
        except OSError as e:
            print(f"[ActionCenterControl] Failed to bind port {COMMAND_PORT}: {e}")
            return

        while True:
            try:
                conn, addr = sock.accept()
            except OSError:
                break
            with conn:
                try:
                    data = conn.recv(1024)
                    if not data:
                        continue
                    cmd = data.decode("utf-8", errors="ignore").strip().upper()
                    if cmd == "SHOW_ACTION_CENTER":
                        self.sig_show_action_center.emit()
                    elif cmd == "HIDE_ACTION_CENTER":
                        self.sig_hide_action_center.emit()
                    elif cmd == "TOGGLE_ACTION_CENTER":
                        self.sig_toggle_action_center.emit()
                except Exception as e:
                    print(f"[ActionCenterControl] Error handling command: {e}")
