#!/usr/bin/env python3
import sys
import threading
import time
from datetime import datetime
import requests
import psutil
import html

from PySide6.QtCore import (
    Qt, QTimer, QPropertyAnimation, QEasingCurve, QRect, Signal, QObject, QPoint
)
from PySide6.QtGui import QFont, QPalette, QColor, QTextCursor, QPainter, QBrush, QPixmap, QFontDatabase
from PySide6.QtWidgets import (
    QApplication, QWidget, QMainWindow, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QListWidget,
    QListWidgetItem, QFrame, QSizePolicy, QGraphicsDropShadowEffect, QScrollArea,
    QStackedWidget
)

import markdown

from Main_Unit.Config.Sys_Config import SYSTEM_ICON_PATH
from Main_Unit.find_items import find_items

system_ico = find_items(SYSTEM_ICON_PATH)

# =========================
# API CONFIG
# =========================
API_BASE = "http://127.0.0.1:8765"
API_TOKEN = "Sentinel_!-2026@360!"


class ApiSignals(QObject):
    stream_chunk = Signal(str)
    stream_finished = Signal()
    stream_error = Signal(str)
    notifications_updated = Signal(list)


# NOTE: signals is created per-instance inside CopilotPage.__init__ to prevent
# cross-instance bleed. This module-level stub exists only for backward-compat
# with any code that imported it before; it is NOT used by CopilotPage itself.
signals = ApiSignals()   # legacy stub — do not use directly


# =========================
# Answer buffer for Markdown
# =========================
class AnswerBuffer:
    """
    Keeps the current answer as Markdown and renders the full
    answer to HTML on demand. Avoids broken tags from partial HTML.
    """
    def __init__(self):
        self.current_answer_md = ""

    def reset(self):
        self.current_answer_md = ""

    def append_chunk(self, chunk: str):
        self.current_answer_md += chunk

    def render_html(self) -> str:
        try:
            # nl2br keeps newlines as <br> for nicer chat layout
            return markdown.markdown(self.current_answer_md, extensions=["nl2br"])
        except Exception:
            return self.current_answer_md.replace("\n", "<br>")


# =========================
# API workers
# =========================
def ask_stream_worker(question: str, sig: "ApiSignals"):
    """Run in a daemon thread. Uses the per-instance sig to avoid cross-bleed."""
    url = f"{API_BASE}/ask"
    headers = {"X-Auth-Token": API_TOKEN}
    payload = {"question": question}
    try:
        with requests.post(url, headers=headers, json=payload, stream=True, timeout=60) as r:
            if r.status_code != 200:
                sig.stream_error.emit(f"Server error {r.status_code}")
                return
            for chunk in r.iter_content(chunk_size=64):
                if chunk:
                    sig.stream_chunk.emit(chunk.decode("utf-8", errors="ignore"))
    except Exception as e:
        sig.stream_error.emit(str(e))
    finally:
        sig.stream_finished.emit()


def notifications_worker(sig: "ApiSignals", stop_flag: list):
    """Run in a daemon thread. stop_flag[0]=True exits the loop on next tick."""
    url = f"{API_BASE}/notifications"
    headers = {"X-Auth-Token": API_TOKEN}
    while not stop_flag[0]:
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    sig.notifications_updated.emit(data)
        except Exception:
            pass
        for _ in range(10):          # sleep 10 s in 1 s ticks so stop_flag is checked promptly
            if stop_flag[0]:
                break
            time.sleep(1)


# =========================
# Main Window
# =========================
class CopilotPage(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.resize(800, 600)
        self._drag_pos = QPoint()

        self.nav_buttons = {}  # for active state

        self.answer_buffer = AnswerBuffer()
        self.current_answer_block_pos = None

        self._setup_style()
        self._setup_ui()
        self._connect_signals()

        # periodic local node check (no console)
        self.node_timer = QTimer(self)
        self.node_timer.timeout.connect(self.update_local_node_status)
        self.node_timer.start(5000)  # every 5s
        self.update_local_node_status()

        # Per-instance stop flag — set to True in closeEvent / when embedded page is destroyed
        self._notif_stop = [False]
        threading.Thread(
            target=notifications_worker,
            args=(self._signals, self._notif_stop),
            daemon=True,
        ).start()

    def _setup_style(self):
        self.setStyleSheet("""
            /* Base Container — dark theme matching Sentinel app */
            QWidget#Root {
                background-color: #080c10;
                border-radius: 14px;
                border: 1px solid #21262d;
            }

            /* Sidebar */
            QFrame#Sidebar {
                background-color: #0d1117;
                border-top-left-radius: 14px;
                border-bottom-left-radius: 14px;
                border-right: 1px solid #21262d;
            }

            QPushButton#NavButton {
                color: #8b949e;
                background: transparent;
                border: none;
                border-radius: 10px;
                text-align: left;
                padding: 10px 16px;
                font-size: 13px;
                font-weight: 500;
                margin: 2px 8px;
            }
            QPushButton#NavButton:hover {
                background-color: #161b22;
                color: #e6edf3;
            }
            QPushButton#NavButton[active="true"] {
                background-color: #2f81f722;
                color: #2f81f7;
            }

            /* Main content area */
            QFrame#MainArea {
                background-color: transparent;
            }

            /* Chat display */
            QTextEdit#ChatDisplay {
                background-color: transparent;
                border: none;
                font-size: 13px;
                color: #e6edf3;
                padding: 10px;
            }
            QTextEdit#ChatDisplay code {
                font-family: Consolas, monospace;
                background-color: #161b22;
                padding: 2px 4px;
                border-radius: 4px;
                color: #7ee787;
            }
            QTextEdit#ChatDisplay pre {
                background-color: #0d1117;
                color: #7ee787;
                padding: 8px;
                border-radius: 6px;
                font-family: Consolas, monospace;
            }

            /* Input bar */
            QFrame#InputCard {
                background-color: #161b22;
                border-radius: 12px;
                border: 1px solid #21262d;
            }
            QLineEdit#QueryInput {
                border: none;
                background: transparent;
                padding: 12px;
                font-size: 13px;
                color: #e6edf3;
            }
            QLineEdit#QueryInput::placeholder {
                color: #484f58;
            }

            QPushButton#ActionBtn {
                background-color: #2f81f7;
                color: white;
                border: none;
                border-radius: 8px;
                font-weight: 700;
                padding: 8px 18px;
                margin-right: 6px;
                font-size: 13px;
            }
            QPushButton#ActionBtn:hover { background-color: #388bfd; }
            QPushButton#ActionBtn:disabled { background-color: #21262d; color: #484f58; }

            /* Rail / notification card */
            QFrame#RailCard {
                background-color: #161b22;
                border-radius: 12px;
                border: 1px solid #21262d;
            }
            QLabel#RailTitle {
                font-size: 11px;
                font-weight: 700;
                color: #8b949e;
            }
            QLabel {
                color: #e6edf3;
                background: transparent;
            }

            /* List widget */
            QListWidget {
                background: transparent;
                border: none;
                font-size: 12px;
                outline: none;
                color: #e6edf3;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #21262d;
                color: #8b949e;
            }
            QListWidget::item:hover { background: #161b22; }

            /* Scrollbar */
            QScrollBar:vertical {
                background: transparent; width: 6px; border: none;
            }
            QScrollBar::handle:vertical {
                background: #21262d; border-radius: 3px; min-height: 20px;
            }
        """)

    def _setup_ui(self):
        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)

        main_layout = QHBoxLayout(root)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 1. SIDEBAR
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(260)
        side_lay = QVBoxLayout(sidebar)
        side_lay.setContentsMargins(10, 30, 10, 30)

        # Custom app icon from local file
        shield_icon_label = QLabel()
        shield_icon_label.setPixmap(QPixmap(system_ico).scaled(48, 48, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        shield_icon_label.setFixedSize(48, 48)
        shield_icon_label.setAlignment(Qt.AlignCenter)
        shield_icon_label.setScaledContents(False)

        side_lay.addWidget(shield_icon_label, alignment=Qt.AlignCenter)

        # Navigation buttons
        btn_copilot = QPushButton("AI Copilot")
        btn_copilot.setObjectName("NavButton")
        btn_copilot.setProperty("active", True)
        btn_copilot.clicked.connect(lambda: self.set_page(0))
        side_lay.addWidget(btn_copilot)
        self.nav_buttons["copilot"] = btn_copilot

        btn_monitor = QPushButton("Monitoring")
        btn_monitor.setObjectName("NavButton")
        btn_monitor.setProperty("active", False)
        btn_monitor.clicked.connect(lambda: self.set_page(1))
        side_lay.addWidget(btn_monitor)
        self.nav_buttons["monitor"] = btn_monitor

        side_lay.addStretch()

        # User Status Card (Local Node) – Font Awesome icon
        u_card = QFrame()
        u_card.setStyleSheet("background: #161b22; border-radius: 10px; border: 1px solid #21262d; margin: 8px;")
        u_lay = QHBoxLayout(u_card)

        # Default to inactive state icon (circle)
        self.node_status_icon = QLabel("\uf111")  # Font Awesome 'circle' (Unicode f111)
        self.node_status_icon.setStyleSheet(
            "color: #EF4444; font-size: 16px; font-family: 'Font Awesome 6 Free';"
        )
        self.node_status_text = QLabel("Local Node: Inactive")
        self.node_status_text.setStyleSheet("color: #E5E7EB;")

        u_lay.addWidget(self.node_status_icon)
        u_lay.addWidget(self.node_status_text)
        side_lay.addWidget(u_card)

        # 2. CENTRAL CHAT AREA (page 0)
        chat_wrap = QFrame()
        chat_wrap.setObjectName("MainArea")
        chat_lay = QVBoxLayout(chat_wrap)
        chat_lay.setContentsMargins(40, 20, 40, 40)

        # Header Row
        header = QHBoxLayout()
        title_block = QVBoxLayout()
        t = QLabel("Sentinel Copilot")
        t.setStyleSheet("font-size: 22px; font-weight: 800; color: #e6edf3;")
        st = QLabel("Real-time local LLM analysis for AriaSecurity")
        st.setStyleSheet("color: #8b949e; font-size: 13px;")
        title_block.addWidget(t)
        title_block.addWidget(st)
        header.addLayout(title_block)
        header.addStretch()

        # Simple Window Controls
        for char in ["✕"]:
            btn = QPushButton(char)
            btn.setFixedSize(32, 32)
            btn.setStyleSheet(
                "background: #21262d; border-radius: 6px; "
                "color: #8b949e; font-weight: bold; border: none;"
                "QPushButton:hover { background: #f8514922; color: #f85149; }"
            )
            if char == "✕":
                btn.clicked.connect(self.close)
            header.addWidget(btn)

        chat_lay.addLayout(header)
        chat_lay.addSpacing(30)

        # Main Scrollable Chat
        self.chat_display = QTextEdit()
        self.chat_display.setObjectName("ChatDisplay")
        self.chat_display.setReadOnly(True)
        self.chat_display.setAcceptRichText(True)  # IMPORTANT for HTML
        chat_lay.addWidget(self.chat_display)

        # Floating Input Bar
        input_container = QFrame()
        input_container.setObjectName("InputCard")
        input_container.setFixedHeight(70)

        # Shadow effect
        shadow = QGraphicsDropShadowEffect(
            blurRadius=25, xOffset=0, yOffset=10, color=QColor(0, 0, 0, 25)
        )
        input_container.setGraphicsEffect(shadow)

        input_lay = QHBoxLayout(input_container)
        self.query_input = QLineEdit()
        self.query_input.setObjectName("QueryInput")
        self.query_input.setPlaceholderText("Paste logs or ask about system anomalies...")

        self.send_btn = QPushButton("Analyze")
        self.send_btn.setObjectName("ActionBtn")
        self.send_btn.setFixedHeight(45)

        input_lay.addWidget(self.query_input)
        input_lay.addWidget(self.send_btn)
        chat_lay.addWidget(input_container)

        # 3. MONITORING PAGE (Live Incidents + Environment Context together)
        monitoring_page = QFrame()
        monitoring_layout = QVBoxLayout(monitoring_page)
        monitoring_layout.setContentsMargins(40, 20, 40, 40)

        # Notif Card
        notif_card = QFrame()
        notif_card.setObjectName("RailCard")
        notif_inner = QVBoxLayout(notif_card)

        nt = QLabel("Live Incidents")
        nt.setObjectName("RailTitle")
        notif_inner.addWidget(nt)

        self.notif_list = QListWidget()
        notif_inner.addWidget(self.notif_list)
        monitoring_layout.addWidget(notif_card, stretch=2)

        # Stacked pages
        self.pages = QStackedWidget()
        self.pages.addWidget(chat_wrap)        # index 0: Copilot
        self.pages.addWidget(monitoring_page)  # index 1: Monitoring

        # Add to main
        main_layout.addWidget(sidebar)
        main_layout.addWidget(self.pages, stretch=1)

    # ---------- LOGIC & SIGNALS ----------
    def _connect_signals(self):
        self.send_btn.clicked.connect(self.on_send)
        # Per-instance signals — avoids cross-instance bleed when embedded
        self._signals = ApiSignals()
        self.query_input.returnPressed.connect(self.on_send)
        self._signals.stream_chunk.connect(self.on_chunk)
        self._signals.stream_finished.connect(self.on_finished)
        self._signals.stream_error.connect(self._on_stream_error)   # was never wired
        self._signals.notifications_updated.connect(self.update_notifs)

    def set_page(self, index: int):
        self.pages.setCurrentIndex(index)
        # update active state
        for key, btn in self.nav_buttons.items():
            active = (index == 0 and key == "copilot") or (index == 1 and key == "monitor")
            btn.setProperty("active", active)
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def on_send(self):
        text = self.query_input.text().strip()
        if not text:
            return
        self.query_input.clear()

        # Reset current answer state
        self.answer_buffer.reset()
        self.current_answer_block_pos = None

        # Show query header as HTML, safely escaped
        self.chat_display.append(
            "<div style='color:#2f81f7; font-weight:bold;'>Query:</div> "
            f"<span style='color:#e6edf3;'>{html.escape(text)}</span><br>"
        )
        self.chat_display.append(
            "<div style='color:#3fb950; font-weight:bold;'>Sentinel AI:</div>"
        )

        # Insert an empty block where the answer will be rendered/re-rendered
        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.current_answer_block_pos = cursor.position()
        cursor.insertHtml("<div></div>")
        self.chat_display.setTextCursor(cursor)
        self.chat_display.ensureCursorVisible()

        self.send_btn.setEnabled(False)
        threading.Thread(
            target=ask_stream_worker, args=(text, self._signals), daemon=True
        ).start()

    def on_chunk(self, chunk: str):
        if self.current_answer_block_pos is None:
            # Fallback: append plain text if block not set
            self.chat_display.append(html.escape(chunk))
            return

        # Update the Markdown buffer
        self.answer_buffer.append_chunk(chunk)
        html_answer = self.answer_buffer.render_html()

        cursor = self.chat_display.textCursor()
        # Go to the start of the answer block
        cursor.setPosition(self.current_answer_block_pos)

        # Select from that position to the end and replace with fresh HTML
        cursor.movePosition(QTextCursor.End, QTextCursor.KeepAnchor)
        cursor.removeSelectedText()

        cursor.insertHtml(f"<div style='color:#e6edf3;'>{html_answer}</div>")

        self.chat_display.setTextCursor(cursor)
        self.chat_display.ensureCursorVisible()

    def on_finished(self):
        self.send_btn.setEnabled(True)
        self.chat_display.append(
            "<br><hr style='border: 0.5px solid #21262d;'><br>"
        )
        self.current_answer_block_pos = None

    def _on_stream_error(self, msg: str):
        """Show stream errors inline in the chat — button is re-enabled by on_finished."""
        self.chat_display.append(
            f"<span style='color:#f85149;'>⚠ {html.escape(msg)}</span><br>"
        )

    def closeEvent(self, event):
        """Stop the notifications polling thread when the window/page closes."""
        try:
            self._notif_stop[0] = True
        except Exception:
            pass
        super().closeEvent(event)

    def update_notifs(self, data):
        self.notif_list.clear()
        # defensive: ensure it's a list
        if not isinstance(data, list):
            return
        for item in data[-10:]:
            title = item.get("title", "Unknown")
            t = item.get("time", "")
            self.notif_list.addItem(f"⚠️ {title}\n{t}")

    # Local node status using psutil – Font Awesome icons
    def update_local_node_status(self):
        running = False
        target = "SentinelAiSenseService.exe"  # adjust if needed

        try:
            for proc in psutil.process_iter(["name"]):
                if proc.info.get("name") == target:
                    running = True
                    break
        except Exception:
            running = False

        if running:
            # Font Awesome 'check' (Unicode f00c)
            self.node_status_icon.setText("\uf00c")
            self.node_status_icon.setStyleSheet(
                "color: #10B981; font-size: 16px; font-family: 'Font Awesome 6 Free';"
            )
            self.node_status_text.setText("Local Node: Active")
        else:
            # Font Awesome 'circle' (Unicode f111)
            self.node_status_icon.setText("\uf111")
            self.node_status_icon.setStyleSheet(
                "color: #EF4444; font-size: 16px; font-family: 'Font Awesome 6 Free';"
            )
            self.node_status_text.setText("Local Node: Inactive")

    # Drag window
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() & Qt.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))

    # Load Font Awesome TTF so the icons render properly
    # Adjust the path below to where your fa-solid-900.ttf actually lives
    fa_path = "assets/fonts/fa-solid-900.ttf"
    font_id = QFontDatabase.addApplicationFont(fa_path)
    if font_id == -1:
        print(f"Failed to load Font Awesome font from {fa_path}")
    else:
        families = QFontDatabase.applicationFontFamilies(font_id)
        print("Loaded Font Awesome families:", families)

    win = CopilotPage()
    win.show()
    sys.exit(app.exec())
