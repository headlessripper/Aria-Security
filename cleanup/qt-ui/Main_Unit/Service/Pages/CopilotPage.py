"""
CopilotPage.py — Argus AI Copilot
Conversational security assistant powered by AVBrain + Phi-3.5-mini.

Architecture:
  User types → _ChatWorker (QThread) → AVBrain.chat() [blocking LLM call]
  → response emitted via Qt signal → main thread adds bubble to scroll area

Argus is agentic: it can call tools (get_threats, block_ip, read_log, …)
by emitting [TOOL:name:arg] tags in its response. AVBrain parses and
executes those transparently before returning the final reply.
"""
from __future__ import annotations

import textwrap
import time
from typing import Optional

from PySide6.QtCore import (
    Qt, QThread, Signal, Slot, QObject, QTimer, QSize,
)
from PySide6.QtGui import QFont, QTextCursor, QColor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QLineEdit, QSizePolicy, QTextEdit,
    QGraphicsOpacityEffect,
)

# ── Theme ────────────────────────────────────────────────────────────────────
BG      = "#0d1117"
SURFACE = "#161b22"
CARD    = "#1c2128"
BORDER  = "#30363d"
ACCENT  = "#2f81f7"
GREEN   = "#3fb950"
RED     = "#f85149"
ORANGE  = "#d29922"
TEXT    = "#e6edf3"
DIM     = "#8b949e"
MUTED   = "#484f58"

_FONT   = "Segoe UI"


# ── Worker ───────────────────────────────────────────────────────────────────

class _ChatWorker(QObject):
    """Runs AVBrain.chat() on a background thread; emits result via signal."""
    response_ready = Signal(str)
    error          = Signal(str)

    def __init__(self, user_message: str):
        super().__init__()
        self._msg = user_message

    @Slot()
    def run(self):
        try:
            from Main_Unit.Engine.Service.AVBrain import get_avbrain
            result = get_avbrain().chat(self._msg)
            self.response_ready.emit(result)
        except Exception as e:
            self.error.emit(f"Argus error: {e}")


# ── Chat bubble ───────────────────────────────────────────────────────────────

class _Bubble(QFrame):
    """Single chat message bubble."""

    def __init__(
        self,
        text: str,
        role: str,          # "user" | "aria" | "system"
        parent=None,
    ):
        super().__init__(parent)
        self._role = role

        is_user   = role == "user"
        is_system = role == "system"

        bg      = CARD    if is_user   else SURFACE
        border  = BORDER  if not is_system else MUTED
        accent  = ACCENT  if not is_user else MUTED
        radius  = "12px 12px 2px 12px" if is_user else "12px 12px 12px 2px"

        self.setStyleSheet(
            f"QFrame {{"
            f"  background:{bg};"
            f"  border:1px solid {border};"
            f"  border-left: {'3px solid ' + accent if not is_user else '1px solid ' + border};"
            f"  border-radius:{radius};"
            f"}}"
        )
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        # Role label
        if not is_system:
            role_lbl = QLabel("You" if is_user else "Argus")
            role_lbl.setFont(QFont(_FONT, 9, QFont.Bold))
            role_lbl.setStyleSheet(
                f"color:{'#' + ('586069' if is_user else '79c0ff')};background:transparent;border:none;"
            )
            layout.addWidget(role_lbl)

        # Message body — use QLabel for normal text; preserve newlines
        body = QLabel(text)
        body.setFont(QFont(_FONT, 10))
        body.setWordWrap(True)
        body.setTextInteractionFlags(Qt.TextSelectableByMouse)
        body.setStyleSheet(
            f"color:{'#' + ('8b949e' if is_system else 'e6edf3')};"
            f"background:transparent;border:none;"
        )
        body.setTextFormat(Qt.PlainText)
        layout.addWidget(body)


class _ThinkingBubble(QFrame):
    """Animated "Argus is thinking…" indicator."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(
            f"QFrame{{background:{SURFACE};border:1px solid {BORDER};"
            f"border-left:3px solid {MUTED};border-radius:12px 12px 12px 2px;}}"
        )
        lyt = QHBoxLayout(self)
        lyt.setContentsMargins(12, 8, 12, 8)
        self._lbl = QLabel("Argus is thinking")
        self._lbl.setFont(QFont(_FONT, 10))
        self._lbl.setStyleSheet(f"color:{DIM};background:transparent;border:none;")
        lyt.addWidget(self._lbl)
        lyt.addStretch()

        self._dots = 0
        self._timer = QTimer(self)
        self._timer.setInterval(500)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    def _tick(self):
        self._dots = (self._dots + 1) % 4
        self._lbl.setText("Argus is thinking" + "." * self._dots)

    def stop(self):
        self._timer.stop()


# ── Quick-action button strip ─────────────────────────────────────────────────

_QUICK_ACTIONS = [
    ("System Status",    "What is the current system status?"),
    ("Active Threats",   "Show me all active threats right now."),
    ("Module Status",    "Are all protection modules running?"),
    ("Recent Events",    "What happened in the last 10 events?"),
    ("Protection Level", "What is my current protection level and why?"),
    ("Reload Argus",      "__reload_aria__"),
    ("Clear Chat",       "__clear__"),
]


# ── Main page ─────────────────────────────────────────────────────────────────

class CopilotPage(QWidget):
    """
    Argus AI Copilot — full chat interface wired to AVBrain.
    Drop into QStackedWidget: copilot_page = CopilotPage()
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker_thread: Optional[QThread] = None
        self._thinking_bubble: Optional[_ThinkingBubble] = None
        self._build_ui()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        self.setStyleSheet(f"QWidget{{background:{BG};color:{TEXT};}}")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header ────────────────────────────────────────────────────────────
        header = QFrame()
        header.setFixedHeight(52)
        header.setStyleSheet(
            f"QFrame{{background:{SURFACE};border-bottom:1px solid {BORDER};}}"
        )
        h_lyt = QHBoxLayout(header)
        h_lyt.setContentsMargins(16, 0, 16, 0)

        dot = QLabel("●")
        dot.setFont(QFont(_FONT, 10))
        dot.setStyleSheet(f"color:{GREEN};background:transparent;")

        title = QLabel("Argus — Security Copilot")
        title.setFont(QFont(_FONT, 13, QFont.Bold))
        title.setStyleSheet(f"color:{TEXT};background:transparent;")

        self._status_lbl = QLabel("Ready")
        self._status_lbl.setFont(QFont(_FONT, 9))
        self._status_lbl.setStyleSheet(f"color:{DIM};background:transparent;")

        h_lyt.addWidget(dot)
        h_lyt.addSpacing(6)
        h_lyt.addWidget(title)
        h_lyt.addStretch()
        h_lyt.addWidget(self._status_lbl)
        root.addWidget(header)

        # ── Quick-action strip ────────────────────────────────────────────────
        qa_frame = QFrame()
        qa_frame.setStyleSheet(
            f"QFrame{{background:{SURFACE};border-bottom:1px solid {BORDER};}}"
        )
        qa_lyt = QHBoxLayout(qa_frame)
        qa_lyt.setContentsMargins(10, 6, 10, 6)
        qa_lyt.setSpacing(6)

        for label, payload in _QUICK_ACTIONS:
            btn = QPushButton(label)
            btn.setFont(QFont(_FONT, 9))
            btn.setFixedHeight(26)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet(
                f"QPushButton{{background:{CARD};color:{DIM};"
                f"border:1px solid {BORDER};border-radius:13px;padding:0 10px;}}"
                f"QPushButton:hover{{background:{BORDER};color:{TEXT};}}"
            )
            btn.clicked.connect(lambda _=False, p=payload: self._on_quick(p))
            qa_lyt.addWidget(btn)

        qa_lyt.addStretch()
        root.addWidget(qa_frame)

        # ── Chat scroll area ──────────────────────────────────────────────────
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._scroll.setStyleSheet(
            f"QScrollArea{{background:{BG};border:none;}}"
            f"QScrollBar:vertical{{background:{BG};width:6px;border:none;}}"
            f"QScrollBar::handle:vertical{{background:{BORDER};border-radius:3px;}}"
            f"QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;}}"
        )

        self._chat_container = QWidget()
        self._chat_container.setStyleSheet(f"background:{BG};")
        self._chat_layout = QVBoxLayout(self._chat_container)
        self._chat_layout.setContentsMargins(16, 16, 16, 16)
        self._chat_layout.setSpacing(10)
        self._chat_layout.addStretch()

        self._scroll.setWidget(self._chat_container)
        root.addWidget(self._scroll, 1)

        # ── Input row ─────────────────────────────────────────────────────────
        input_frame = QFrame()
        input_frame.setStyleSheet(
            f"QFrame{{background:{SURFACE};border-top:1px solid {BORDER};}}"
        )
        in_lyt = QHBoxLayout(input_frame)
        in_lyt.setContentsMargins(12, 10, 12, 10)
        in_lyt.setSpacing(8)

        self._input = QLineEdit()
        self._input.setPlaceholderText("Ask Argus anything about your system security…")
        self._input.setFont(QFont(_FONT, 10))
        self._input.setFixedHeight(36)
        self._input.setStyleSheet(
            f"QLineEdit{{background:{CARD};color:{TEXT};"
            f"border:1px solid {BORDER};border-radius:8px;padding:0 12px;}}"
            f"QLineEdit:focus{{border-color:{ACCENT};}}"
        )
        self._input.returnPressed.connect(self._send)

        self._send_btn = QPushButton("Send")
        self._send_btn.setFixedSize(64, 36)
        self._send_btn.setFont(QFont(_FONT, 10, QFont.Bold))
        self._send_btn.setCursor(Qt.PointingHandCursor)
        self._send_btn.setStyleSheet(
            f"QPushButton{{background:{ACCENT};color:white;"
            f"border:none;border-radius:8px;}}"
            f"QPushButton:hover{{background:#388bfd;}}"
            f"QPushButton:disabled{{background:{MUTED};color:{BORDER};}}"
        )
        self._send_btn.clicked.connect(self._send)

        in_lyt.addWidget(self._input)
        in_lyt.addWidget(self._send_btn)
        root.addWidget(input_frame)

        # ── Welcome message ───────────────────────────────────────────────────
        self._add_system_msg(
            "Argus online. I'm watching your system. Ask me anything or use the quick actions above.\n"
            "I can check threats, block IPs, read logs, and reason about your security posture."
        )

    # ── Bubble management ──────────────────────────────────────────────────────

    def _add_bubble(self, text: str, role: str):
        """Insert a chat bubble before the stretch spacer."""
        bubble = _Bubble(text, role)
        # Insert before the trailing stretch (last item)
        count = self._chat_layout.count()
        self._chat_layout.insertWidget(count - 1, bubble)
        self._scroll_to_bottom()

    def _add_system_msg(self, text: str):
        self._add_bubble(text, "system")

    def _show_thinking(self):
        self._thinking_bubble = _ThinkingBubble()
        count = self._chat_layout.count()
        self._chat_layout.insertWidget(count - 1, self._thinking_bubble)
        self._scroll_to_bottom()

    def _hide_thinking(self):
        if self._thinking_bubble:
            self._thinking_bubble.stop()
            self._thinking_bubble.setParent(None)
            self._thinking_bubble.deleteLater()
            self._thinking_bubble = None

    def _scroll_to_bottom(self):
        QTimer.singleShot(50, lambda: (
            self._scroll.verticalScrollBar().setValue(
                self._scroll.verticalScrollBar().maximum()
            )
        ))

    # ── Send / receive ─────────────────────────────────────────────────────────

    def _send(self):
        msg = self._input.text().strip()
        if not msg:
            return
        self._input.clear()
        self._dispatch(msg)

    def _on_quick(self, payload: str):
        if payload == "__clear__":
            self._clear_chat()
            return
        if payload == "__reload_aria__":
            self._reload_aria()
            return
        self._dispatch(payload)

    def _dispatch(self, message: str):
        if self._worker_thread and self._worker_thread.isRunning():
            self._add_system_msg("Still thinking… please wait.")
            return

        self._add_bubble(message, "user")
        self._show_thinking()
        self._set_busy(True)
        self._status_lbl.setText("Thinking…")

        # Create worker + thread
        worker = _ChatWorker(message)
        thread = QThread(self)
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.response_ready.connect(self._on_response)
        worker.error.connect(self._on_error)
        worker.response_ready.connect(thread.quit)
        worker.error.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(lambda: setattr(self, "_worker_thread", None))

        self._worker_thread = thread
        thread.start()

    @Slot(str)
    def _on_response(self, text: str):
        self._hide_thinking()
        self._add_bubble(text, "aria")
        self._set_busy(False)
        self._status_lbl.setText("Ready")

    @Slot(str)
    def _on_error(self, err: str):
        self._hide_thinking()
        self._add_bubble(f"⚠ {err}", "system")
        self._set_busy(False)
        self._status_lbl.setText("Error")

    def _set_busy(self, busy: bool):
        self._send_btn.setEnabled(not busy)
        self._input.setEnabled(not busy)

    # ── Utilities ──────────────────────────────────────────────────────────────

    def _clear_chat(self):
        # Remove all bubbles (everything except the trailing stretch)
        while self._chat_layout.count() > 1:
            item = self._chat_layout.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()
        try:
            from Main_Unit.Engine.Service.AVBrain import get_avbrain
            get_avbrain().clear_chat_history()
        except Exception:
            pass
        self._add_system_msg("Chat cleared. Argus memory reset.")

    def _reload_aria(self):
        try:
            from Main_Unit.Engine.Service.AVBrain import get_avbrain
            get_avbrain().reload_aria_prompts()
            self._add_system_msg("✅ soul.md + mind.md reloaded. Argus personality updated.")
        except Exception as e:
            self._add_system_msg(f"⚠ Reload failed: {e}")
