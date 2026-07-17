"""Plugin System Page — view, enable/disable optional Sentinel plugins."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QColor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QMessageBox,
)

CARD = "#161b22"; BORDER = "#21262d"; SURFACE = "#0d1117"
ACCENT = "#2f81f7"; GREEN = "#3fb950"; RED = "#f85149"; ORANGE = "#d29922"
TEXT = "#e6edf3"; TEXT_DIM = "#8b949e"; TEXT_MUTED = "#484f58"

# Each plugin: (display_name, description, pip_package, import_name, icon_char)
_PLUGINS = [
    ("YARA Engine",       "Signature-based malware detection",       "yara-python",   "yara",        "🔍"),
    ("Cryptography",      "Fernet AES-256 for Secure Vault",         "cryptography",  "cryptography","🔐"),
    ("llama-cpp-python",  "Local LLM inference engine (AVBrain)",    "llama-cpp-python", "llama_cpp", "🧠"),
    ("scikit-learn",      "IsolationForest anomaly detection (AVBrain)", "scikit-learn", "sklearn", "🔬"),
    ("ONNX Runtime",      "ML binary classification engine",         "onnxruntime",   "onnxruntime", "⚙️"),
    ("psutil",            "Process enumeration and memory stats",     "psutil",        "psutil",      "📊"),
    ("requests",          "HTTP client for VirusTotal / threat intel","requests",      "requests",    "🌐"),
    ("schedule",          "Python cron-style task scheduling",        "schedule",      "schedule",    "⏰"),
]


def _find_python_exe() -> str | None:
    """
    Return a usable Python interpreter path for pip install.

    In compiled (PyInstaller) mode sys.executable is the app EXE itself, so
    we cannot run ``sys.executable -m pip``.  We look for a virtualenv or
    system Python next to the EXE.  Returns None if none is found — callers
    must surface an error in that case.

    In source / dev mode sys.executable IS Python — just return it directly.
    """
    if not getattr(sys, "frozen", False):
        return sys.executable  # dev mode — always works

    # Frozen mode: search for a Python interpreter
    exe_dir = Path(sys.executable).parent
    candidates = [
        exe_dir / ".venv" / "Scripts" / "python.exe",
        exe_dir / "venv" / "Scripts" / "python.exe",
        Path(os.environ.get("VIRTUAL_ENV", "")) / "Scripts" / "python.exe",
        exe_dir / "python.exe",
    ]
    for c in candidates:
        try:
            if c.exists():
                return str(c)
        except Exception:
            pass

    # Last resort: look for python on PATH
    try:
        r = subprocess.run(
            ["where", "python"],
            capture_output=True, text=True, timeout=5,
        )
        first = r.stdout.strip().splitlines()[0] if r.returncode == 0 else ""
        if first and Path(first).exists():
            return first
    except Exception:
        pass

    return None


class _InstallWorker(QThread):
    done = Signal(str, bool, str)  # pkg, success, message

    def __init__(self, package: str, python_exe: str):
        super().__init__()
        self._pkg        = package
        self._python_exe = python_exe

    def run(self):
        try:
            result = subprocess.run(
                [self._python_exe, "-m", "pip", "install", self._pkg, "--quiet"],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                self.done.emit(self._pkg, True, "Installed successfully")
            else:
                self.done.emit(self._pkg, False, result.stderr.strip()[:200])
        except Exception as e:
            self.done.emit(self._pkg, False, str(e))


def _is_installed(import_name: str) -> bool:
    try:
        __import__(import_name)
        return True
    except ImportError:
        return False


class _PluginCard(QFrame):
    install_requested = Signal(str, str)  # pip_package, import_name

    def __init__(self, name: str, desc: str, pkg: str, import_name: str,
                 icon: str, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self._pkg         = pkg
        self._import_name = import_name
        self._installed   = _is_installed(import_name)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(14)

        ico_lbl = QLabel(icon)
        ico_lbl.setFixedSize(32, 32)
        ico_lbl.setAlignment(Qt.AlignCenter)
        ico_lbl.setStyleSheet(f"font-size:18px;")
        layout.addWidget(ico_lbl)

        info = QVBoxLayout()
        info.setSpacing(2)
        name_lbl = QLabel(name)
        name_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        desc_lbl = QLabel(desc)
        desc_lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        pkg_lbl  = QLabel(f"pip: {pkg}")
        pkg_lbl.setStyleSheet(f"color:{TEXT_MUTED};font-size:10px;font-family:Consolas;")
        info.addWidget(name_lbl)
        info.addWidget(desc_lbl)
        info.addWidget(pkg_lbl)
        layout.addLayout(info, 1)

        right = QVBoxLayout()
        right.setAlignment(Qt.AlignCenter)
        right.setSpacing(4)

        self._status_lbl = QLabel()
        self._status_lbl.setAlignment(Qt.AlignCenter)
        self._status_lbl.setFixedWidth(90)
        right.addWidget(self._status_lbl)

        self._action_btn = QPushButton()
        self._action_btn.setFixedSize(90, 30)
        self._action_btn.setStyleSheet(
            f"QPushButton{{border-radius:6px;font-size:12px;font-weight:600;}}"
        )
        self._action_btn.clicked.connect(self._on_action)
        right.addWidget(self._action_btn)

        layout.addLayout(right)
        self._refresh_ui()

    def _refresh_ui(self):
        if self._installed:
            self._status_lbl.setText("Installed")
            self._status_lbl.setStyleSheet(f"color:{GREEN};font-size:11px;font-weight:600;")
            self._action_btn.setText("Reinstall")
            self._action_btn.setStyleSheet(
                f"QPushButton{{background:{CARD};color:{TEXT_DIM};"
                f"border:1px solid {BORDER};border-radius:6px;"
                f"font-size:11px;}}"
                f"QPushButton:hover{{background:#1c2128;}}"
            )
        else:
            self._status_lbl.setText("Not Installed")
            self._status_lbl.setStyleSheet(f"color:{ORANGE};font-size:11px;font-weight:600;")
            self._action_btn.setText("Install")
            self._action_btn.setStyleSheet(
                f"QPushButton{{background:{ACCENT};color:white;border:none;"
                f"border-radius:6px;font-size:11px;font-weight:600;}}"
                f"QPushButton:hover{{background:#388bfd;}}"
            )

    def _on_action(self):
        self.install_requested.emit(self._pkg, self._import_name)

    def set_installing(self):
        self._action_btn.setText("Installing…")
        self._action_btn.setEnabled(False)
        self._status_lbl.setText("Installing")
        self._status_lbl.setStyleSheet(f"color:{ACCENT};font-size:11px;")

    def set_result(self, success: bool, msg: str):
        self._action_btn.setEnabled(True)
        self._installed = success if success else _is_installed(self._import_name)
        self._refresh_ui()
        if not success:
            self._status_lbl.setText("Failed")
            self._status_lbl.setStyleSheet(f"color:{RED};font-size:11px;font-weight:600;")


class _ModelCard(QFrame):
    """
    Download card for the AVBrain LLM model (Phi-3.5-mini-instruct-Q4_K_M.gguf).
    Opens AVBrainModelDownloaderWindow on demand — download is always optional.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        from pathlib import Path
        self._model_file = Path.home() / ".AriaSecurity" / "avbrain" / "Phi-3.5-mini-instruct-Q4_K_M.gguf"

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(14)

        ico = QLabel("🧠")
        ico.setFixedSize(32, 32)
        ico.setAlignment(Qt.AlignCenter)
        ico.setStyleSheet("font-size:18px;")
        layout.addWidget(ico)

        info = QVBoxLayout()
        info.setSpacing(2)
        name_lbl = QLabel("AVBrain LLM Model")
        name_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        desc_lbl = QLabel("Phi-3.5-mini-instruct-Q4_K_M — powers Argus Copilot threat reasoning")
        desc_lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        size_lbl = QLabel("~2.2 GB  ·  GPU or CPU  ·  ~/.AriaSecurity/avbrain/")
        size_lbl.setStyleSheet(f"color:{TEXT_MUTED};font-size:10px;font-family:Consolas;")
        info.addWidget(name_lbl)
        info.addWidget(desc_lbl)
        info.addWidget(size_lbl)
        layout.addLayout(info, 1)

        right = QVBoxLayout()
        right.setAlignment(Qt.AlignCenter)
        right.setSpacing(4)

        self._status_lbl = QLabel()
        self._status_lbl.setAlignment(Qt.AlignCenter)
        self._status_lbl.setFixedWidth(100)
        right.addWidget(self._status_lbl)

        self._btn = QPushButton()
        self._btn.setFixedSize(100, 30)
        self._btn.clicked.connect(self._on_click)
        right.addWidget(self._btn)

        layout.addLayout(right)
        self._refresh_ui()

    def _refresh_ui(self):
        if self._model_file.exists():
            sz_mb = self._model_file.stat().st_size / (1024 * 1024)
            self._status_lbl.setText(f"Downloaded\n{sz_mb:.0f} MB")
            self._status_lbl.setStyleSheet(f"color:{GREEN};font-size:11px;font-weight:600;text-align:center;")
            self._btn.setText("Re-download")
            self._btn.setStyleSheet(
                f"QPushButton{{background:{CARD};color:{TEXT_DIM};"
                f"border:1px solid {BORDER};border-radius:6px;font-size:11px;}}"
                f"QPushButton:hover{{background:#1c2128;}}"
            )
        else:
            self._status_lbl.setText("Not Downloaded")
            self._status_lbl.setStyleSheet(f"color:{ORANGE};font-size:11px;font-weight:600;")
            self._btn.setText("Download")
            self._btn.setStyleSheet(
                f"QPushButton{{background:{ACCENT};color:white;border:none;"
                f"border-radius:6px;font-size:11px;font-weight:600;}}"
                f"QPushButton:hover{{background:#388bfd;}}"
            )

    def _on_click(self):
        try:
            from Main_Unit.Engine.Service.SentinelActivation.AVBrainModelDownloader import (
                AVBrainModelDownloaderWindow,
            )
            win = AVBrainModelDownloaderWindow(auto_start=True)
            win.setAttribute(win.WA_DeleteOnClose, True)
            # Refresh our status chip when the window closes
            win.destroyed.connect(self._refresh_ui)
            win.show()
        except Exception as e:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Error", f"Could not open downloader:\n{e}")


class PluginSystemPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(14)

        hdr = QHBoxLayout()
        title = QLabel("Plugin System")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        hdr.addWidget(title)
        hdr.addStretch()
        refresh_btn = QPushButton("Refresh Status")
        refresh_btn.setStyleSheet(
            f"QPushButton{{background:{CARD};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:8px;padding:7px 16px;font-size:13px;}}"
            f"QPushButton:hover{{background:#1c2128;}}"
        )
        refresh_btn.clicked.connect(self._rebuild_cards)
        hdr.addWidget(refresh_btn)
        root.addLayout(hdr)

        _frozen = getattr(sys, "frozen", False)
        _hint_suffix = (
            "  ⚠️  Running as compiled EXE — install packages manually with pip, "
            "or run from source to use the Install button."
            if _frozen else
            "  Install runs pip in the current Python environment. Restart may be required."
        )
        hint = QLabel(
            "Optional Python packages that unlock Sentinel features." + _hint_suffix
        )
        hint.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        hint.setWordWrap(True)
        root.addWidget(hint)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll_widget = QWidget()
        self._cards_layout = QVBoxLayout(scroll_widget)
        self._cards_layout.setContentsMargins(0, 0, 0, 0)
        self._cards_layout.setSpacing(8)

        # ── AI Model section header ───────────────────────────────────────────
        model_hdr = QLabel("AI Models")
        model_hdr.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        model_hdr.setStyleSheet(f"color:{TEXT_DIM};margin-top:4px;")
        self._cards_layout.addWidget(model_hdr)

        self._model_card = _ModelCard()
        self._model_card.setStyleSheet(
            f"QFrame#Card{{background:{CARD};border:1px solid {BORDER};border-radius:10px;}}"
        )
        self._cards_layout.addWidget(self._model_card)

        # ── Python packages section header ────────────────────────────────────
        pkg_hdr = QLabel("Python Packages")
        pkg_hdr.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        pkg_hdr.setStyleSheet(f"color:{TEXT_DIM};margin-top:8px;")
        self._cards_layout.addWidget(pkg_hdr)

        self._cards_layout.addStretch()
        scroll.setWidget(scroll_widget)
        root.addWidget(scroll, 1)

        self._cards: dict[str, _PluginCard] = {}
        self._worker: _InstallWorker | None = None
        QTimer.singleShot(100, self._rebuild_cards)

    def _rebuild_cards(self):
        # Refresh the model card status chip
        self._model_card._refresh_ui()

        # Remove existing pip plugin cards only — keep fixed items (headers, model card, stretch)
        # Fixed items: model_hdr(0), model_card(1), pkg_hdr(2), then dynamic cards, then stretch
        _FIXED = 3  # items before dynamic cards
        while self._cards_layout.count() > _FIXED + 1:   # +1 for trailing stretch
            item = self._cards_layout.takeAt(_FIXED)
            if item and item.widget():
                item.widget().deleteLater()
        self._cards.clear()

        for name, desc, pkg, import_name, icon in _PLUGINS:
            card = _PluginCard(name, desc, pkg, import_name, icon)
            card.setStyleSheet(
                f"QFrame#Card{{background:{CARD};border:1px solid {BORDER};border-radius:10px;}}"
            )
            card.install_requested.connect(self._install)
            # Insert before the trailing stretch
            self._cards_layout.insertWidget(self._cards_layout.count() - 1, card)
            self._cards[pkg] = card

    def _install(self, pkg: str, import_name: str):
        if self._worker and self._worker.isRunning():
            QMessageBox.information(self, "Busy", "An installation is already in progress.")
            return

        python_exe = _find_python_exe()
        if python_exe is None:
            QMessageBox.warning(
                self,
                "Cannot Install Plugins",
                "Plugins cannot be installed from within the compiled application.\n\n"
                "Run AriaSecurity from source (python SentinelUI.py) or ensure a "
                "Python interpreter is accessible next to the EXE.\n\n"
                "Alternatively, install packages manually:\n"
                f"  pip install {pkg}",
            )
            return

        card = self._cards.get(pkg)
        if card:
            card.set_installing()

        # IMPORTANT: do NOT connect finished → deleteLater while holding self._worker.
        # The C++ object would be destroyed but the Python wrapper stays dangling,
        # causing RuntimeError on the next isRunning() check.
        # Instead we clear self._worker = None in the done callback.
        self._worker = _InstallWorker(pkg, python_exe)
        self._worker.done.connect(self._on_install_done)
        self._worker.start()

    def _on_install_done(self, pkg: str, success: bool, msg: str):
        self._worker = None          # drop reference BEFORE any UI work
        card = self._cards.get(pkg)
        if card:
            card.set_result(success, msg)
        if success:
            QMessageBox.information(self, "Installed", f"{pkg} installed successfully.")
        else:
            QMessageBox.warning(self, "Install Failed", f"{pkg}: {msg}")
