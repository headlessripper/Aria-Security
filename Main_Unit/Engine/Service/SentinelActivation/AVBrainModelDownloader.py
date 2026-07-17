#!/usr/bin/env python3
"""
AVBrainModelDownloader.py

Downloads the AVBrain LLM model (Phi-3.5-mini-instruct-Q4_K_M.gguf)
if not already present on disk.

Model stats:
  Name : Phi-3.5-mini-instruct-Q4_K_M.gguf
  Size : ~2.2 GB
  Source: bartowski/Phi-3.5-mini-instruct-GGUF on Hugging Face
  Capability: strong reasoning in a 3.8B-parameter footprint, MIT licence
  GPU : full VRAM offload via llama-cpp-python (n_gpu_layers=-1)
  CPU : works on ~8 GB RAM, ~3-6 tokens/sec on modern CPU
"""

import sys
import threading
from pathlib import Path
from typing import Optional

import requests
from PySide6.QtCore import Qt, Signal, QObject, QTimer
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QHBoxLayout,
)

from Main_Unit.Config.Sys_Config import SYSTEM_ICON_PATH
from Main_Unit.find_items import find_items

_system_ico = find_items(SYSTEM_ICON_PATH)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

MODEL_URL = (
    "https://huggingface.co/bartowski/Phi-3.5-mini-instruct-GGUF"
    "/resolve/main/Phi-3.5-mini-instruct-Q4_K_M.gguf"
)
MODEL_DIR  = Path.home() / ".AriaSecurity" / "avbrain"
MODEL_FILE = MODEL_DIR / "Phi-3.5-mini-instruct-Q4_K_M.gguf"


# ---------------------------------------------------------------------------
# Worker signals
# ---------------------------------------------------------------------------

class _Signals(QObject):
    progress = Signal(int)        # 0-100
    status   = Signal(str)
    finished = Signal(bool, str)  # (success, message)


# ---------------------------------------------------------------------------
# Download worker
# ---------------------------------------------------------------------------

class _DownloadWorker(threading.Thread):
    def __init__(self, url: str, target: Path, signals: _Signals):
        super().__init__(daemon=True, name="AVBrainModelDownload")
        self.url     = url
        self.target  = target
        self.signals = signals
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        try:
            self.target.parent.mkdir(parents=True, exist_ok=True)
            self.signals.status.emit("Connecting to Hugging Face…")

            with requests.get(self.url, stream=True, timeout=30) as r:
                r.raise_for_status()
                total_raw = r.headers.get("content-length")
                total = int(total_raw) if total_raw else None

                downloaded = 0
                chunk = max(1024 * 1024, (total // 1000) if total else 1024 * 1024)

                with open(self.target, "wb") as f:
                    for data in r.iter_content(chunk_size=chunk):
                        if self._cancel:
                            self.signals.status.emit("Download cancelled.")
                            self.signals.finished.emit(False, "Cancelled.")
                            return
                        if not data:
                            continue
                        f.write(data)
                        downloaded += len(data)
                        if total:
                            pct = int(downloaded * 100 / total)
                            mb  = downloaded / (1024 * 1024)
                            total_mb = total / (1024 * 1024)
                            self.signals.progress.emit(pct)
                            self.signals.status.emit(
                                f"Downloading… {mb:.0f} / {total_mb:.0f} MB  ({pct}%)"
                            )

            self.signals.progress.emit(100)
            self.signals.status.emit("Download complete.")
            self.signals.finished.emit(True, "Model downloaded successfully.")
        except Exception as e:
            self.signals.finished.emit(False, f"Failed: {e}")


# ---------------------------------------------------------------------------
# Downloader UI  (same dark shadcn style as SentinelModel_downloader.py)
# ---------------------------------------------------------------------------

class AVBrainModelDownloaderWindow(QWidget):
    def __init__(self, auto_start: bool = True):
        super().__init__()
        self._signals = _Signals()
        self._signals.progress.connect(self._on_progress)
        self._signals.status.connect(self._on_status)
        self._signals.finished.connect(self._on_finished)

        self._worker: Optional[_DownloadWorker] = None

        self.setWindowTitle("AVBrain Model Installer")
        self.setWindowIcon(QIcon(_system_ico))
        self.setMinimumWidth(440)
        self.setWindowFlags(
            self.windowFlags()
            & ~Qt.WindowMaximizeButtonHint
            & ~Qt.WindowMinimizeButtonHint
        )
        self._build_ui()
        if auto_start:
            self.start_download()

    def _build_ui(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #0d1117;
                color: #e6edf3;
                font-family: 'Segoe UI', system-ui, sans-serif;
            }
            QLabel#Title {
                font-size: 17px;
                font-weight: 600;
                color: #f0f6fc;
            }
            QLabel#Sub {
                font-size: 12px;
                color: #8b949e;
            }
            QProgressBar {
                border: 1px solid #30363d;
                border-radius: 6px;
                background: #161b22;
                text-align: center;
                color: #e6edf3;
                height: 20px;
            }
            QProgressBar::chunk {
                background: #238636;
                border-radius: 5px;
            }
            QPushButton {
                border-radius: 6px;
                padding: 6px 16px;
                background: #21262d;
                color: #e6edf3;
                border: 1px solid #30363d;
                font-size: 12px;
            }
            QPushButton:hover  { background: #30363d; }
            QPushButton:disabled { color: #484f58; background: #161b22; border-color: #21262d; }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(10)

        title = QLabel("Installing AVBrain Model")
        title.setObjectName("Title")

        sub = QLabel(
            "Phi-3.5-mini-instruct-Q4_K_M.gguf  (~2.2 GB)\n"
            "This model powers AVBrain's threat intelligence and protection\n"
            "level reasoning. Download is required to enable AI features."
        )
        sub.setObjectName("Sub")
        sub.setWordWrap(True)

        self._status_lbl = QLabel("Ready.")
        self._status_lbl.setObjectName("Sub")

        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)

        self._retry_btn = QPushButton("Retry")
        self._retry_btn.setEnabled(False)
        self._retry_btn.clicked.connect(self.start_download)

        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.clicked.connect(self._cancel_download)

        self._close_btn = QPushButton("Close")
        self._close_btn.setEnabled(False)
        self._close_btn.clicked.connect(self.close)

        btn_row.addWidget(self._retry_btn)
        btn_row.addWidget(self._cancel_btn)
        btn_row.addWidget(self._close_btn)

        layout.addWidget(title)
        layout.addWidget(sub)
        layout.addSpacing(6)
        layout.addWidget(self._status_lbl)
        layout.addWidget(self._bar)
        layout.addSpacing(4)
        layout.addLayout(btn_row)

    def start_download(self):
        self._retry_btn.setEnabled(False)
        self._close_btn.setEnabled(False)
        self._cancel_btn.setEnabled(True)
        self._bar.setValue(0)
        self._status_lbl.setText("Starting…")
        self._worker = _DownloadWorker(MODEL_URL, MODEL_FILE, self._signals)
        self._worker.start()

    def _cancel_download(self):
        if self._worker:
            self._worker.cancel()
        self._cancel_btn.setEnabled(False)

    def _on_progress(self, pct: int):
        self._bar.setValue(pct)

    def _on_status(self, text: str):
        self._status_lbl.setText(text)

    def _on_finished(self, success: bool, msg: str):
        self._status_lbl.setText(msg)
        self._cancel_btn.setEnabled(False)
        if success:
            self._bar.setValue(100)
            self._close_btn.setEnabled(True)
            timer = QTimer(self)
            timer.setSingleShot(True)
            timer.timeout.connect(self.close)
            timer.start(1800)
        else:
            self._retry_btn.setEnabled(True)
            self._close_btn.setEnabled(True)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def model_exists() -> bool:
    return MODEL_FILE.exists()


def ensure_model_headless() -> bool:
    """Download model silently (no UI). Returns True on success."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    if MODEL_FILE.exists():
        return True
    try:
        with requests.get(MODEL_URL, stream=True, timeout=30) as r:
            r.raise_for_status()
            with open(MODEL_FILE, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        f.write(chunk)
        return True
    except Exception as e:
        print(f"AVBrain model download failed: {e}", file=sys.stderr)
        return False


def run_downloader_ui() -> bool:
    """Show UI downloader if model is missing. Returns True if model is present afterwards."""
    if MODEL_FILE.exists():
        return True
    app = QApplication.instance() or QApplication(sys.argv)
    win = AVBrainModelDownloaderWindow(auto_start=True)
    win.show()
    app.exec()
    return MODEL_FILE.exists()
