import os
import subprocess
from urllib.parse import urlparse

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QProgressBar, QPushButton,
    QMessageBox, QFrame, QGraphicsDropShadowEffect, QApplication
)
from PySide6.QtCore import Qt, QPoint
from PySide6.QtGui import QFont, QColor

from Main_Unit.Worker.UpdatorThreads import ReleaseCheckThread, DownloadThread
from Main_Unit.Config.Sys_Config import CURRENT_VERSION


class Update(QWidget):
    def __init__(self):
        super().__init__()

        self.latest_version = None
        self.download_url = None
        self.local_filename = None

        self.init_ui()
        self.set_state("checking")
        self.check_release()

    def init_ui(self):
        # Modern shadcn card with shadow
        self.setWindowTitle("Aria Security")
        self.setFixedSize(420, 300)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.SubWindow)

        # Glassmorphism background
        self.setAttribute(Qt.WA_TranslucentBackground, True)

        # Main card container
        self.card = QFrame(self)
        self.card.setFixedSize(400, 260)
        self.card.move(10, 10)

        # Shadcn glassmorphism effect
        self.card.setStyleSheet("""
        QFrame {
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 rgba(14, 14, 14, 0.95),
                stop:1 rgba(18, 18, 18, 0.95)
            );
            border: transparent;
            border-radius: 12px;
        }

        /* Stop QLabel from auto-brightening */
        QLabel {
            color: #e5e7eb;
            background-color: transparent;
        }
        """)

        # Drop shadow
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(40)
        shadow.setXOffset(0)
        shadow.setYOffset(20)
        shadow.setColor(QColor(0, 0, 0, 60))
        self.card.setGraphicsEffect(shadow)

        # Layout
        layout = QVBoxLayout(self.card)
        layout.setSpacing(24)
        layout.setContentsMargins(32, 32, 32, 24)

        # Header
        header_layout = QVBoxLayout()
        header_layout.setSpacing(8)

        self.title_label = QLabel("Update Available", self.card)
        self.title_label.setFont(QFont("Inter", 20, QFont.Black))
        self.title_label.setAlignment(Qt.AlignCenter)

        header_layout.addWidget(self.title_label)
        layout.addLayout(header_layout)

        # Content
        self.content_label = QLabel(self.card)
        self.content_label.setFont(QFont("Inter", 14))
        self.content_label.setAlignment(Qt.AlignCenter)
        self.content_label.setWordWrap(True)
        layout.addWidget(self.content_label)

        # Progress bar (shadcn style)
        self.progress_container = QFrame(self.card)
        self.progress_container.setFixedHeight(48)
        self.progress_container.setStyleSheet("""
            QFrame {
                background: transparent;
                border-radius: 8px;
                border: transparent;
            }
        """)
        self.progress_container.hide()

        progress_layout = QVBoxLayout(self.progress_container)
        progress_layout.setContentsMargins(12, 8, 12, 8)

        self.progress_bar = QProgressBar(self.progress_container)
        self.progress_bar.setFixedHeight(20)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: transparent;
                border: 1px solid transparent;
                border-radius: 4px;
                text-align: center;
                color: #444444;
                font-weight: bold;
            }

            QProgressBar::chunk {
                background-color: #ffffff;
                border-radius: 4px;
            }
            """)

        progress_layout.addWidget(self.progress_bar)
        layout.addWidget(self.progress_container)

        # Buttons container
        self.button_frame = QFrame(self.card)
        self.button_frame.setStyleSheet("""
            QFrame {
                background: transparent;
            }
        """)
        btn_layout = QVBoxLayout(self.button_frame)
        btn_layout.setSpacing(12)

        self.update_btn = QPushButton("Download Update", self.button_frame)
        self.update_btn.setFont(QFont("Inter", 14, QFont.Medium))
        self.update_btn.setFixedHeight(44)
        self.update_btn.setStyleSheet("""
            QPushButton {
                padding: 10px;
                font-size: 14px;
                background-color: #000000;
                color: white;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2d2d2d;
                color: white;
            }
        """)
        self.update_btn.clicked.connect(self.start_download)
        self.update_btn.hide()

        self.later_btn = QPushButton("Skip for now", self.button_frame)
        self.later_btn.setFont(QFont("Inter", 14))
        self.later_btn.setFixedHeight(44)
        self.later_btn.setStyleSheet("""
            QPushButton {
                padding: 10px;
                font-size: 14px;
                background-color: #000000;
                color: white;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2d2d2d;
                color: white;
            }
        """)
        #self.later_btn.clicked.connect()

        btn_layout.addWidget(self.update_btn)
        btn_layout.addWidget(self.later_btn)
        layout.addWidget(self.button_frame)

        layout.addStretch()

        # Drag support
        self.dragging = False
        self.drag_position = QPoint()
        self.card.mousePressEvent = self.mouse_press
        self.card.mouseMoveEvent = self.mouse_move
        self.card.mouseReleaseEvent = self.mouse_release
        
    def open_update(self):
        """Call this whenever user triggers 'Check for updates'."""
        self.show()
        self.raise_()          # bring to front
        self.activateWindow()  # focus
        self.set_state("checking")
        self.check_release()

    # Draggable window using non-deprecated globalPosition()
    def mouse_press(self, event):
        if event.button() == Qt.LeftButton:
            self.dragging = True
            global_pos = event.globalPosition()          # QPointF
            self.drag_position = global_pos.toPoint() - self.frameGeometry().topLeft()

    def mouse_move(self, event):
        if self.dragging and event.buttons() == Qt.LeftButton:
            global_pos = event.globalPosition()          # QPointF
            self.move(global_pos.toPoint() - self.drag_position)

    def mouse_release(self, event):
        self.dragging = False

    # State handler (shadcn style)
    def set_state(self, state):
        self.content_label.hide()
        self.progress_container.hide()
        self.update_btn.hide()
        self.later_btn.hide()

        if state == "checking":
            self.title_label.setText("Checking for updates")
            self.content_label.setText("Looking for the latest version...")
            self.content_label.show()

        elif state == "up_to_date":
            self.title_label.setText("Up to date!")
            self.content_label.setText(
                f"You're on the latest version<br><strong>{CURRENT_VERSION}</strong>"
            )
            self.content_label.show()
            self.later_btn.setText("Close")
            self.later_btn.show()

        elif state == "update_available":
            self.title_label.setText("Update Available")
            self.content_label.setText(
                f"Version <strong>{self.latest_version}</strong> is available"
            )
            self.content_label.show()
            self.update_btn.show()
            self.later_btn.show()

        elif state == "downloading":
            self.progress_container.show()
            self.title_label.setText("Downloading Update")

        elif state == "failed":
            self.title_label.setText("Connection Error")
            self.content_label.setText(
                "Unable to check for updates.<br>Please check your internet connection."
            )
            self.content_label.show()
            self.later_btn.show()

    # Release check
    def check_release(self):
        self.release_thread = ReleaseCheckThread()
        self.release_thread.result_ready.connect(self.handle_release_result)
        self.release_thread.start()

    def handle_release_result(self, latest_version, download_url):
        if latest_version is None:
            self.set_state("failed")
            return

        self.latest_version = latest_version
        self.download_url = download_url
        self.local_filename = (
            os.path.basename(urlparse(download_url).path) if download_url else None
        )

        if self.latest_version == CURRENT_VERSION:
            self.set_state("up_to_date")
        else:
            self.set_state("update_available")

    # Download logic
    def start_download(self):
        if not self.download_url:
            QMessageBox.warning(self, "Error", "No download URL available")
            return

        self.set_state("downloading")
        self.update_btn.setEnabled(False)
        self.download_thread = DownloadThread(self.download_url, self.local_filename)
        self.download_thread.progress_updated.connect(self.update_progress)
        self.download_thread.download_complete.connect(self.download_finished)
        self.download_thread.download_failed.connect(self.download_failed)
        self.download_thread.start()

    def update_progress(self, current, total):
        if total <= 0:
            return
        percent = int(current / total * 100)
        self.progress_bar.setValue(percent)
        self.content_label.setText(f"Downloaded {current / 1024 / 1024:.1f} MB")

    def download_finished(self, filename):
        QMessageBox.information(self, "Success", f"Downloaded to {filename}")
        self.run_installer(filename)

    def download_failed(self, error):
        QMessageBox.critical(self, "Download Failed", error)
        self.update_btn.setEnabled(True)
        self.set_state("update_available")

    def run_installer(self, path):
        try:
            subprocess.run([path, "/SILENT"], shell=True)
            QMessageBox.information(self, "Installing", "Update installer launched!")
            self.close()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


#if __name__ == "__main__":
#    import sys#
#
#    app = QApplication(sys.argv)
##    win = Update()
 #   win.show()
 #   sys.exit(app.exec())
