# SentinelStorage.py

import sys
from collections import deque

from PySide6.QtCore import Qt, QThread, Signal, QRectF, QPoint, QTimer
from PySide6.QtGui import QPainter, QColor, QPen, QPainterPath, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QStackedWidget, QGraphicsView,
    QGraphicsScene, QGraphicsLineItem, QGraphicsPathItem, QFrame
)

from Main_Unit.Service.Pages.InterfacePage import InterfacesListPage
from Main_Unit.Service.Pages.Style_Qss.qss import qss
from Main_Unit.find_items import find_items
from Main_Unit.Config.Sys_Config import SYSTEM_ICON_PATH

system_ico = find_items(SYSTEM_ICON_PATH)

# ===================== Main Window (StoragePage only) =====================

class View_Conn(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetScope")
        self.setWindowIcon(QIcon(find_items('icons/icon.png') or 'icons/icon.png'))
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

        # StoragePage as the only main page
        self.page_storage = InterfacesListPage()
        center_lay.addWidget(self.page_storage, 1)

        shell_lay.addWidget(center, 1)
        outer_lay.addWidget(shell)
        self.setCentralWidget(outer)

        # Optional: if StoragePage needs periodic updates, wire a QTimer here
        # e.g.:
        # self._storage_timer = QTimer(self)
        # self._storage_timer.timeout.connect(self.page_storage.update_content)
        # self._storage_timer.start(2000)

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
        # If you keep any workers, stop them here (currently unused in this minimal setup)
        event.accept()


# ===================== main =====================

#def main():
#    app = QApplication(sys.argv)
##    app.setStyle("Fusion")
 #   app.setStyleSheet(qss)
 #   w = MainWindow()
 #   w.show()
 #   sys.exit(app.exec())


#if __name__ == "__main__":
#    main()
