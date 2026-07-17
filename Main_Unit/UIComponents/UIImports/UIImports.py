import sys
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStackedLayout, QFrame, QScrollArea, QPlainTextEdit, QMessageBox, QSystemTrayIcon, QMenu, 
)
from PySide6.QtCore import Qt, QPoint, QPropertyAnimation, QEasingCurve, QSize, QObject, Signal, QThread, QSettings
from PySide6.QtGui import QFont, QIcon, QPixmap, QAction
import qtawesome as qta
import os
import time
import ctypes, traceback

import subprocess
import sys
import io
import qrcode
import json

from Main_Unit.Config.Sys_Config import license_agreement
from Main_Unit.Service.find_menu import find_menu
from Main_Unit.find_items import find_items
from Main_Unit.Service.write_to_log import write_to_log
from Main_Unit.Engine.Service.SentinelService_v2 import SentinelService  # ✅ Import the service
from Main_Unit.Config.Sys_Config import SYSTEM_ICON_PATH, NET_LOG_LOGGING_FILE, APP_NAME, COMPILER_VERSION, VERSION, APP_DESCRIPTION, BUILD_DATE, DEVELOPER, PAIR_PORT, MY_IP
from Main_Unit.Actions.Check_Update import Update
from Main_Unit.Service.SentinelNotify import Notify
# SentinelModel_downloader removed — model downloading handled by AVBrainModelDownloader
from Main_Unit.Engine.Service.SentinelActivation.Sentinellicense_activation import (
    ensure_activated_once,
    get_active_features,
    APP_FEATURES,
)
from Main_Unit.Service.SentinelUserProfile import SystemInfoWindow
from Main_Unit.Service.Pages.SentinelAuthenticationPage import AuthWidget
from Main_Unit.Service.SentinelServiceAgent import EXE_NAMES, start_one
from Main_Unit.Service.PluginInstaller import ensure_all_installed
from Main_Unit.UIComponents.AnimatedDropdown import AnimatedDropdown
from Main_Unit.UIComponents.Card import Card
from Main_Unit.UIComponents.AnimatedToggle import AnimatedToggle
from Main_Unit.Service.FirewallCleanWorker import FirewallCleanupWorker
from Main_Unit.Service.LogTail import LogTailThread, EmittingStream