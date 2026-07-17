# SentinelService.py - FIXED: No cross-thread timer issues
import os
import sys
import time
import json
from pathlib import Path
from PySide6.QtCore import QThread, Signal, QObject, QTimer, Slot
from PySide6.QtCore import QSettings, QCoreApplication
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import winreg

from Main_Unit.Actions.Execute_Action import Executioner
from Main_Unit.Engine.Compiler.SentinelCompiler_v5 import VirusScanner
from Main_Unit.Engine.Service.SentinelNetProtectionNG2 import SentinelAgentService as NetService

# Fixed get_user_directories (removed duplicate Desktop)
def get_user_directories():
    """Get paths to user directories: Desktop, Documents, Downloads on Windows."""
    home = os.path.expanduser("~")
    dirs = {
        "Desktop": os.path.join(home, "Desktop"),
        "Documents": os.path.join(home, "Documents"),
        "Pictures": os.path.join(home, "Pictures"),
        "Videos": os.path.join(home, "Videos"),
        "Music": os.path.join(home, "Music")
    }
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
        downloads_guid = "{374DE290-123F-4565-9164-39C4925E467B}"
        dirs["Downloads"], _ = winreg.QueryValueEx(reg_key, downloads_guid)
        winreg.CloseKey(reg_key)
    except FileNotFoundError:
        dirs["Downloads"] = os.path.join(home, "Downloads")
    return [d for d in dirs.values() if os.path.exists(d)]

def is_user_file(event):
    """Filter to only user-generated files, ignore system/temp files."""
    src_path = event.src_path.lower()
    system_paths = [
        'windows', 'program files', 'programdata', 'appdata\\local\\temp',
        'appdata\\roaming\\microsoft', '$recycle.bin', 'system volume information',
        '__pycache__', '.venv', 'venv', 'node_modules', '.git'
    ]
    if any(sys_path in src_path for sys_path in system_paths):
        return False
    temp_exts = {'.tmp', '.temp', '.log', '~', '.bak', '.old', '.chk', '.sys', '.pyc', '.pyo'}
    if Path(src_path).suffix.lower() in temp_exts:
        return False
    system_files = {'thumbs.db', 'desktop.ini', 'autorun.inf'}
    if Path(src_path).name.lower() in system_files:
        return False
    return True

class AnomalyHandler(FileSystemEventHandler, QObject):
    anomaly_detected = Signal(str)

    def __init__(self, settings, scanner, executor, parent=None):
        QObject.__init__(self, parent)
        FileSystemEventHandler.__init__(self)
        self.settings = settings
        self.scanner = scanner
        self.executor = executor

    def on_any_event(self, event):
        if event.is_directory or not is_user_file(event):
            return
        dir_path = os.path.dirname(event.src_path)
        user_dirs = get_user_directories()
        if not any(dir_path.lower().startswith(user_dir.lower()) for user_dir in user_dirs):
            return
        self.log_anomaly(dir_path)
        self.anomaly_detected.emit(dir_path)

    def log_anomaly(self, dir_path):
        try:
            anomaly_list = self.settings.value("anomaly_directory", [])
            if isinstance(anomaly_list, str):
                anomaly_list = json.loads(anomaly_list)
            elif not isinstance(anomaly_list, list):
                anomaly_list = []
            if not any(item.get("file", "") == dir_path for item in anomaly_list):
                anomaly_list.append({"file": dir_path})
                self.settings.setValue("anomaly_directory", anomaly_list)
                self.settings.sync()
                print(f"Logged user anomaly directory: {dir_path}")
        except Exception as e:
            print(f"Error updating QSettings: {e}")

class SentinelWorker(QObject):
    """Worker object - NO PERSISTENT TIMERS, singleShot chaining only."""
    display_status_changed = Signal(str)
    status_changed = Signal(str)
    scanning_complete = Signal(int)

    def __init__(self):
        super().__init__()
        QCoreApplication.setOrganizationName("Aria")
        QCoreApplication.setApplicationName("Aria Security")
        self.settings = QSettings()
        self.scanner = VirusScanner()
        self.net_service = NetService(interval=1.5)
        self.executor = Executioner()
        self.observer = None
        self.running = False
        self.scan_cancelled = False  # ✅ Per-scan cancel flag

    def net_start_monitor(self):
        self.display_status_changed.emit("Status: Online")
        self.net_service.start_monitoring()

    def net_stop_monitor(self):
        self.display_status_changed.emit("Status: Offline")
        self.net_service.stop_monitoring()

    def train_model_current_history(self):
        self.display_status_changed.emit("Status: Training")
        self.net_service.train_model_async()

    @Slot(float)
    def collect_and_train_model(self, duration):
        self.display_status_changed.emit(f"Status: Training {duration}")
        self.net_service.train_model_async(collect_minutes=duration)

    def start_monitoring(self):
        self.status_changed.emit("Sentinel Protection: Starting...")
        self.running = True
        
        # ✅ NO PERSISTENT TIMER - singleShot chain starts here
        self.schedule_next_scan()
        
        # Network monitoring
        self.net_start_monitor()
        
        # Initial scan
        QTimer.singleShot(100, self.periodic_scan)
        
        # Setup observer
        event_handler = AnomalyHandler(self.settings, self.scanner, self.executor, self)
        event_handler.anomaly_detected.connect(self.on_anomaly)
        
        self.observer = Observer()
        user_dirs = get_user_directories()
        for directory in user_dirs:
            if os.path.exists(directory):
                self.observer.schedule(event_handler, path=directory, recursive=True)
                print(f"Monitoring: {directory}")
        self.observer.start()
        
        self.status_changed.emit("Sentinel Protection: Enabled")

    def schedule_next_scan(self):
        """Schedule next scan 5s later - NO persistent timer."""
        if self.running:
            QTimer.singleShot(5000, self.periodic_scan)

    @Slot()
    def periodic_scan(self):
        if not self.running:
            print("⏹️ Scan aborted: not running")
            self.schedule_next_scan()
            return
        
        self.scan_cancelled = False  # Reset per scan
        
        try:
            anomalies = self.settings.value("anomaly_directory", [])
            if not anomalies:
                self.status_changed.emit("Idle")
                self.schedule_next_scan()
                return
            
            anomaly = anomalies[0]
            dir_path = anomaly['file']
            
            # ✅ FIXED: Mutable list references
            running_flag = [self.running]  # [True] - mutable!
            cancel_flag = [self.scan_cancelled]  # [False] - mutable!
            
            if os.path.exists(dir_path):
                self.status_changed.emit(f"Scanning: {os.path.basename(dir_path)}")
                # Pass self.running and self.scan_cancelled to scanner

                scan_count, detections = self.scanner.scan_directory(
                    dir_path, 
                    executor=self.executor,
                    running_flag=running_flag,  # Passes [self.running]
                    cancel_flag=cancel_flag     # Passes [self.scan_cancelled]
                )
                self.scanning_complete.emit(len(detections))
            else:
                self.status_changed.emit("Directory missing - Idle")
            
            self.status_changed.emit("Idle")
            
            # Cleanup
            if isinstance(anomalies, list) and len(anomalies) > 0:
                anomalies.pop(0)
                self.settings.setValue("anomaly_directory", anomalies)
                self.settings.sync()
                
        except Exception as e:
            print(f"Scan error: {e}")
            self.status_changed.emit("Idle - Error")
        
        if self.running:
            self.schedule_next_scan()

    @Slot(str)
    def on_anomaly(self, dir_path):
        print(f"ANOMALY: {dir_path}")

    def stop_monitoring(self):
        print("🛑 Worker stopping...")
        self.running = False        # Sets running_flag[0] = False
        self.scan_cancelled = True  # Sets cancel_flag[0] = True
        
        # Observer stops file events immediately
        if self.observer:
            self.observer.stop()
            self.observer.join(0.5)
        
        self.net_stop_monitor()
        self.status_changed.emit("Sentinel Protection: Disabled")
        print("🛑 Sentinel monitoring stopped safely")

# Usage class for UI
class SentinelService:
    def __init__(self, parent=None):
        self.parent = parent
        self.thread = QThread(parent)
        self.worker = SentinelWorker()
        self.worker.moveToThread(self.thread)
        
        # Connect thread lifecycle
        self.thread.started.connect(self.worker.start_monitoring)
        self.worker.status_changed.connect(self.on_status_changed)
        self.worker.display_status_changed.connect(self.on_display_status_changed)
        self.worker.scanning_complete.connect(self.on_scan_complete)
    
    def start_monitoring(self):
        if not self.thread.isRunning():
            self.thread.start(QThread.Priority.LowPriority)
    
    def stop_monitoring(self):
        self.worker.stop_monitoring()
        self.thread.quit()
        self.thread.wait(3000)
    
    def on_status_changed(self, status):
        if self.parent:
            self.parent.toggle_label.setText(status)
    
    def on_display_status_changed(self, status):
        if self.parent:
            self.parent.display_status.setText(status)
    
    def train_model_current_history(self):
        self.worker.train_model_current_history()
    
    def collect_and_train_model(self, duration):
        self.worker.collect_and_train_model(duration)
    
    def on_scan_complete(self, threats):
        print(f"🛡️ Scan complete: {threats} threats neutralized")

