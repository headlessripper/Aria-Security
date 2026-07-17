import os, time 
from PySide6.QtCore import Signal, QThread, QObject
from collections import deque

class EmittingStream(QObject):
    """Stream to GUI AND file simultaneously."""
    text_written = Signal(str)
    
    def __init__(self, log_filename: str = 'logs/SystemSentinel.log'):
        super().__init__()
        self.log_filename = log_filename
        self.output_buffer = deque(maxlen=1000)  # Ring buffer
    
    def write(self, text):
        if text.strip():  # Skip empty writes
            # 1. GUI emit
            self.text_written.emit(text.rstrip())
            
            # 2. Buffer for queries
            self.output_buffer.append(text.rstrip())
            
            # 3. Async file write (non-blocking)
            self._async_log(text.rstrip())
    
    def flush(self):
        pass
    
    def _async_log(self, text):
        """Thread-safe file logging."""
        from pathlib import Path
        from Main_Unit.Service.write_to_log import write_to_log
        
        try:
            write_to_log(text, self.log_filename)
        except:
            pass  # Silent fail
    
    def get_recent(self, n=50):
        """Get last N lines for reports."""
        return list(self.output_buffer)[-n:]
    
class LogTailThread(QThread):
    new_line = Signal(str)

    def __init__(self, log_path, parent=None):
        super().__init__(parent)
        self.log_path = log_path
        self._running = True

    def run(self):
        # Wait until file exists
        while not os.path.exists(self.log_path) and self._running:
            time.sleep(0.5)

        with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
            # Jump to end of file
            f.seek(0, os.SEEK_END)

            while self._running:
                line = f.readline()
                if line:
                    self.new_line.emit(line.rstrip())
                else:
                    time.sleep(0.2)

    def stop(self):
        self._running = False