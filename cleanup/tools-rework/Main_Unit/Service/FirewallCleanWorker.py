
import subprocess, sys
from PySide6.QtCore import Signal, QThread

class FirewallCleanupWorker(QThread):
    finished_ok = Signal()
    finished_error = Signal(str)

    def __init__(self, pattern, parent=None):
        super().__init__(parent)
        self.pattern = pattern  # e.g. "PSDS_BLOCK_*" or "Sentinel_BLOCK_*"

    def run(self):
        ps_script = fr"""
            Get-NetFirewallRule |
            Where-Object {{ $_.DisplayName -like "{self.pattern}" }} |
            ForEach-Object {{
                Remove-NetFirewallRule -Name $_.Name -ErrorAction SilentlyContinue
            }}
        """

        kwargs = {
            "capture_output": True,
            "text": True,
            "check": True,
        }

        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        try:
            subprocess.run(["powershell", "-Command", ps_script], **kwargs)
            self.finished_ok.emit()
        except subprocess.CalledProcessError as e:
            self.finished_error.emit(e.stderr or str(e))
        except Exception as e:
            self.finished_error.emit(str(e))