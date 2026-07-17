import os
import requests

from PySide6.QtCore import (
    Qt, QThread, Signal
)

from Main_Unit.Config.Sys_Config import OWNER, REPO

class ReleaseCheckThread(QThread):
    result_ready = Signal(object, object)  # latest_version, download_url

    def run(self):
        url = f'https://api.github.com/repos/{OWNER}/{REPO}/releases/latest'
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            latest_version = data.get('tag_name', None)
            if data.get('assets'):
                download_url = data['assets'][0]['browser_download_url']
            else:
                download_url = data.get('html_url', None)
            self.result_ready.emit(latest_version, download_url)
        except Exception as e:
            self.result_ready.emit(None, None)

class DownloadThread(QThread):
    progress_updated = Signal(int, int)
    download_complete = Signal(str)
    download_failed = Signal(str)

    def __init__(self, url, local_filename):
        super().__init__()
        self.url = url
        self.local_filename = local_filename

    def run(self):
        try:
            headers = {}
            downloaded_size = 0
            if os.path.exists(self.local_filename):
                downloaded_size = os.path.getsize(self.local_filename)
                headers['Range'] = f'bytes={downloaded_size}-'

            response = requests.get(self.url, headers=headers, stream=True, timeout=15)
            response.raise_for_status()
            total_size = int(response.headers.get('content-length', 0)) + downloaded_size

            with open(self.local_filename, 'ab') as f:
                for chunk in response.iter_content(chunk_size=1024*1024):
                    if chunk:
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        self.progress_updated.emit(downloaded_size, total_size)
            self.download_complete.emit(self.local_filename)
        except Exception as e:
            self.download_failed.emit(str(e))
