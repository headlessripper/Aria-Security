global _logger_initialized 
import threading
import logging
import os

#-----------------------------------------------------------------------------
# Logger Setup
#-----------------------------------------------------------------------------

import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)

_logger_lock = threading.Lock()
_logger_initialized = False

def setup_logger(log_file_path='logs/sys.log'):
    global _logger_initialized
    with _logger_lock:
        if _logger_initialized:
            return
        try:
            log_dir = os.path.dirname(log_file_path)
            if log_dir:
                try:
                    os.makedirs(log_dir, exist_ok=True)
                except Exception:
                    log_file_path = os.path.basename(log_file_path)

            try:
                logging.basicConfig(
                    filename=log_file_path,
                    filemode='a',
                    level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    encoding='utf-8'
                )
            except Exception:
                logging.basicConfig(
                    filename=log_file_path,
                    filemode='a',
                    level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )

            logging.raiseExceptions = False
            logging.debug('Logger initialized successfully.')
            _logger_initialized = True

        except Exception as e:
            write_to_log(f"Logger initialization failed: {e}")
            _logger_initialized = True

setup_logger()

def write_log(message: str, level=logging.DEBUG):
    try:
        if not _logger_initialized:
            setup_logger()
        logging.log(level, message)
    except Exception:
        pass
setup_logger()
from datetime import datetime

def _to_console_bus(message: str, file_path: str) -> None:
    """Mirror the line into the in-app console bus.

    The Console page reads the bus, not files, so service logging has to be
    published here as well as written to disk. Uses the log file's stem as the
    source (e.g. logs/NetPro.log -> "NetPro"). Never raises.
    """
    try:
        from Services.log_bus import get_log_bus
        source = os.path.splitext(os.path.basename(file_path or ''))[0] or 'Sentinel'
        get_log_bus().emit(str(message), source=source)
    except Exception:
        pass


def write_to_log(message: str, file_path: str = 'logs/Sentinel.log') -> None:
    """Append a timestamped line to *file_path* and publish it to the console bus.

    This function is intentionally silent on all I/O errors — a logging
    helper must never crash its caller.  If writing fails, the message is
    echoed to stderr so it is not silently lost.
    """
    _to_console_bus(message, file_path)
    try:
        dir_part = os.path.dirname(file_path)
        if dir_part:
            os.makedirs(dir_part, exist_ok=True)
        timestamped_message = f'[{datetime.now().isoformat()}] {message}\n'
        with open(file_path, 'a', encoding='utf-8') as log_file:
            log_file.write(timestamped_message)
    except Exception:
        # Best-effort fallback: write to stderr so the message isn't lost,
        # but never raise — callers must not have to worry about logging.
        try:
            import sys as _sys
            _sys.stderr.write(f'[write_to_log fallback] {message}\n')
        except Exception:
            pass
