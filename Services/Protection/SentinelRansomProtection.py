# SentinelRansomProtection.py
# Full ransomware behavioral detection and containment engine.
#
# Detection layers:
#   1. Canary honeypot files — AAA prefix so ransomware touches them first alphabetically
#   2. Mass rename detector — N files renamed to ransomware extensions within T seconds
#   3. Entropy spike detector — file content becomes highly entropic (encryption)
#   4. Shadow copy deletion monitor — vssadmin/wmic delete is a ransomware tell
#   5. Backup sabotage monitor — bcdedit recoveryenabled no
#
# On detection: kill the offending process, quarantine via Executioner, toast alert.

import os
import sys
import time
import math
import threading
import subprocess
import hashlib
import struct
from pathlib import Path
from collections import defaultdict, deque
from typing import Optional, Dict, Set, List
from datetime import datetime

import psutil
import wmi
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from winotify import Notification, audio

from Config.Sys_Config import SYSTEM_ICON_PATH, watch_dirs, SCAN_EXTENSIONS
from Interface.write_to_log import write_to_log
from Interface.find_items import find_items

# Brain import is deferred to avoid circular imports at module load time
def _get_brain():
    from Services.SentinelBrain import get_brain, ThreatEvent, ThreatCategory, ThreatSeverity
    return get_brain(), ThreatEvent, ThreatCategory, ThreatSeverity

RANSOM_LOG = "logs/Ransom.log"

# Extensions that ransomware renames files to
RANSOM_EXTENSIONS: Set[str] = {
    '.locked', '.encrypted', '.crypto', '.cry', '.lock', '.ryk', '.conti',
    '.lockbit', '.wannacry', '.darkside', '.crypt', '.enc', '.ezz', '.exx',
    '.vvv', '.aaa', '.abc', '.xyz', '.zzz', '.micro', '.ttt', '.mp3',
    '.cerber', '.cerber2', '.cerber3', '.coverton', '.crypz', '.cryp1',
    '.cryptowall', '.dharma', '.globe', '.osiris', '.zepto', '.locky',
    '.sage', '.shit', '.thor', '.vault', '.wncry', '.wncryt', '.wcry',
    '.id-', '.ransom', '.pays', '.STOP', '.djvu',
}

# Legitimate extensions that should never be renamed by normal user activity
PROTECTED_EXTENSIONS: Set[str] = {
    '.docx', '.xlsx', '.pptx', '.pdf', '.jpg', '.jpeg', '.png', '.mp4',
    '.mp3', '.zip', '.rar', '.doc', '.xls', '.ppt', '.txt', '.csv',
}

# Extensions that are ALREADY high-entropy by design (compressed / encoded).
# Do NOT run entropy checks on these — they will always score 7.0-8.0 even
# when untouched, causing constant false positives.
_SKIP_ENTROPY_EXTENSIONS: Set[str] = {
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp',   # images (DCT/lossless)
    '.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv',     # video
    '.mp3', '.aac', '.ogg', '.flac', '.wav',            # audio
    '.zip', '.rar', '.7z', '.gz', '.bz2', '.tar',       # archives
    '.apk', '.jar',                                      # already-zipped containers
}

# Suspicious commands indicating ransomware deleting backups
BACKUP_SABOTAGE_PATTERNS = [
    'vssadmin delete shadows',
    'wmic shadowcopy delete',
    'bcdedit /set recoveryenabled no',
    'bcdedit /set bootstatuspolicy ignoreallfailures',
    'wbadmin delete catalog',
    'diskshadow /s',
]

CANARY_FILENAME = "AAA_Sentinel_Canary_DO_NOT_MODIFY.txt"
CANARY_CONTENT_TEMPLATE = (
    "This file is monitored by Aria Security Ransomware Protection.\n"
    "Any modification or renaming will trigger an immediate security response.\n"
    "Sentinel Canary ID: {canary_id}\nCreated: {created}\n"
)

# Detection thresholds
MASS_RENAME_COUNT = 8       # files renamed within window
MASS_RENAME_WINDOW = 10.0   # seconds
ENTROPY_THRESHOLD = 7.2     # bits per byte (normal files ~4-6, encrypted ~7.9)
ENTROPY_SAMPLE_SIZE = 65536 # 64KB sample for entropy calculation


def _log(msg: str):
    write_to_log(msg, RANSOM_LOG)


def _compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _file_entropy(path: str) -> float:
    try:
        with open(path, 'rb') as f:
            sample = f.read(ENTROPY_SAMPLE_SIZE)
        return _compute_entropy(sample)
    except (OSError, PermissionError):
        return 0.0


def _get_process_accessing_file(filepath: str) -> Optional[psutil.Process]:
    """
    Try to find which process last touched a file.

    Strategy (Windows-specific):
      1. Open-handle scan — succeeds only when Sentinel runs with
         SeDebugPrivilege; rarely works in practice on modern Windows.
      2. Heuristic fallback — ransomware encrypts aggressively, so look
         for recently-started (< 120 s) non-system user processes that are
         actively consuming CPU during the event window.  The highest-CPU
         candidate is returned as the most-likely encryptor.
    """
    # ── Strategy 1: open handle lookup ───────────────────────────────────────
    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                for f in proc.open_files():
                    if f.path.lower() == filepath.lower():
                        return proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass

    # ── Strategy 2: CPU-spike heuristic on recently-created user processes ───
    # Processes that are: started recently, not system/known-safe, and burning
    # CPU are the most likely encryptors during an active ransomware event.
    _SKIP_NAMES: Set[str] = {
        'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
        'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe',
        'searchindexer.exe', 'python.exe', 'pythonw.exe', 'sentinelui.exe',
    }
    try:
        now = time.time()
        candidates: List[tuple] = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
            try:
                pid  = proc.info['pid']
                name = (proc.info['name'] or '').lower()
                exe  = (proc.info['exe']  or '').lower()
                ct   = proc.info.get('create_time') or 0.0
                if pid in (os.getpid(), 0, 4):
                    continue
                if name in _SKIP_NAMES:
                    continue
                if exe.startswith(('c:\\windows\\', 'c:\\program files\\')):
                    continue
                if now - ct > 120:          # only care about processes < 2 min old
                    continue
                cpu = proc.cpu_percent(interval=0.05)
                if cpu > 5.0:               # actively burning CPU → encrypting
                    candidates.append((cpu, proc))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            return candidates[0][1]
    except Exception:
        pass

    return None


def _kill_process(pid: int, name: str):
    """Terminate a process and log the action."""
    try:
        p = psutil.Process(pid)
        p.suspend()  # pause first to stop encryption mid-flight
        time.sleep(0.3)
        p.kill()
        _log(f"[RANSOM] KILLED PID {pid} ({name}) — ransomware containment")
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        _log(f"[RANSOM] Could not kill PID {pid}: {e}")
        return False


def _toast_alert(title: str, msg: str):
    icon = find_items(SYSTEM_ICON_PATH)
    try:
        toast = Notification(
            app_id="Aria Security",
            title=title,
            msg=msg,
            icon=icon,
            duration="long",
        )
        toast.set_audio(audio.Reminder, loop=False)
        toast.show()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Canary manager
# ---------------------------------------------------------------------------

class CanaryManager:
    """Places and monitors honeypot files in watched directories."""

    def __init__(self, watch_paths: List[str]):
        self.watch_paths = watch_paths
        self.canary_paths: Dict[str, str] = {}  # dir -> canary_path
        self.canary_hashes: Dict[str, str] = {}  # canary_path -> sha256
        self._lock = threading.Lock()

    def deploy(self):
        for directory in self.watch_paths:
            try:
                if not os.path.isdir(directory):
                    continue
                canary_path = os.path.join(directory, CANARY_FILENAME)
                canary_id = hashlib.md5(directory.encode()).hexdigest()[:8]
                content = CANARY_CONTENT_TEMPLATE.format(
                    canary_id=canary_id,
                    created=datetime.now().isoformat()
                )

                # If the file already exists (hidden/read-only from a prior run),
                # strip the protection attributes so we can overwrite it.
                if os.path.exists(canary_path):
                    try:
                        subprocess.run(
                            ['attrib', '-H', '-R', canary_path],
                            capture_output=True,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                        )
                    except Exception:
                        pass

                try:
                    with open(canary_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    h = hashlib.sha256(content.encode()).hexdigest()
                except PermissionError:
                    # File is still locked — read the existing content and register
                    # its hash so watchdog monitoring still works even without a rewrite.
                    try:
                        with open(canary_path, 'r', encoding='utf-8') as f:
                            existing = f.read()
                        h = hashlib.sha256(existing.encode()).hexdigest()
                        _log(f"[CANARY] Existing canary registered (read-only): {canary_path}")
                    except Exception as e2:
                        _log(f"[CANARY] Cannot access existing canary {canary_path}: {e2}")
                        continue

                # Re-hide the file after writing
                subprocess.run(
                    ['attrib', '+H', canary_path],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                with self._lock:
                    self.canary_paths[directory] = canary_path
                    self.canary_hashes[canary_path] = h
                _log(f"[CANARY] Deployed: {canary_path}")
            except Exception as e:
                _log(f"[CANARY] Deploy failed for {directory}: {e}")

    def remove(self):
        for canary_path in list(self.canary_paths.values()):
            try:
                if os.path.exists(canary_path):
                    subprocess.run(['attrib', '-H', canary_path], capture_output=True,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
                    os.remove(canary_path)
            except Exception:
                pass

    def is_canary(self, path: str) -> bool:
        return os.path.basename(path) == CANARY_FILENAME

    def check_canary_integrity(self, path: str) -> bool:
        """Returns True if the canary at path has been tampered with."""
        with self._lock:
            expected_hash = self.canary_hashes.get(path)
        if expected_hash is None:
            return False
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            actual = hashlib.sha256(content.encode()).hexdigest()
            return actual != expected_hash
        except Exception:
            # File renamed or deleted — also counts as tampered
            return True


# ---------------------------------------------------------------------------
# Watchdog event handler
# ---------------------------------------------------------------------------

class RansomEventHandler(FileSystemEventHandler):

    def __init__(self, controller: "RansomProtectionController"):
        super().__init__()
        self.controller = controller
        # Sliding window: track rename events per process window
        self._rename_times: deque = deque()
        self._lock = threading.RLock()

    def on_moved(self, event):
        if event.is_directory:
            return
        src = event.src_path
        dst = event.dest_path
        self._handle_rename(src, dst)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._handle_modified(event.src_path)

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle_created(event.src_path)

    def _handle_rename(self, src: str, dst: str):
        # Canary tampered?
        if self.controller.canary_mgr.is_canary(src):
            _log(f"[RANSOM] CANARY RENAMED: {src} -> {dst}")
            self.controller.trigger_containment(
                src, "Canary file renamed — ransomware confirmed", critical=True
            )
            return

        dst_ext = Path(dst).suffix.lower()
        src_ext = Path(src).suffix.lower()

        # Protected doc renamed to ransomware ext?
        if src_ext in PROTECTED_EXTENSIONS and dst_ext in RANSOM_EXTENSIONS:
            _log(f"[RANSOM] RANSOM RENAME: {src} -> {dst}")
            with self._lock:
                now = time.time()
                self._rename_times.append(now)
                # prune old entries
                while self._rename_times and self._rename_times[0] < now - MASS_RENAME_WINDOW:
                    self._rename_times.popleft()
                count = len(self._rename_times)

            if count >= MASS_RENAME_COUNT:
                _log(f"[RANSOM] MASS RENAME DETECTED: {count} files in {MASS_RENAME_WINDOW}s")
                self.controller.trigger_containment(
                    dst, f"Mass file rename: {count} files encrypted", critical=True
                )
            else:
                _log(f"[RANSOM] Suspicious rename #{count}: {Path(dst).name}")
                self.controller.record_suspicious_rename(count)

        # Any file renamed to ransom ext (even without known src ext)
        elif dst_ext in RANSOM_EXTENSIONS:
            _log(f"[RANSOM] File renamed to ransom extension: {dst}")
            with self._lock:
                now = time.time()
                self._rename_times.append(now)
                while self._rename_times and self._rename_times[0] < now - MASS_RENAME_WINDOW:
                    self._rename_times.popleft()
                count = len(self._rename_times)
            if count >= MASS_RENAME_COUNT:
                self.controller.trigger_containment(
                    dst, f"Mass ransom extension rename: {count} files", critical=True
                )

    def _handle_modified(self, path: str):
        # Canary modified?
        if self.controller.canary_mgr.is_canary(path):
            if self.controller.canary_mgr.check_canary_integrity(path):
                _log(f"[RANSOM] CANARY MODIFIED: {path}")
                self.controller.trigger_containment(
                    path, "Canary file modified — ransomware confirmed", critical=True
                )
            return

        ext = Path(path).suffix.lower()
        if ext not in PROTECTED_EXTENSIONS:
            return

        # Skip already-compressed / already-high-entropy formats — these will
        # always read 7.0-8.0 even when untouched and produce constant false positives.
        if ext in _SKIP_ENTROPY_EXTENSIONS:
            return

        # Entropy check: encrypted documents have very high entropy
        try:
            size = os.path.getsize(path)
        except OSError:
            return
        if size < 512:
            return

        entropy = _file_entropy(path)
        if entropy >= ENTROPY_THRESHOLD:
            _log(f"[RANSOM] HIGH ENTROPY ({entropy:.2f}): {path}")
            self.controller.record_entropy_hit(path, entropy)

    def _handle_created(self, path: str):
        name = Path(path).name.lower()
        # Ransom note heuristics
        ransom_note_patterns = [
            'read_me', 'readme', 'how_to_decrypt', 'decrypt_instruction',
            'recovery_file', 'files_encrypted', 'ransom_note', 'restore_files',
            '!readme', '_readme', 'help_decrypt', 'how_to_restore',
            'decrypt_my_files', 'your_files_are_encrypted',
        ]
        if any(p in name for p in ransom_note_patterns):
            _log(f"[RANSOM] RANSOM NOTE CREATED: {path}")
            self.controller.trigger_containment(
                path, f"Ransom note created: {name}", critical=True
            )


# ---------------------------------------------------------------------------
# Command monitor — watches for vssadmin/wbadmin/bcdedit abuse
# ---------------------------------------------------------------------------

class BackupSabotageMonitor(threading.Thread):
    """WMI-based process creation watcher for backup deletion commands."""

    def __init__(self, controller: "RansomProtectionController"):
        super().__init__(daemon=True, name="RansomCmdMonitor")
        self.controller = controller
        self.running = False

    def run(self):
        self.running = True
        try:
            c = wmi.WMI()
            watcher = c.Win32_Process.watch_for("creation")
            while self.running:
                try:
                    # timeout_ms=2000 means the call returns every 2 s even if
                    # no process was created, so stop() can unblock the thread
                    # responsively instead of waiting for the next OS event.
                    proc = watcher(timeout_ms=2000)
                    if not self.running:
                        break
                    cmdline = (proc.CommandLine or "").lower()
                    for pattern in BACKUP_SABOTAGE_PATTERNS:
                        if pattern in cmdline:
                            _log(f"[RANSOM] BACKUP SABOTAGE: {cmdline}")
                            self.controller.trigger_containment(
                                proc.ExecutablePath or "unknown",
                                f"Backup deletion detected: {cmdline[:80]}",
                                pid=proc.ProcessId,
                                critical=True,
                            )
                            break
                except wmi.x_wmi_timed_out:
                    continue   # normal poll tick — recheck self.running
                except Exception as e:
                    if self.running:
                        _log(f"[RANSOM] CmdMonitor error: {e}")
                        time.sleep(1)
        except Exception as e:
            _log(f"[RANSOM] CmdMonitor fatal: {e}")

    def stop(self):
        self.running = False


# ---------------------------------------------------------------------------
# Main controller
# ---------------------------------------------------------------------------

class RansomProtectionController:
    """
    Top-level ransomware protection controller.
    Integrates with SentinelWorker via start()/stop().

    Set enable_isolation=True to automatically kill the ransomware process.
    """

    def __init__(self, enable_isolation: bool = True, executioner=None):
        self.enable_isolation = enable_isolation
        self.executioner = executioner  # optional Executioner for quarantine

        self.canary_mgr = CanaryManager(watch_dirs)
        self.observer: Optional[Observer] = None
        self.cmd_monitor: Optional[BackupSabotageMonitor] = None
        self.running = False
        self._lock = threading.Lock()

        # State tracking
        self._entropy_hits: Dict[str, List[float]] = defaultdict(list)  # path -> [timestamps]
        self._suspicious_rename_count = 0
        self._containment_triggered = False
        self._containment_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        if self.running:
            return
        self.running = True
        self._containment_triggered = False

        # Deploy honeypot canary files
        self.canary_mgr.deploy()

        # Start filesystem watcher
        handler = RansomEventHandler(self)
        self.observer = Observer()
        for directory in watch_dirs:
            if os.path.isdir(directory):
                self.observer.schedule(handler, path=directory, recursive=True)
                _log(f"[RANSOM] Watching: {directory}")
        self.observer.start()

        # Start backup sabotage monitor
        self.cmd_monitor = BackupSabotageMonitor(self)
        self.cmd_monitor.start()

        _log("[RANSOM] Ransomware Protection ACTIVE")
        _toast_alert("Ransomware Protection", "Active — monitoring for ransomware activity")
        try:
            brain, _, _, _ = _get_brain()
            brain.set_module_running("RansomProtection", True)
        except Exception:
            pass

    def stop(self):
        self.running = False

        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=3)
            except Exception:
                pass
            self.observer = None

        if self.cmd_monitor:
            self.cmd_monitor.stop()
            self.cmd_monitor = None

        self.canary_mgr.remove()
        _log("[RANSOM] Ransomware Protection STOPPED")
        try:
            brain, _, _, _ = _get_brain()
            brain.set_module_running("RansomProtection", False)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Detection callbacks
    # ------------------------------------------------------------------

    def record_suspicious_rename(self, count: int):
        with self._lock:
            self._suspicious_rename_count = count
        if count >= 3:
            _toast_alert(
                "Ransomware Warning",
                f"Suspicious file renaming detected ({count} files). Monitoring closely."
            )

    def record_entropy_hit(self, path: str, entropy: float):
        now = time.time()
        with self._lock:
            hits = self._entropy_hits[path]
            hits.append(now)
            # prune old
            self._entropy_hits[path] = [t for t in hits if now - t < 30]
            count = len(self._entropy_hits[path])

        if count >= 3:
            _log(f"[RANSOM] ENTROPY HIT x{count} on {path} (entropy={entropy:.2f})")
            self.trigger_containment(path, f"Repeated high-entropy writes (entropy={entropy:.2f})")

    def trigger_containment(
        self,
        file_path: str,
        reason: str,
        pid: Optional[int] = None,
        critical: bool = False,
    ):
        with self._containment_lock:
            if self._containment_triggered and not critical:
                return
            self._containment_triggered = True

        _log(f"[RANSOM] CONTAINMENT TRIGGERED: {reason}")
        _log(f"[RANSOM] Affected file: {file_path}")

        try:
            brain, ThreatEvent, ThreatCategory, ThreatSeverity = _get_brain()
            brain.emit_event(ThreatEvent(
                category=ThreatCategory.RANSOMWARE,
                severity=ThreatSeverity.CRITICAL if critical else ThreatSeverity.HIGH,
                title="Ransomware containment triggered",
                detail=reason,
                source_module="RansomProtection",
                file_path=file_path,
                pid=pid,
            ))
        except Exception:
            pass

        # Find responsible process if not provided
        if pid is None:
            proc = _get_process_accessing_file(file_path)
            if proc:
                pid = proc.pid
                name = proc.name()
            else:
                name = "unknown"
        else:
            try:
                name = psutil.Process(pid).name()
            except Exception:
                name = "unknown"

        # Kill process
        if self.enable_isolation and pid is not None:
            # Safety: never kill our own process or system processes
            safe_to_kill = pid not in (os.getpid(), 0, 4)
            if safe_to_kill:
                _kill_process(pid, name)

        # Toast alert
        _toast_alert(
            "RANSOMWARE DETECTED",
            f"Threat contained! Process: {name}\nReason: {reason}"
        )

        # Quarantine the file via Executioner if available
        if self.executioner and os.path.exists(file_path):
            try:
                self.executioner.handle_threat(file_path)
            except Exception as e:
                _log(f"[RANSOM] Executioner quarantine failed: {e}")

        # Suspend all user-writable processes as a last resort on critical hits
        if critical:
            self._emergency_suspend_user_processes(exclude_pid=pid)

    def _emergency_suspend_user_processes(self, exclude_pid: Optional[int] = None):
        """
        On confirmed ransomware: suspend non-system processes to halt
        encryption in progress. User must reboot after containment.
        This is last-resort only.
        """
        _log("[RANSOM] EMERGENCY: Suspending user processes to halt encryption")
        system_names = {
            'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
            'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe',
            'sentinelui.exe', 'python.exe', 'pythonw.exe',
        }
        our_pid = os.getpid()
        suspended = []
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                name = (proc.info['name'] or '').lower()
                if pid in (our_pid, 0, 4) or pid == exclude_pid:
                    continue
                if name in system_names:
                    continue
                exe = (proc.info['exe'] or '').lower()
                if exe.startswith(r'c:\windows') or exe.startswith(r'c:\program files'):
                    continue
                proc.suspend()
                suspended.append((pid, name))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

        _log(f"[RANSOM] Suspended {len(suspended)} processes: {suspended[:10]}")
        _toast_alert(
            "RANSOMWARE EMERGENCY STOP",
            f"Suspended {len(suspended)} processes. Reboot required to resume normal operation."
        )

    def is_running(self) -> bool:
        return self.running
