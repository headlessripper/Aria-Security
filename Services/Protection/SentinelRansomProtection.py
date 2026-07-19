# SentinelRansomProtection.py
# Real-time file-system ransomware detection, rewritten as a BaseService.
#
# Detection layers (each contributes a "trip reason" that feeds
# _classify_and_respond's graduated response policy):
#   1. velocity  — too many file-system events in a sliding window
#   2. entropy   — a modified file's content spikes to near-uniform entropy
#   3. canary    — a hidden honeypot file was touched
#   4. extension — a new/renamed file lands on a known ransomware extension
#
# On trip: emit a CRITICAL RANSOMWARE threat event, then classify_and_respond
# decides whether to just alert or to suspend the offending process — subject
# to a safety guard that never suspends a trusted/critical-system process.

from __future__ import annotations
import math, os, time, threading
from collections import deque
from pathlib import Path
from Services.framework.base_service import BaseService
from Services.SentinelBrain import ThreatCategory, ThreatSeverity

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except Exception:  # keep importable in isolation / test environments without watchdog
    Observer = None
    FileSystemEventHandler = object


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data); ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


class _Window:
    """Sliding count of event timestamps. count() is PURE (no mutation) so
    repeated queries don't interfere; add() prunes beyond a max horizon."""
    def __init__(self, max_horizon: float = 3600.0):
        self._ts = deque()
        self._max = max_horizon
    def add(self, ts: float) -> None:
        self._ts.append(ts)
        cutoff = ts - self._max
        while self._ts and self._ts[0] < cutoff:
            self._ts.popleft()
    def count(self, now: float, seconds: float) -> int:
        cutoff = now - seconds
        return sum(1 for t in self._ts if t > cutoff)  # half-open (now-seconds, now]


_DEFAULTS = {
    "watch_dirs": [],
    "window_seconds": 5,
    "velocity_threshold": 30,
    "entropy_threshold": 7.8,
    "entropy_sample_bytes": 8192,
    "canary_count": 3,
    "ransom_extensions": [".locked", ".crypto", ".enc", ".ryk", ".crypt", ".wcry"],
    "action": "auto",                 # auto | alert_only | always_suspend
    "protected_images": ["explorer.exe", "system", "svchost.exe", "csrss.exe"],
}

# Content written into canary honeypot files. Kept generic/inert.
_CANARY_CONTENT = b"Aria Security honeypot file. Do not delete.\n"


class _RansomEventHandler(FileSystemEventHandler):
    """Forwards raw watchdog events to the owning RansomProtection service."""

    def __init__(self, service: "RansomProtection"):
        super().__init__()
        self._service = service

    def on_created(self, event):
        if event.is_directory:
            return
        self._service._handle_fs_event(event.src_path, kind="created")

    def on_modified(self, event):
        if event.is_directory:
            return
        self._service._handle_fs_event(event.src_path, kind="modified")

    def on_moved(self, event):
        if event.is_directory:
            return
        self._service._handle_fs_event(event.dest_path, kind="moved")


class RansomProtection(BaseService):
    name = "RansomProtection"

    def __init__(self, config=None, brain=None):
        cfg = dict(_DEFAULTS); cfg.update(config or {})
        super().__init__(cfg, brain)
        self._window = _Window()
        self._recent_trips: deque = deque()   # (ts, reason) for multi-detector correlation
        self._canaries: set[str] = set()
        self._observer = None

    # --- detection helpers (pinned by tests) ---
    def _pid_is_protected(self, pid) -> bool:
        # trusted-signed or critical system image -> never suspend
        if pid is None:
            return False
        try:
            import psutil
            p = psutil.Process(pid)
            name = (p.name() or "").lower()
            if name in {x.lower() for x in self.config["protected_images"]}:
                return True
            exe = p.exe()
            from Engine.Detection.cert_reputation import CertReputation
            return bool(exe and CertReputation().evaluate(exe).get("trusted"))
        except Exception:
            return False

    def _suspend_pid(self, pid) -> bool:
        try:
            import psutil
            psutil.Process(pid).suspend(); return True
        except Exception:
            return False

    def _classify_and_respond(self, trip_reasons: set, path: str, pid) -> str:
        high_conf = ("canary" in trip_reasons) or (len(trip_reasons) >= 2)
        action = self.config.get("action", "auto")
        if action == "alert_only":
            return "alert"
        want_suspend = (action == "always_suspend") or (action == "auto" and high_conf)
        if not want_suspend:
            return "alert"
        if pid is None:
            return "alert"
        if self._pid_is_protected(pid):
            return "alert_safeguarded"
        self._suspend_pid(pid)
        return "suspend"

    def _on_trip(self, trip_reasons: set, path: str, pid) -> None:
        self.emit_threat(ThreatCategory.RANSOMWARE, ThreatSeverity.CRITICAL,
                         "Ransomware behavior detected",
                         f"triggers={sorted(trip_reasons)} path={path}",
                         file_path=path, pid=pid, extra={"reasons": sorted(trip_reasons)})
        self._classify_and_respond(trip_reasons, path, pid)

    # --- individual detectors (each exception-isolated by the caller) ---
    def _detect_velocity(self, ts: float) -> bool:
        self._window.add(ts)
        threshold = self.config["velocity_threshold"]
        seconds = self.config["window_seconds"]
        return self._window.count(ts, seconds) > threshold

    def _detect_entropy(self, path: str) -> bool:
        try:
            sample_size = self.config["entropy_sample_bytes"]
            with open(path, "rb") as f:
                data = f.read(sample_size)
        except OSError:
            return False
        if not data:
            return False
        return shannon_entropy(data) >= self.config["entropy_threshold"]

    def _detect_canary(self, path: str) -> bool:
        return path in self._canaries

    def _detect_extension(self, path: str) -> bool:
        suffix = Path(path).suffix.lower()
        return suffix in {e.lower() for e in self.config["ransom_extensions"]}

    def _record_trip_reason(self, reason: str, ts: float) -> None:
        self._recent_trips.append((ts, reason))
        seconds = self.config["window_seconds"]
        cutoff = ts - seconds
        while self._recent_trips and self._recent_trips[0][0] < cutoff:
            self._recent_trips.popleft()

    def _correlated_reasons(self, now: float) -> set:
        seconds = self.config["window_seconds"]
        cutoff = now - seconds
        return {reason for (ts, reason) in self._recent_trips if ts > cutoff}

    # --- event handling: run all detectors on an incoming fs event ---
    def _handle_fs_event(self, path: str, kind: str) -> None:
        now = time.time()
        reasons: set = set()

        try:
            if self._detect_velocity(now):
                reasons.add("velocity")
        except Exception:
            pass

        try:
            if self._detect_canary(path):
                reasons.add("canary")
        except Exception:
            pass

        if kind in ("created", "moved"):
            try:
                if self._detect_extension(path):
                    reasons.add("extension")
            except Exception:
                pass

        if kind == "modified":
            try:
                if self._detect_entropy(path):
                    reasons.add("entropy")
            except Exception:
                pass

        if not reasons:
            return

        for reason in reasons:
            self._record_trip_reason(reason, now)

        # Correlate with any other reasons tripped by recent events in the
        # same window (e.g. an extension-rename followed shortly by an
        # entropy-spiking write on a different file) for the >=2-detector
        # high-confidence path.
        correlated = self._correlated_reasons(now) | reasons

        try:
            pid = self._pid_for_path(path)
        except Exception:
            pid = None

        try:
            self._on_trip(correlated, path, pid)
        except Exception:
            pass

    def _pid_for_path(self, path: str):
        """Best-effort lookup of the process currently holding path open.
        Never raises; returns None if unknown."""
        try:
            import psutil
            for proc in psutil.process_iter(["pid"]):
                try:
                    for f in proc.open_files():
                        if f.path == path:
                            return proc.pid
                except Exception:
                    continue
        except Exception:
            pass
        return None

    # --- canary seeding ---
    def _seed_canaries(self) -> None:
        count = self.config.get("canary_count", 0)
        for directory in self.config.get("watch_dirs", []):
            if not os.path.isdir(directory):
                continue
            for i in range(count):
                canary_path = os.path.join(directory, f".~sentinel_canary_{i}.tmp")
                try:
                    with open(canary_path, "wb") as f:
                        f.write(_CANARY_CONTENT)
                    try:
                        import subprocess
                        subprocess.run(["attrib", "+H", canary_path],
                                        capture_output=True,
                                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                    except Exception:
                        pass
                    self._canaries.add(canary_path)
                except OSError:
                    continue

    def _remove_canaries(self) -> None:
        for canary_path in list(self._canaries):
            try:
                if os.path.exists(canary_path):
                    os.remove(canary_path)
            except OSError:
                pass
        self._canaries.clear()

    # --- watchdog wiring ---
    def _run(self) -> None:
        self._seed_canaries()

        watch_dirs = [d for d in self.config.get("watch_dirs", []) if os.path.isdir(d)]
        if watch_dirs and Observer is not None:
            handler = _RansomEventHandler(self)
            self._observer = Observer()
            for directory in watch_dirs:
                self._observer.schedule(handler, path=directory, recursive=True)
            self._observer.start()

        self._heartbeat()
        while not self._stopping():
            self._heartbeat()
            if not self._sleep(1.0):
                break

    def _teardown(self) -> None:
        try:
            if self._observer:
                self._observer.stop(); self._observer.join(timeout=2)
        except Exception:
            pass
        try:
            self._remove_canaries()
        except Exception:
            pass
