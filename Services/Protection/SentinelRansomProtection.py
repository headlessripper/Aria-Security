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
    # Naturally high-entropy formats: skip the entropy detector to avoid FPs.
    "skip_entropy_extensions": [
        ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mkv", ".avi", ".mov",
        ".mp3", ".zip", ".7z", ".rar", ".gz", ".docx", ".xlsx", ".pptx", ".pdf",
    ],
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
        self._service._handle_fs_event("created", event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._service._handle_fs_event("modified", event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        # Feed BOTH the original and the new path: a rename-to-encrypt
        # (canary -> canary.locked) must be seen at the ORIGINAL path (canary
        # trip) AND at the destination (extension trip).
        self._service._handle_fs_event("moved", event.src_path, event.dest_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        # A deleted canary (or wiper/mass-delete behaviour) must not be
        # invisible: route the removed path through detection too.
        self._service._handle_fs_event("deleted", event.src_path)


class RansomProtection(BaseService):
    name = "RansomProtection"

    def __init__(self, config=None, brain=None):
        cfg = dict(_DEFAULTS); cfg.update(config or {})
        super().__init__(cfg, brain)
        self._window = _Window()
        # (ts, path, reason) for per-FILE multi-detector correlation.
        self._recent_trips: deque = deque()
        self._canaries: set[str] = set()
        self._observer = None
        # Guards the shared mutable detector state (_window, _recent_trips,
        # _canaries) against watchdog's multiple emitter threads. This is a
        # dedicated lock, NOT BaseService._lock (which guards start/stop).
        self._state_lock = threading.Lock()

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
        suffix = Path(path).suffix.lower()
        if suffix in {e.lower() for e in self.config.get("skip_entropy_extensions", [])}:
            return False  # naturally high-entropy format -> not a signal
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

    def _record_trip_reason(self, path: str, reason: str, ts: float) -> None:
        self._recent_trips.append((ts, path, reason))
        seconds = self.config["window_seconds"]
        cutoff = ts - seconds
        while self._recent_trips and self._recent_trips[0][0] < cutoff:
            self._recent_trips.popleft()

    def _correlated_reasons(self, path: str, now: float) -> set:
        # Per-FILE correlation: only reasons tripped for the SAME path within
        # the window combine. This stops two unrelated single-detector trips on
        # DIFFERENT files from faking a >=2-detector high-confidence suspend.
        seconds = self.config["window_seconds"]
        cutoff = now - seconds
        return {reason for (ts, p, reason) in self._recent_trips
                if p == path and ts > cutoff}

    def _evaluate_path(self, path: str, now: float, velocity: bool,
                       check_extension: bool, check_entropy: bool) -> set:
        """Run the per-file detectors for `path`, record/correlate reasons, and
        return the correlated reason-set for THIS path (empty if nothing tripped
        on it). Must be called while holding `self._state_lock`."""
        reasons: set = set()
        if velocity:
            reasons.add("velocity")

        try:
            if self._detect_canary(path):
                reasons.add("canary")
        except Exception:
            pass

        if check_extension:
            try:
                if self._detect_extension(path):
                    reasons.add("extension")
            except Exception:
                pass

        if check_entropy:
            try:
                if self._detect_entropy(path):
                    reasons.add("entropy")
            except Exception:
                pass

        if not reasons:
            return set()

        for reason in reasons:
            self._record_trip_reason(path, reason, now)
        return self._correlated_reasons(path, now)

    # --- event handling: run all detectors on an incoming fs event ---
    def _handle_fs_event(self, kind: str, src_path: str, dest_path: str = None) -> None:
        now = time.time()
        to_trip: list = []  # (correlated_reasons, path) computed under the lock

        # Hold the state lock while touching _window / _recent_trips / _canaries;
        # release it before the (potentially slow) _on_trip / suspend work.
        with self._state_lock:
            # Velocity is a single global signal: count each fs event exactly
            # once (including a move), attributed to this event's primary path.
            velocity_tripped = False
            try:
                if self._detect_velocity(now):
                    velocity_tripped = True
            except Exception:
                pass

            # For moves the destination is the "new" file (extension/entropy),
            # for everything else the primary path is src_path.
            primary = dest_path if (kind == "moved" and dest_path) else src_path

            if primary:
                correlated = self._evaluate_path(
                    primary, now,
                    velocity=velocity_tripped,
                    check_extension=kind in ("created", "moved"),
                    check_entropy=(kind == "modified"),
                )
                if correlated:
                    to_trip.append((correlated, primary))

            # A canary being moved/renamed/deleted AWAY from its seeded path is a
            # canary trip: check the ORIGINAL path on moves/deletes too.
            if kind == "moved" and src_path and src_path != primary:
                correlated = self._evaluate_path(
                    src_path, now,
                    velocity=False, check_extension=False, check_entropy=False,
                )
                if correlated:
                    to_trip.append((correlated, src_path))

        for correlated, path in to_trip:
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
                    with self._state_lock:
                        self._canaries.add(canary_path)
                except OSError:
                    continue

    def _remove_canaries(self) -> None:
        with self._state_lock:
            paths = list(self._canaries)
        for canary_path in paths:
            try:
                if os.path.exists(canary_path):
                    os.remove(canary_path)
            except OSError:
                pass
        with self._state_lock:
            self._canaries.clear()

    # --- watchdog wiring ---
    def _run(self) -> None:
        self._seed_canaries()

        watch_dirs = [d for d in self.config.get("watch_dirs", []) if os.path.isdir(d)]
        if watch_dirs and Observer is not None:
            handler = _RansomEventHandler(self)
            self._observer = Observer()
            scheduled = 0
            for directory in watch_dirs:
                # Isolate each watch: one bad/inaccessible directory must not
                # crash _run and permanently ERROR the whole service.
                try:
                    self._observer.schedule(handler, path=directory, recursive=True)
                    scheduled += 1
                except Exception as e:
                    self._log(f"failed to watch {directory}: {e}", "ERROR")
            if scheduled:
                try:
                    self._observer.start()
                except Exception as e:
                    self._log(f"observer start failed: {e}", "ERROR")
                    self._observer = None
            else:
                self._observer = None

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
