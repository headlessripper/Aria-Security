# SentinelBrain.py
# Central nervous system for AriaSecurity.
#
# Every protection engine emits ThreatEvents here.
# The UI and any other subscriber listens to Brain signals.
# This gives the whole system a single source of truth for threat state.

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Dict, List, Optional, Any

from Main_Unit.Service.write_to_log import write_to_log


# ---------------------------------------------------------------------------
# Event taxonomy
# ---------------------------------------------------------------------------

class ThreatCategory(Enum):
    MALWARE     = auto()   # file scanner / hash match / ONNX
    RANSOMWARE  = auto()   # entropy spike / canary / mass-rename
    NETWORK     = auto()   # NetPro firewall block / blacklist hit
    EXPLOIT     = auto()   # DLL injection / suspicious process chain
    BEHAVIORAL  = auto()   # behavioral rules engine alert
    USB         = auto()   # USB auto-scan threat found
    SYSTEM      = auto()   # generic system-level alert (model update, feed refresh)


class ThreatSeverity(Enum):
    INFO     = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4


@dataclass
class ThreatEvent:
    category: ThreatCategory
    severity: ThreatSeverity
    title: str
    detail: str
    source_module: str              # e.g. "RansomProtection", "NetPro", "ExploitProtection"
    timestamp: float = field(default_factory=time.time)
    file_path: Optional[str] = None
    ip_address: Optional[str] = None
    pid: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "category":      self.category.name,
            "severity":      self.severity.name,
            "title":         self.title,
            "detail":        self.detail,
            "source_module": self.source_module,
            "timestamp":     self.timestamp,
            "file_path":     self.file_path,
            "ip_address":    self.ip_address,
            "pid":           self.pid,
            "extra":         self.extra,
        }


# ---------------------------------------------------------------------------
# Protection module status
# ---------------------------------------------------------------------------

@dataclass
class ModuleStatus:
    name: str
    running: bool = False
    last_event_ts: float = 0.0
    event_count: int = 0
    health_note: str = "OK"


# ---------------------------------------------------------------------------
# Pure-Python signal (replaces Qt Signal so the brain has no Qt dependency)
# ---------------------------------------------------------------------------

class _Signal:
    """Thread-safe callable list — same connect/emit interface as Qt Signal."""
    def __init__(self):
        self._cbs: List[Callable] = []
        self._lock = threading.Lock()

    def connect(self, fn: Callable) -> None:
        with self._lock:
            if fn not in self._cbs:
                self._cbs.append(fn)

    def disconnect(self, fn: Optional[Callable] = None) -> None:
        with self._lock:
            if fn is None:
                self._cbs.clear()
            else:
                self._cbs = [cb for cb in self._cbs if cb is not fn]

    def emit(self, *args) -> None:
        with self._lock:
            cbs = list(self._cbs)
        for cb in cbs:
            try:
                cb(*args)
            except Exception:
                pass


class _BrainSignals:
    """Signal carrier — same interface as the old Qt version."""
    def __init__(self):
        self.threat_detected          = _Signal()   # (ThreatEvent,)
        self.protection_level_changed = _Signal()   # (int,)
        self.module_status_changed    = _Signal()   # (str, bool)
        self.threat_log_cleared       = _Signal()   # ()
        self.status_line_changed      = _Signal()   # (str,)


# ---------------------------------------------------------------------------
# SentinelBrain
# ---------------------------------------------------------------------------

class SentinelBrain:
    """
    Singleton central event bus.

    Usage (from any engine):
        from Main_Unit.Engine.Service.SentinelBrain import get_brain, ThreatEvent, ThreatCategory, ThreatSeverity
        brain = get_brain()
        brain.emit_event(ThreatEvent(
            category=ThreatCategory.MALWARE,
            severity=ThreatSeverity.HIGH,
            title="Malware detected",
            detail=f"File: {path}",
            source_module="VirusScanner",
            file_path=path,
        ))

    Usage (from UI):
        brain = get_brain()
        brain.signals.threat_detected.connect(self.on_threat)
        brain.signals.protection_level_changed.connect(self.update_gauge)
    """

    _instance: Optional[SentinelBrain] = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self):
        self.signals = _BrainSignals()

        # Rolling threat log (last 1000 events)
        self._threat_log: deque[ThreatEvent] = deque(maxlen=1000)
        self._log_lock = threading.Lock()

        # Module registry
        self._modules: Dict[str, ModuleStatus] = {}
        self._module_lock = threading.Lock()

        # Counters per category
        self._category_counts: Dict[ThreatCategory, int] = {c: 0 for c in ThreatCategory}
        self._total_threats = 0
        self._blocked_count = 0

        # AVBrain override — when AVBrain is active it calls set_protection_level()
        # and _compute_protection_level() returns that value instead of the rule score.
        self._override_level: Optional[int] = None

        # Session start
        self._session_start = time.time()

    # ------------------------------------------------------------------
    # Singleton access
    # ------------------------------------------------------------------

    @classmethod
    def get(cls) -> SentinelBrain:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = SentinelBrain()
        return cls._instance

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    def emit_event(self, event: ThreatEvent) -> None:
        """
        Emit a threat event from any engine thread.
        Thread-safe. Queues to log, updates counters, emits Qt signal.
        """
        with self._log_lock:
            self._threat_log.append(event)
            self._category_counts[event.category] += 1
            if event.severity.value >= ThreatSeverity.MEDIUM.value:
                self._total_threats += 1

        # Update the emitting module's last-event timestamp
        with self._module_lock:
            mod = self._modules.get(event.source_module)
            if mod:
                mod.last_event_ts = event.timestamp
                mod.event_count += 1

        # Log to file
        write_to_log(
            f"[Brain][{event.category.name}][{event.severity.name}] "
            f"{event.source_module}: {event.title} — {event.detail}",
            "logs/SentinelBrain.log"
        )

        # Qt signal (safe from any thread because PySide6 queues cross-thread signals)
        self.signals.threat_detected.emit(event)

        # Recompute and emit protection level
        self.signals.protection_level_changed.emit(self._compute_protection_level())
        self.signals.status_line_changed.emit(self._build_status_line())

    def emit_block(self, ip: str, reason: str) -> None:
        """Convenience shortcut for network-block events."""
        self._blocked_count += 1
        self.emit_event(ThreatEvent(
            category=ThreatCategory.NETWORK,
            severity=ThreatSeverity.HIGH,
            title=f"IP blocked: {ip}",
            detail=reason,
            source_module="NetProtection",
            ip_address=ip,
        ))

    # ------------------------------------------------------------------
    # Module registry
    # ------------------------------------------------------------------

    def register_module(self, name: str) -> None:
        with self._module_lock:
            if name not in self._modules:
                self._modules[name] = ModuleStatus(name=name)

    def set_module_running(self, name: str, running: bool, health_note: str = "OK") -> None:
        with self._module_lock:
            if name not in self._modules:
                self._modules[name] = ModuleStatus(name=name)
            self._modules[name].running = running
            self._modules[name].health_note = health_note
        self.signals.module_status_changed.emit(name, running)
        self.signals.protection_level_changed.emit(self._compute_protection_level())
        self.signals.status_line_changed.emit(self._build_status_line())

    def get_module_statuses(self) -> List[ModuleStatus]:
        with self._module_lock:
            return list(self._modules.values())

    # ------------------------------------------------------------------
    # State queries
    # ------------------------------------------------------------------

    def get_recent_events(self, n: int = 50) -> List[ThreatEvent]:
        with self._log_lock:
            events = list(self._threat_log)
        return events[-n:]

    def get_events_by_category(self, category: ThreatCategory) -> List[ThreatEvent]:
        with self._log_lock:
            return [e for e in self._threat_log if e.category == category]

    def get_threat_counts(self) -> Dict[str, int]:
        with self._log_lock:
            return {c.name: v for c, v in self._category_counts.items()}

    def get_total_threats(self) -> int:
        return self._total_threats

    def get_blocked_count(self) -> int:
        return self._blocked_count

    def clear_threat_log(self) -> None:
        with self._log_lock:
            self._threat_log.clear()
            for k in self._category_counts:
                self._category_counts[k] = 0
            self._total_threats = 0
        self.signals.threat_log_cleared.emit()

    # ------------------------------------------------------------------
    # Protection level computation
    # ------------------------------------------------------------------

    def set_protection_level(self, level: int) -> None:
        """
        Called by AVBrain to push its computed protection level.
        Once AVBrain is active _compute_protection_level() returns
        this value so all existing callers transparently get the AI score.
        """
        self._override_level = max(0, min(100, int(level)))
        self.signals.protection_level_changed.emit(self._override_level)
        self.signals.status_line_changed.emit(self._build_status_line())

    def _compute_protection_level(self) -> int:
        """
        Returns 0–100 integer protection level.

        If AVBrain has called set_protection_level() its value is authoritative.
        Otherwise falls back to the built-in rule-based calculation:
          - module online ratio
          - penalty for recent HIGH/CRITICAL events in the last 60 s
        """
        # AVBrain override takes precedence
        if self._override_level is not None:
            return self._override_level

        with self._module_lock:
            modules = list(self._modules.values())

        if not modules:
            return 100

        active = sum(1 for m in modules if m.running)
        total  = len(modules)
        level  = int((active / total) * 100)

        cutoff = time.time() - 60
        with self._log_lock:
            recent_severe = sum(
                1 for e in self._threat_log
                if e.timestamp >= cutoff
                and e.severity.value >= ThreatSeverity.HIGH.value
            )

        level = max(0, level - min(30, recent_severe * 5))
        return level

    def _build_status_line(self) -> str:
        level = self._compute_protection_level()
        with self._module_lock:
            active = sum(1 for m in self._modules.values() if m.running)
            total  = len(self._modules)
        return (
            f"Protection {level}% | "
            f"Modules {active}/{total} | "
            f"Threats {self._total_threats} | "
            f"Blocked {self._blocked_count}"
        )


# ---------------------------------------------------------------------------
# Module-level singleton accessor
# ---------------------------------------------------------------------------

def get_brain() -> SentinelBrain:
    return SentinelBrain.get()
