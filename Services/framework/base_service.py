from __future__ import annotations
import threading, time, traceback
from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import Optional

try:
    from Services.SentinelBrain import get_brain, ThreatEvent
except Exception:  # keep importable in isolation
    get_brain = None
    ThreatEvent = None

class ServiceState(Enum):
    STOPPED = auto(); STARTING = auto(); RUNNING = auto(); STOPPING = auto(); ERROR = auto()

class BaseService(ABC):
    """Uniform lifecycle + Brain integration for every protection service."""
    name: str = "BaseService"

    def __init__(self, config: Optional[dict] = None, brain=None):
        self.config = config or {}
        self._brain = brain if brain is not None else (get_brain() if get_brain else None)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._state = ServiceState.STOPPED
        self._last_heartbeat = 0.0
        self._error: Optional[str] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._error = None
        self._state = ServiceState.STARTING
        self._thread = threading.Thread(target=self._guarded_run, daemon=True, name=self.name)
        self._thread.start()
        self._state = ServiceState.RUNNING
        self._set_module_running(True)

    def stop(self, timeout: float = 5.0) -> None:
        self._state = ServiceState.STOPPING
        self._stop_event.set()
        try:
            self._teardown()
        except Exception as e:
            self._log(f"teardown error: {e}", "ERROR")
        if self._thread:
            self._thread.join(timeout=timeout)
        self._state = ServiceState.STOPPED
        self._set_module_running(False)

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive()) and self._state == ServiceState.RUNNING

    def health(self) -> dict:
        return {"name": self.name, "state": self._state.name,
                "last_heartbeat": self._last_heartbeat, "error": self._error}

    @abstractmethod
    def _run(self) -> None: ...

    def _teardown(self) -> None:
        pass

    def _guarded_run(self) -> None:
        try:
            self._run()
        except Exception as e:
            self._error = f"{e}\n{traceback.format_exc()}"
            self._state = ServiceState.ERROR
            self._log(f"_run crashed: {e}", "ERROR")

    def _stopping(self) -> bool:
        return self._stop_event.is_set()

    def _sleep(self, seconds: float) -> bool:
        return not self._stop_event.wait(seconds)  # False if stopped during the wait

    def _heartbeat(self) -> None:
        self._last_heartbeat = time.time()

    def emit_threat(self, category, severity, title: str, detail: str,
                    file_path=None, pid=None, ip_address=None, extra=None) -> None:
        self._heartbeat()
        if not self._brain or ThreatEvent is None:
            return
        try:
            self._brain.emit_event(ThreatEvent(
                category=category, severity=severity, title=title, detail=detail,
                source_module=self.name, file_path=file_path, pid=pid,
                ip_address=ip_address, extra=extra or {}))
        except Exception as e:
            self._log(f"emit_threat failed: {e}", "ERROR")

    def emit_block(self, ip: str, reason: str) -> None:
        if self._brain:
            try: self._brain.emit_block(ip, reason)
            except Exception: pass

    def _set_module_running(self, running: bool) -> None:
        if self._brain:
            try: self._brain.set_module_running(self.name, running)
            except Exception: pass

    def _log(self, msg: str, level: str = "INFO") -> None:
        print(f"[{self.name}] {level}: {msg}")
