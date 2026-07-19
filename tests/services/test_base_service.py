import time
from Services.framework.base_service import BaseService
from Services.SentinelBrain import ThreatCategory, ThreatSeverity

class _Echo(BaseService):
    name = "EchoSvc"
    def _run(self):
        while not self._stopping():
            if not self._sleep(0.05):
                break

class _Crash(BaseService):
    name = "CrashSvc"
    def _run(self):
        raise RuntimeError("boom")

def test_lifecycle_and_brain_registration(fake_brain):
    s = _Echo(brain=fake_brain)
    assert s.is_running() is False
    s.start()
    assert s.is_running() is True
    assert fake_brain.module_states["EchoSvc"] is True
    s.stop()
    assert s.is_running() is False
    assert fake_brain.module_states["EchoSvc"] is False
    assert s.health()["state"] == "STOPPED"

def test_stop_is_prompt(fake_brain):
    s = _Echo(brain=fake_brain)
    s.start()
    t0 = time.time()
    s.stop(timeout=2)
    assert time.time() - t0 < 1.5  # cooperative stop, not the full timeout

def test_idempotent_start(fake_brain):
    s = _Echo(brain=fake_brain)
    s.start(); first = s._thread
    s.start(); assert s._thread is first  # no second thread
    s.stop()

def test_emit_threat_builds_event(fake_brain):
    s = _Echo(brain=fake_brain)
    s.emit_threat(ThreatCategory.RANSOMWARE, ThreatSeverity.CRITICAL, "Title", "detail",
                  file_path="C:/x", pid=42, extra={"k": "v"})
    assert len(fake_brain.events) == 1
    e = fake_brain.events[0]
    assert e.category == ThreatCategory.RANSOMWARE and e.severity == ThreatSeverity.CRITICAL
    assert e.source_module == "EchoSvc" and e.pid == 42 and e.extra == {"k": "v"}

def test_run_crash_sets_error_not_process(fake_brain):
    s = _Crash(brain=fake_brain)
    s.start()
    time.sleep(0.15)
    assert s.health()["state"] == "ERROR"   # crashed internally, process still alive
    s.stop()
