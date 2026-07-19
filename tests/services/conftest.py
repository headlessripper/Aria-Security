import pytest

class FakeBrain:
    def __init__(self):
        self.events = []
        self.blocks = []
        self.module_states = {}
        self.threats = []
    def emit_event(self, evt):
        self.events.append(evt)
        self.threats.append({
            "category": getattr(evt, "category", None),
            "severity": getattr(evt, "severity", None),
            "title": getattr(evt, "title", None),
            "detail": getattr(evt, "detail", None),
            "file_path": getattr(evt, "file_path", None),
        })
    def emit_block(self, ip, reason): self.blocks.append((ip, reason))
    def set_module_running(self, name, running, health_note="OK"): self.module_states[name] = running

@pytest.fixture
def fake_brain():
    return FakeBrain()
