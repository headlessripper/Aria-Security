import pytest

class FakeBrain:
    def __init__(self):
        self.events = []
        self.blocks = []
        self.module_states = {}
    def emit_event(self, evt): self.events.append(evt)
    def emit_block(self, ip, reason): self.blocks.append((ip, reason))
    def set_module_running(self, name, running, health_note="OK"): self.module_states[name] = running

@pytest.fixture
def fake_brain():
    return FakeBrain()
