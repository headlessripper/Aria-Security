from Services.Protection.SentinelRansomProtection import RansomProtection
from Services.Protection.SentinelExploitProtection import ExploitProtection
from Services.SentinelBehavioralEngine import BehavioralEngine


def test_services_start_stop_uniformly(fake_brain, tmp_path):
    svcs = [RansomProtection(config={"watch_dirs": [str(tmp_path)]}, brain=fake_brain),
            ExploitProtection(config={"poll_interval": 0.1}, brain=fake_brain),
            BehavioralEngine(config={"poll_interval": 0.1}, brain=fake_brain)]
    for s in svcs:
        s.start()
    assert all(s.is_running() for s in svcs)
    for s in svcs:
        s.stop()
    assert not any(s.is_running() for s in svcs)
