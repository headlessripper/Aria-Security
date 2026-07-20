from Services.SentinelScheduler import due_schedules, Scheduler


def test_due_schedules_fires_when_next_run_passed():
    now = 1000.0
    scheds = [
        {"id": "a", "enabled": True,  "next_run": 900.0},   # due
        {"id": "b", "enabled": True,  "next_run": 1100.0},  # future
        {"id": "c", "enabled": False, "next_run": 800.0},   # disabled
    ]
    due = due_schedules(scheds, now)
    assert [s["id"] for s in due] == ["a"]


def test_due_schedules_missing_fields_safe():
    assert due_schedules([{"id": "x"}], 1000.0) == []   # no next_run -> not due, no crash


def test_scheduler_lifecycle(fake_brain):
    s = Scheduler(brain=fake_brain, on_scan_due=lambda sid, path: None)
    s.start(); assert s.is_running() is True
    s.stop();  assert s.is_running() is False
