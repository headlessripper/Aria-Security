import json
from Services.SentinelBehavioralEngine import load_rules, event_matches, RuleState

def test_event_matches_ops():
    rule = {"event": "process_start",
            "conditions": [{"field": "image", "op": "contains", "value": "powershell"},
                           {"field": "cmdline", "op": "regex", "value": "-enc"}]}
    assert event_matches(rule, {"type": "process_start", "image": "powershell.exe", "cmdline": "ps -enc x"}) is True
    assert event_matches(rule, {"type": "process_start", "image": "cmd.exe", "cmdline": "-enc"}) is False
    assert event_matches(rule, {"type": "file_write", "image": "powershell.exe", "cmdline": "-enc"}) is False  # wrong event type

def test_windowed_threshold_fires_once(fake_brain):
    rule = {"id": "R", "event": "net_connect", "threshold": 3, "window_seconds": 10,
            "conditions": [{"field": "remote_ip", "op": "startswith", "value": "185."}]}
    st = RuleState(rule)
    ev = {"type": "net_connect", "remote_ip": "185.1.1.1"}
    assert st.feed(rule, ev, now=0) is False
    assert st.feed(rule, ev, now=1) is False
    assert st.feed(rule, ev, now=2) is True     # 3rd within window -> fire
    assert st.feed(rule, ev, now=3) is False    # already fired for this burst

def test_single_event_rule_fires_immediately():
    rule = {"id": "S", "event": "process_start", "threshold": 1, "window_seconds": None,
            "conditions": [{"field": "image", "op": "eq", "value": "mimikatz.exe"}]}
    st = RuleState(rule)
    assert st.feed(rule, {"type": "process_start", "image": "mimikatz.exe"}, now=0) is True

def test_load_rules_skips_malformed(tmp_path):
    p = tmp_path / "rules.json"
    p.write_text(json.dumps({"rules": [
        {"id": "ok", "event": "process_start", "conditions": []},
        {"id": "bad"},                        # missing 'event' -> skipped
        "not a dict",                          # skipped
    ]}))
    rules = load_rules(str(p))
    assert [r["id"] for r in rules] == ["ok"]
