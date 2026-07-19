from Services.Protection.SentinelNetProtectionNG2 import classify_connection, is_private_or_local
from Services.Protection.threat_intel_store import ThreatIntelStore
from Services.SentinelBrain import ThreatSeverity

CFG = {"whitelist": set(), "rep_block_threshold": 80, "rep_alert_threshold": 50,
       "suspicious_ports": {4444, 1337}}

def test_private_and_loopback_skipped():
    assert is_private_or_local("192.168.1.5") and is_private_or_local("127.0.0.1")
    assert is_private_or_local("8.8.8.8") is False
    intel = ThreatIntelStore()
    action, _, _ = classify_connection({"raddr_ip": "10.0.0.9", "raddr_port": 443}, intel, CFG)
    assert action == "clean"

def test_ioc_match_blocks():
    intel = ThreatIntelStore(); intel.add_bad_ips({"185.220.1.1"}, "feodo")
    action, reason, sev = classify_connection({"raddr_ip": "185.220.1.1", "raddr_port": 443}, intel, CFG)
    assert action == "block" and sev == ThreatSeverity.HIGH

def test_high_reputation_blocks():
    intel = ThreatIntelStore(); intel.set_reputation("9.9.9.9", 90)
    action, _, sev = classify_connection({"raddr_ip": "9.9.9.9", "raddr_port": 443}, intel, CFG)
    assert action == "block"

def test_mid_reputation_alerts():
    intel = ThreatIntelStore(); intel.set_reputation("9.9.9.8", 60)
    action, _, sev = classify_connection({"raddr_ip": "9.9.9.8", "raddr_port": 443}, intel, CFG)
    assert action == "alert" and sev == ThreatSeverity.MEDIUM

def test_suspicious_port_alerts():
    intel = ThreatIntelStore()
    action, reason, _ = classify_connection({"raddr_ip": "9.9.9.7", "raddr_port": 4444}, intel, CFG)
    assert action == "alert" and "port" in reason.lower()

def test_whitelisted_ip_clean():
    intel = ThreatIntelStore(); intel.add_bad_ips({"9.9.9.6"}, "x")
    cfg = dict(CFG); cfg["whitelist"] = {"9.9.9.6"}
    action, _, _ = classify_connection({"raddr_ip": "9.9.9.6", "raddr_port": 4444}, intel, cfg)
    assert action == "clean"

def test_benign_public_clean():
    intel = ThreatIntelStore()
    action, _, _ = classify_connection({"raddr_ip": "8.8.8.8", "raddr_port": 443}, intel, CFG)
    assert action == "clean"
