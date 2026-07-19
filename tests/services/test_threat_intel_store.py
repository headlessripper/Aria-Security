import time
from Services.Protection.threat_intel_store import ThreatIntelStore, get_intel_store

def test_bad_ip_add_and_query():
    s = ThreatIntelStore()
    s.add_bad_ips({"1.2.3.4", " 5.6.7.8 ", "", None}, source="feed")
    assert s.is_bad_ip("1.2.3.4") and s.is_bad_ip("5.6.7.8")
    assert s.is_bad_ip("9.9.9.9") is False

def test_bad_hash_case_insensitive():
    s = ThreatIntelStore()
    s.add_bad_hashes({"ABCDEF"}, source="x")
    assert s.is_bad_hash("abcdef") and s.is_bad_hash("ABCDEF")
    assert s.is_bad_hash("000000") is False

def test_reputation_ttl():
    s = ThreatIntelStore()
    s.set_reputation("1.1.1.1", 90, ttl_s=100)
    assert s.ip_reputation("1.1.1.1") == 90
    s.set_reputation("2.2.2.2", 40, ttl_s=-1)   # already expired
    assert s.ip_reputation("2.2.2.2") is None
    assert s.ip_reputation("3.3.3.3") is None

def test_singleton():
    assert get_intel_store() is get_intel_store()

def test_stats():
    s = ThreatIntelStore()
    s.add_bad_ips({"1.2.3.4"}, source="feodo")
    st = s.stats()
    assert st["bad_ips"] == 1 and "feodo" in st["sources"]
