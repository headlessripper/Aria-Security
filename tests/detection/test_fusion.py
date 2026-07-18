from Engine.Detection.fusion import fuse

def test_whitelist_wins_over_everything():
    r = fuse({"whitelisted": True, "hash_exact": True, "ml_prob": 0.99})
    assert r["verdict"] == "CLEAN" and r["confidence"] == 100

def test_exact_hash_definitive():
    r = fuse({"hash_exact": True, "ml_prob": 0.1})
    assert r["verdict"] == "MALWARE" and r["confidence"] == 100

def test_fuzzy_match():
    r = fuse({"fuzzy": {"matched": True, "source": "imphash:abc"}})
    assert r["verdict"] == "MALWARE" and r["confidence"] == 90

def test_yara_hit():
    r = fuse({"yara": ["Win32_Trojan_X"]})
    assert r["verdict"] == "MALWARE"

def test_abused_signer():
    r = fuse({"cert": {"abused": True, "trusted": True}})
    assert r["verdict"] == "MALWARE" and r["confidence"] == 95

def test_ml_high_untrusted_is_malware():
    r = fuse({"ml_prob": 0.95, "cert": {"trusted": False}})
    assert r["verdict"] == "MALWARE"

def test_ml_high_trusted_downgraded():
    r = fuse({"ml_prob": 0.95, "cert": {"trusted": True}})
    assert r["verdict"] == "SUSPICIOUS"

def test_ml_medium_suspicious():
    r = fuse({"ml_prob": 0.6})
    assert r["verdict"] == "SUSPICIOUS"

def test_nothing_fires_clean():
    r = fuse({"ml_prob": 0.1, "cert": {"trusted": True}})
    assert r["verdict"] == "CLEAN"
