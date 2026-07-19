from Services.SentinelThreatIntelligence import parse_ip_list, parse_hashes

def test_parse_ip_list():
    text = "# comment\n; also comment\n1.2.3.4\n5.6.7.8 , foo\nnot-an-ip\n\n10.0.0.1\n"
    ips = parse_ip_list(text)
    assert ips == {"1.2.3.4", "5.6.7.8", "10.0.0.1"}

def test_parse_hashes_regex_fallback():
    text = ("sha256: " + "a" * 64 + "\nmd5: " + "b" * 32 + "\ngarbage\n")
    sha, md5 = parse_hashes(text)
    assert ("a" * 64) in sha and ("b" * 32) in md5

def test_parse_hashes_bytes_ok():
    sha, md5 = parse_hashes(("c" * 64).encode())
    assert ("c" * 64) in sha
