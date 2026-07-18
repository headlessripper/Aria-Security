from Engine.Compiler.SentinelCompiler_v5 import VirusScanner


def test_scanner_initializes_all_layers():
    vs = VirusScanner(max_workers=2)
    assert vs.ml_scanner is not None
    assert vs.fuzzy is not None
    assert vs.cert is not None


def test_scan_benign_system_pe(benign_pe):
    vs = VirusScanner(max_workers=2)
    r = vs.scan_file(benign_pe)
    assert r["verdict"] in ("CLEAN", "SUSPICIOUS", "MALWARE", "WHITELISTED", "IGNORED")
    # a Microsoft-signed system exe must not be a definitive MALWARE by hash/fuzzy
    assert "Known-bad hash" not in r["reasons"]
