from pathlib import Path


def test_mind_does_not_claim_isolationforest():
    txt = Path("Argus/mind.md").read_text(encoding="utf-8").lower()
    assert "isolationforest" not in txt and "isolation forest" not in txt
    assert "if_anomaly_score" not in txt


def test_mind_lists_real_protection_level_inputs():
    txt = Path("Argus/mind.md").read_text(encoding="utf-8").lower()
    assert "module" in txt and "threat" in txt and "llm" in txt


def test_mind_lists_new_tools():
    txt = Path("Argus/mind.md").read_text(encoding="utf-8")
    for tool in ("scan_file", "lookup_ip", "lookup_hash", "block_ip"):
        assert tool in txt
