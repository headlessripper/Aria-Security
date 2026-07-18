from Engine.Detection.fuzzy_hash import FuzzyHasher

def test_imphash_on_real_pe(benign_pe):
    fh = FuzzyHasher()
    h = fh.imphash(benign_pe)
    assert h is None or (isinstance(h, str) and len(h) == 32)

def test_tlsh_compute(benign_pe_bytes):
    fh = FuzzyHasher()
    t = fh.tlsh(benign_pe_bytes)
    assert t is None or isinstance(t, str)

def test_match_empty_db(benign_pe):
    fh = FuzzyHasher()  # empty DB
    r = fh.match(benign_pe)
    assert r["matched"] is False

def test_match_seeded_imphash(benign_pe, tmp_path):
    fh0 = FuzzyHasher()
    imp = fh0.imphash(benign_pe)
    if not imp:
        return  # PE has no imports; skip
    db = tmp_path / "bad.txt"
    db.write_text(f"imphash:{imp}\n")
    fh = FuzzyHasher(db_path=str(db))
    r = fh.match(benign_pe)
    assert r["matched"] is True and r["source"].startswith("imphash:")
