import os, glob
import yara

RULES_DIR = "Engine/Rules/curated"
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def _compile():
    files = {os.path.splitext(os.path.basename(f))[0]: f
             for f in glob.glob(os.path.join(RULES_DIR, "*.yar"))}
    return yara.compile(filepaths=files)

def test_ruleset_compiles():
    rules = _compile()
    assert rules is not None

def test_eicar_matches():
    rules = _compile()
    matches = rules.match(data=EICAR.encode())
    assert any("EICAR" in m.rule.upper() for m in matches)
