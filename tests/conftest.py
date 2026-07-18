import os
import pytest

@pytest.fixture(scope="session")
def benign_pe():
    """A real, Microsoft-signed Windows PE for extractor/cert/fuzzy tests."""
    for cand in (r"C:\Windows\System32\notepad.exe",
                 r"C:\Windows\System32\calc.exe",
                 r"C:\Windows\System32\cmd.exe"):
        if os.path.exists(cand):
            return cand
    pytest.skip("no system PE available")

@pytest.fixture(scope="session")
def benign_pe_bytes(benign_pe):
    with open(benign_pe, "rb") as f:
        return f.read()
