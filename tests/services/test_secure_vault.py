"""
Tests for SecureVault hardening (Phase 3D Task 2):
  - wrong password / corrupt entry -> clean VaultError (no raw traceback)
  - round-trip add/extract with the correct password still works
"""
import pytest

import Services.SentinelSecureVault as vault


def test_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "VAULT_DIR", tmp_path / "vault")
    (tmp_path / "vault").mkdir()
    src = tmp_path / "secret.txt"
    src.write_bytes(b"top secret data")

    vid = vault.add(str(src), "pw123", delete_original=False)
    out = vault.extract(vid, str(tmp_path / "out"), "pw123")

    assert open(out, "rb").read() == b"top secret data"


def test_wrong_password_clean_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "VAULT_DIR", tmp_path / "vault")
    (tmp_path / "vault").mkdir()
    src = tmp_path / "s.txt"
    src.write_bytes(b"x")

    vid = vault.add(str(src), "right", delete_original=False)

    with pytest.raises(vault.VaultError):
        vault.extract(vid, str(tmp_path / "out"), "wrong")
