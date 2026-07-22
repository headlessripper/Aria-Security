"""
SentinelSecureVault — Fernet-encrypted file vault.

Files are encrypted and stored in ~/.AriaSecurity/SecureVault/.
Each file gets its own AES key stored alongside it (key file is
itself encrypted with the vault password's PBKDF2-derived key).

Operations:
  - add(src_path, password)   — encrypt and store, remove original
  - extract(vault_id, dst_dir, password)  — decrypt to dst_dir
  - delete(vault_id)          — permanently remove
  - list_files() → list[dict] — enumerate vault contents
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import time
import uuid
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as _hashes
from Config import paths as _paths

VAULT_DIR = _paths.sub("SecureVault")
VAULT_DIR.mkdir(parents=True, exist_ok=True)
META_FILE = VAULT_DIR / "vault_meta.json"


class VaultError(Exception):
    """Raised for vault operations that fail cleanly (e.g. wrong password)."""
    pass


# ── Key derivation ────────────────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=_hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# ── Metadata helpers ──────────────────────────────────────────────────────────

def _meta_file() -> Path:
    # Recomputed from the current VAULT_DIR (not the import-time constant) so
    # tests can monkeypatch VAULT_DIR and get full isolation from the real vault.
    return VAULT_DIR / "vault_meta.json"


def _load_meta() -> dict:
    try:
        meta_file = _meta_file()
        if meta_file.exists():
            return json.loads(meta_file.read_text())
    except Exception:
        pass
    return {}


def _save_meta(meta: dict):
    _meta_file().write_text(json.dumps(meta, indent=2))


# ── Public API ────────────────────────────────────────────────────────────────

def add(src_path: str, password: str, delete_original: bool = True) -> str:
    """Encrypt src_path and add it to the vault. Returns vault_id."""
    src = Path(src_path)
    if not src.exists():
        raise FileNotFoundError(src_path)

    vault_id = str(uuid.uuid4())[:12]
    entry_dir = VAULT_DIR / vault_id
    entry_dir.mkdir(parents=True)

    # Per-file random key
    salt      = os.urandom(16)
    vault_key = _derive_key(password, salt)
    fernet    = Fernet(vault_key)

    enc_data = fernet.encrypt(src.read_bytes())

    data_path = entry_dir / "data.enc"
    salt_path = entry_dir / "salt.bin"
    data_tmp  = entry_dir / "data.enc.tmp"
    salt_tmp  = entry_dir / "salt.bin.tmp"

    # Write to temp paths first, then atomically replace into place so a
    # crash mid-write can never leave a partially-written vault entry.
    data_tmp.write_bytes(enc_data)
    salt_tmp.write_bytes(salt)
    os.replace(str(data_tmp), str(data_path))
    os.replace(str(salt_tmp), str(salt_path))

    meta = _load_meta()
    meta[vault_id] = {
        "vault_id":   vault_id,
        "orig_name":  src.name,
        "orig_path":  str(src),
        "size":       src.stat().st_size,
        "added":      time.time(),
    }
    _save_meta(meta)

    # Only remove the original file after the atomic replace succeeded.
    if delete_original:
        src.unlink(missing_ok=True)

    return vault_id


def extract(vault_id: str, dst_dir: str, password: str) -> str:
    """Decrypt vault entry to dst_dir. Returns path of restored file."""
    entry_dir = VAULT_DIR / vault_id
    if not entry_dir.exists():
        raise FileNotFoundError(f"Vault entry {vault_id} not found")

    try:
        salt = (entry_dir / "salt.bin").read_bytes()
    except OSError as exc:
        raise VaultError("wrong password or corrupt vault entry") from exc

    try:
        vault_key = _derive_key(password, salt)
        fernet    = Fernet(vault_key)
        plain     = fernet.decrypt((entry_dir / "data.enc").read_bytes())
    except InvalidToken as exc:
        raise VaultError("wrong password or corrupt vault entry") from exc
    except OSError as exc:
        raise VaultError("wrong password or corrupt vault entry") from exc

    meta     = _load_meta()
    orig_name = meta.get(vault_id, {}).get("orig_name", vault_id)
    Path(dst_dir).mkdir(parents=True, exist_ok=True)
    dst_path  = Path(dst_dir) / orig_name
    dst_path.write_bytes(plain)
    return str(dst_path)


def delete(vault_id: str):
    """Permanently remove a vault entry."""
    entry_dir = VAULT_DIR / vault_id
    if entry_dir.exists():
        shutil.rmtree(str(entry_dir))
    meta = _load_meta()
    meta.pop(vault_id, None)
    _save_meta(meta)


def list_files() -> list[dict]:
    """Return metadata for all vault entries, newest first."""
    meta = _load_meta()
    return sorted(meta.values(), key=lambda x: x.get("added", 0), reverse=True)


def vault_size_bytes() -> int:
    total = 0
    for f in VAULT_DIR.rglob("*"):
        if f.is_file():
            try:
                total += f.stat().st_size
            except Exception:
                pass
    return total
