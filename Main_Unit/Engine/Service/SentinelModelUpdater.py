# SentinelModelUpdater.py
# Downloads, verifies, and hot-swaps detection models without restarting the app.
#
# Manifest format (hosted on GitHub releases or your own CDN):
# {
#   "models": [
#     {
#       "name": "Engine_General_ZS1.onnx",
#       "version": "1.3.0",
#       "sha256": "abc123...",
#       "url": "https://github.com/headlessripper/AriaSecurity/releases/download/v1.3.0/Engine_General_ZS1.onnx",
#       "type": "onnx",
#       "description": "General PE malware classifier"
#     },
#     { "name": "nids_model.pkl", ... }
#   ],
#   "hashes": {
#     "SHA256-Hashes.txt": { "version": "2026-05-01", "url": "...", "sha256": "..." }
#   }
# }

import os
import sys
import json
import hashlib
import threading
import time
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Dict, List, Callable
from datetime import datetime

import requests

from Main_Unit.Service.write_to_log import write_to_log
from Main_Unit.Config.Sys_Config import (
    OWNER, REPO, CURRENT_VERSION,
    DETECTION_MODEL_PATH
)

UPDATE_LOG = "logs/ModelUpdater.log"
UPDATE_CHECK_INTERVAL = 6 * 3600  # check every 6 hours

# Local version tracking file
VERSION_CACHE_FILE = Path.home() / ".AriaSecurity" / "model_versions.json"
VERSION_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

# Manifest URL — change to your CDN/GitHub endpoint
MANIFEST_URL = f"https://raw.githubusercontent.com/{OWNER}/{REPO}/main/models/manifest.json"

DOWNLOAD_TIMEOUT = 60  # seconds
CHUNK_SIZE = 65536


def _log(msg: str):
    write_to_log(msg, UPDATE_LOG)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_version_cache() -> Dict:
    try:
        if VERSION_CACHE_FILE.exists():
            with open(VERSION_CACHE_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_version_cache(cache: Dict):
    try:
        with open(VERSION_CACHE_FILE, 'w') as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        _log(f"Version cache save failed: {e}")


# ---------------------------------------------------------------------------
# Download helper
# ---------------------------------------------------------------------------

def _download_with_progress(
    url: str,
    dest_path: str,
    expected_sha256: Optional[str] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> bool:
    """
    Download url to dest_path. Verifies sha256 if provided.
    progress_cb(bytes_downloaded, total_bytes) called during download.
    Returns True on success.
    """
    tmp_path = dest_path + ".tmp"
    try:
        response = requests.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT)
        response.raise_for_status()

        total = int(response.headers.get('content-length', 0))
        downloaded = 0

        with open(tmp_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_cb:
                        progress_cb(downloaded, total)

        if expected_sha256:
            actual = _sha256_file(tmp_path)
            if actual.lower() != expected_sha256.lower():
                _log(f"SHA256 mismatch: expected {expected_sha256}, got {actual}")
                os.remove(tmp_path)
                return False

        # Atomic replace
        shutil.move(tmp_path, dest_path)
        return True

    except Exception as e:
        _log(f"Download failed ({url}): {e}")
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        return False


# ---------------------------------------------------------------------------
# Model hot-swap registry
# — modules register their reload callbacks here
# ---------------------------------------------------------------------------

class _HotSwapRegistry:
    def __init__(self):
        self._callbacks: Dict[str, List[Callable]] = {}
        self._lock = threading.Lock()

    def register(self, model_name: str, callback: Callable):
        """Register a callback to be called when model_name is updated."""
        with self._lock:
            self._callbacks.setdefault(model_name, []).append(callback)

    def notify(self, model_name: str, new_path: str):
        """Notify all registered listeners that model_name has been updated."""
        with self._lock:
            callbacks = list(self._callbacks.get(model_name, []))
        for cb in callbacks:
            try:
                cb(new_path)
            except Exception as e:
                _log(f"Hot-swap callback error for {model_name}: {e}")


HOT_SWAP = _HotSwapRegistry()


# ---------------------------------------------------------------------------
# Main updater
# ---------------------------------------------------------------------------

class SentinelModelUpdater:
    """
    Checks for and applies model updates.

    Usage:
        updater = SentinelModelUpdater()
        updater.start_background_checker()   # auto-check every 6h

        # Or manually:
        updater.check_and_update()
    """

    def __init__(self, manifest_url: str = MANIFEST_URL):
        self.manifest_url = manifest_url
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._version_cache = _load_version_cache()

    # ------------------------------------------------------------------
    # Background auto-checker
    # ------------------------------------------------------------------

    def start_background_checker(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._checker_loop, daemon=True, name="SentinelModelUpdater"
        )
        self._thread.start()
        _log("Model updater background checker started")

    def stop(self):
        self._running = False

    def _checker_loop(self):
        # Initial check after 30s (let app fully start)
        time.sleep(30)
        while self._running:
            try:
                self.check_and_update()
            except Exception as e:
                _log(f"Auto-update check failed: {e}")
            # Sleep in small increments so stop() is responsive
            elapsed = 0
            while elapsed < UPDATE_CHECK_INTERVAL and self._running:
                time.sleep(30)
                elapsed += 30

    # ------------------------------------------------------------------
    # Core update logic
    # ------------------------------------------------------------------

    def fetch_manifest(self) -> Optional[Dict]:
        try:
            resp = requests.get(self.manifest_url, timeout=15)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            _log(f"Manifest fetch failed: {e}")
            return None

    def check_and_update(self) -> List[str]:
        """
        Check manifest and download any outdated models.
        Returns list of model names that were updated.
        """
        _log("Checking for model updates...")
        manifest = self.fetch_manifest()
        if not manifest:
            _log("No manifest available — skipping update check")
            return []

        updated = []

        # Update ONNX / pkl models
        for entry in manifest.get("models", []):
            name = entry.get("name", "")
            version = entry.get("version", "")
            url = entry.get("url", "")
            expected_sha256 = entry.get("sha256", "")
            model_type = entry.get("type", "")

            if not name or not url:
                continue

            cached_version = self._version_cache.get(name, {}).get("version", "")

            if cached_version == version:
                _log(f"  {name}: up-to-date (v{version})")
                continue

            _log(f"  {name}: updating {cached_version or 'none'} -> {version}")
            dest = self._resolve_model_path(name, model_type)
            if not dest:
                _log(f"  {name}: cannot resolve destination path — skipping")
                continue

            # Backup current model
            backup_path = dest + f".bak_{int(time.time())}"
            if os.path.exists(dest):
                shutil.copy2(dest, backup_path)

            success = _download_with_progress(
                url, dest, expected_sha256,
                progress_cb=lambda d, t: _log(
                    f"    {name}: {d//1024}KB / {(t or 0)//1024}KB"
                ) if t and d % (CHUNK_SIZE * 8) == 0 else None,
            )

            if success:
                _log(f"  ✅ {name} updated to v{version}")
                self._version_cache[name] = {
                    "version": version,
                    "updated": datetime.now().isoformat(),
                }
                _save_version_cache(self._version_cache)
                HOT_SWAP.notify(name, dest)
                updated.append(name)
                # Remove backup on success
                if os.path.exists(backup_path):
                    try:
                        os.remove(backup_path)
                    except Exception:
                        pass
            else:
                _log(f"  ❌ {name} update failed — restoring backup")
                if os.path.exists(backup_path):
                    shutil.move(backup_path, dest)

        # Update hash databases
        for name, entry in manifest.get("hashes", {}).items():
            version = entry.get("version", "")
            url = entry.get("url", "")
            expected_sha256 = entry.get("sha256", "")

            cached_version = self._version_cache.get(name, {}).get("version", "")
            if cached_version == version:
                continue

            _log(f"  Hash DB {name}: updating {cached_version or 'none'} -> {version}")
            dest = self._resolve_hash_path(name)
            if not dest:
                continue

            success = _download_with_progress(url, dest, expected_sha256)
            if success:
                _log(f"  ✅ Hash DB {name} updated to {version}")
                self._version_cache[name] = {"version": version}
                _save_version_cache(self._version_cache)
                HOT_SWAP.notify(name, dest)
                updated.append(name)

        if not updated:
            _log("All models up-to-date.")

        return updated

    def _resolve_model_path(self, name: str, model_type: str) -> Optional[str]:
        """Map model filename to its local path."""
        base = Path(".")
        if model_type == "onnx":
            return str(base / "Engine" / "Model" / "Detection_Model" / name)
        elif model_type == "pkl":
            return str(base / "models" / name)
        elif model_type == "yara":
            return str(base / "Main_Unit" / "Engine" / "Rules" / "Main_Sys_Rules" / name)
        # Try models/ as default
        return str(base / "models" / name)

    def _resolve_hash_path(self, name: str) -> Optional[str]:
        return str(Path(".") / "Main_Unit" / "Engine" / "Hashes" / name)

    def get_versions(self) -> Dict:
        return dict(self._version_cache)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_updater_instance: Optional[SentinelModelUpdater] = None


def get_updater() -> SentinelModelUpdater:
    global _updater_instance
    if _updater_instance is None:
        _updater_instance = SentinelModelUpdater()
    return _updater_instance
